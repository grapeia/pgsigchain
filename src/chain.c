#include "chain.h"
#include "hash.h"
#include "blocks.h"

#include "access/htup_details.h"
#include "catalog/indexing.h"
#include "catalog/namespace.h"
#include "catalog/pg_type.h"
#include "commands/trigger.h"
#include "executor/spi.h"
#include "utils/builtins.h"
#include "utils/lsyscache.h"
#include "utils/rel.h"
#include "utils/syscache.h"

/*
 * Extract primary key value(s) as a text representation.
 */
char *
pgsigchain_get_row_pk_text(Relation rel, HeapTuple tuple)
{
	TupleDesc		tupdesc = RelationGetDescr(rel);
	StringInfoData	buf;
	List		   *indexoidlist;
	ListCell	   *lc;
	Oid				pkindexoid = InvalidOid;

	indexoidlist = RelationGetIndexList(rel);
	foreach(lc, indexoidlist)
	{
		Oid		indexoid = lfirst_oid(lc);
		HeapTuple	indexTuple;
		Form_pg_index indexForm;

		indexTuple = SearchSysCache1(INDEXRELID, ObjectIdGetDatum(indexoid));
		if (!HeapTupleIsValid(indexTuple))
			continue;

		indexForm = (Form_pg_index) GETSTRUCT(indexTuple);
		if (indexForm->indisprimary)
		{
			pkindexoid = indexoid;
			ReleaseSysCache(indexTuple);
			break;
		}
		ReleaseSysCache(indexTuple);
	}
	list_free(indexoidlist);

	if (!OidIsValid(pkindexoid))
		ereport(ERROR,
				(errcode(ERRCODE_UNDEFINED_OBJECT),
				 errmsg("pgsigchain: table \"%s\" has no primary key",
						RelationGetRelationName(rel))));

	{
		HeapTuple		indexTuple;
		Form_pg_index	indexForm;

		indexTuple = SearchSysCache1(INDEXRELID, ObjectIdGetDatum(pkindexoid));
		indexForm = (Form_pg_index) GETSTRUCT(indexTuple);

		initStringInfo(&buf);
		for (int i = 0; i < indexForm->indnatts; i++)
		{
			int		attnum = indexForm->indkey.values[i];
			Datum	val;
			bool	isnull;
			Oid		typoutput;
			bool	typIsVarlena;
			char   *str;
			Form_pg_attribute att = TupleDescAttr(tupdesc, attnum - 1);

			val = heap_getattr(tuple, attnum, tupdesc, &isnull);

			if (isnull)
				pgsigchain_canonical_append_field(&buf, NULL, 0, true);
			else
			{
				getTypeOutputInfo(att->atttypid, &typoutput, &typIsVarlena);
				str = OidOutputFunctionCall(typoutput, val);
				pgsigchain_canonical_append_field(&buf, str, strlen(str), false);
				pfree(str);
			}
		}

		ReleaseSysCache(indexTuple);
	}

	{
		char	*hex = pgsigchain_bytes_to_hex((const unsigned char *) buf.data, buf.len);
		pfree(buf.data);
		return hex;
	}
}

/*
 * Get the previous chain_hash for a table. Returns pstrdup'd value.
 * Caller must have SPI connected.
 */
static char *
get_prev_hash(Oid table_oid)
{
	char	query[256];
	int		ret;

	snprintf(query, sizeof(query),
			 "SELECT chain_hash FROM pgsigchain.chain_log "
			 "WHERE table_oid = %u ORDER BY id DESC LIMIT 1",
			 table_oid);

	ret = SPI_execute(query, true, 1);
	if (ret != SPI_OK_SELECT)
		ereport(ERROR,
				(errcode(ERRCODE_INTERNAL_ERROR),
				 errmsg("pgsigchain: failed to query chain_log")));

	if (SPI_processed > 0)
		return pstrdup(SPI_getvalue(SPI_tuptable->vals[0],
									SPI_tuptable->tupdesc, 1));
	else
		return pstrdup("0");
}

/*
 * Compute chain_hash = SHA256(prev_hash || row_hash).
 */
static char *
compute_chain_hash(const char *prev_hash, const char *row_hash)
{
	size_t	plen = strlen(prev_hash);
	size_t	rlen = strlen(row_hash);
	char   *concat = palloc(plen + rlen + 1);
	char   *result;

	memcpy(concat, prev_hash, plen);
	memcpy(concat + plen, row_hash, rlen);
	concat[plen + rlen] = '\0';
	result = pgsigchain_compute_sha256(concat, plen + rlen);
	pfree(concat);
	return result;
}

/*
 * Capture actor identity (current_user, app_name, client addr, pid) from the
 * session via SPI. Caller must have SPI connected. All strings are pstrdup'd
 * into the caller's memory context.
 */
static void
capture_actor(PgsigchainActor *actor)
{
	int		ret;
	bool	isnull;
	Datum	val;

	actor->user = NULL;
	actor->app_name = NULL;
	actor->addr = NULL;
	actor->pid = 0;

	ret = SPI_execute(
		"SELECT current_user::text, "
		"       current_setting('application_name', true), "
		"       inet_client_addr()::text, "
		"       pg_backend_pid()",
		true, 1);
	if (ret != SPI_OK_SELECT || SPI_processed == 0)
		return;

	{
		char *s;

		s = SPI_getvalue(SPI_tuptable->vals[0], SPI_tuptable->tupdesc, 1);
		if (s) actor->user = pstrdup(s);

		s = SPI_getvalue(SPI_tuptable->vals[0], SPI_tuptable->tupdesc, 2);
		if (s && s[0] != '\0') actor->app_name = pstrdup(s);

		s = SPI_getvalue(SPI_tuptable->vals[0], SPI_tuptable->tupdesc, 3);
		if (s) actor->addr = pstrdup(s);

		val = SPI_getbinval(SPI_tuptable->vals[0], SPI_tuptable->tupdesc, 4, &isnull);
		actor->pid = isnull ? 0 : DatumGetInt32(val);
	}
}

/*
 * Insert a chain_log entry. Caller must have SPI connected.
 * Returns nothing; raises ERROR on failure.
 */
static void
insert_chain_log(Oid table_oid, const char *row_pk, const char *row_hash,
				 const char *prev_hash, const char *chain_hash,
				 const char *operation, const char *new_row_hash,
				 const char *signature, const PgsigchainActor *actor)
{
	Oid		argtypes[12] = {OIDOID, TEXTOID, TEXTOID, TEXTOID, TEXTOID,
							TEXTOID, TEXTOID, TEXTOID,
							TEXTOID, TEXTOID, TEXTOID, INT4OID};
	Datum	values[12];
	char	nulls[12] = {' ', ' ', ' ', ' ', ' ', ' ', ' ', ' ',
						 ' ', ' ', ' ', ' '};
	int		ret;

	values[0] = ObjectIdGetDatum(table_oid);
	values[1] = CStringGetTextDatum(row_pk);
	values[2] = CStringGetTextDatum(row_hash);
	values[3] = CStringGetTextDatum(prev_hash);
	values[4] = CStringGetTextDatum(chain_hash);
	values[5] = CStringGetTextDatum(operation);

	if (new_row_hash) values[6] = CStringGetTextDatum(new_row_hash);
	else              nulls[6] = 'n';

	if (signature)    values[7] = CStringGetTextDatum(signature);
	else              nulls[7] = 'n';

	if (actor && actor->user)     values[8] = CStringGetTextDatum(actor->user);
	else                          nulls[8] = 'n';

	if (actor && actor->app_name) values[9] = CStringGetTextDatum(actor->app_name);
	else                          nulls[9] = 'n';

	if (actor && actor->addr)     values[10] = CStringGetTextDatum(actor->addr);
	else                          nulls[10] = 'n';

	if (actor)                    values[11] = Int32GetDatum(actor->pid);
	else                          nulls[11] = 'n';

	ret = SPI_execute_with_args(
		"INSERT INTO pgsigchain.chain_log "
		"(table_oid, row_pk, row_hash, prev_hash, chain_hash, "
		" operation, new_row_hash, signature, "
		" actor_user, actor_app, actor_addr, actor_pid) "
		"VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12)",
		12, argtypes, values, nulls, false, 0);

	if (ret != SPI_OK_INSERT)
		ereport(ERROR,
				(errcode(ERRCODE_INTERNAL_ERROR),
				 errmsg("pgsigchain: failed to insert into chain_log")));
}

/*
 * Check auto-finalize threshold and finalize if needed.
 * Caller must have SPI connected.
 */
static void
check_auto_finalize(Oid table_oid)
{
	char	query[256];
	int		ret;
	int		threshold;
	int		unfinalized;

	snprintf(query, sizeof(query),
			 "SELECT auto_finalize_threshold FROM pgsigchain.protected_tables "
			 "WHERE table_oid = %u", table_oid);
	ret = SPI_execute(query, true, 1);
	if (ret != SPI_OK_SELECT || SPI_processed == 0)
		return;

	if (SPI_getvalue(SPI_tuptable->vals[0], SPI_tuptable->tupdesc, 1) == NULL)
		return;

	threshold = atoi(SPI_getvalue(SPI_tuptable->vals[0],
								  SPI_tuptable->tupdesc, 1));
	if (threshold <= 0)
		return;

	snprintf(query, sizeof(query),
			 "SELECT COUNT(*) FROM pgsigchain.chain_log "
			 "WHERE table_oid = %u AND block_id IS NULL", table_oid);
	ret = SPI_execute(query, true, 1);
	if (ret != SPI_OK_SELECT)
		return;

	unfinalized = atoi(SPI_getvalue(SPI_tuptable->vals[0],
									 SPI_tuptable->tupdesc, 1));

	if (unfinalized >= threshold)
		pgsigchain_do_finalize_block(table_oid);
}

/*
 * pgsigchain_chain_trigger — BEFORE INSERT trigger for immutable mode.
 */
PG_FUNCTION_INFO_V1(pgsigchain_chain_trigger);

Datum
pgsigchain_chain_trigger(PG_FUNCTION_ARGS)
{
	TriggerData *trigdata = (TriggerData *) fcinfo->context;
	Relation	 rel;
	HeapTuple	 newtuple;
	Oid			 table_oid;
	char		*row_pk;
	char		*row_hash;
	char		*prev_hash;
	char		*chain_hash;
	PgsigchainActor	 actor;

	if (!CALLED_AS_TRIGGER(fcinfo))
		ereport(ERROR,
				(errcode(ERRCODE_E_R_I_E_TRIGGER_PROTOCOL_VIOLATED),
				 errmsg("pgsigchain_chain_trigger: not called as trigger")));

	if (!TRIGGER_FIRED_BY_INSERT(trigdata->tg_event))
		PG_RETURN_POINTER(trigdata->tg_trigtuple);

	rel = trigdata->tg_relation;
	newtuple = trigdata->tg_trigtuple;
	table_oid = RelationGetRelid(rel);

	SPI_connect();

	/* Serialize chain extension per table so concurrent txns can't read the
	 * same prev_hash and bifurcate the chain. Released at xact end. */
	{
		Oid		argtypes[1] = {INT8OID};
		Datum	values[1] = {Int64GetDatum((int64) table_oid)};

		if (SPI_execute_with_args("SELECT pg_advisory_xact_lock($1)",
								  1, argtypes, values, NULL, false, 0) != SPI_OK_SELECT)
			ereport(ERROR,
					(errcode(ERRCODE_INTERNAL_ERROR),
					 errmsg("pgsigchain: failed to acquire advisory lock")));
	}

	capture_actor(&actor);
	row_hash = pgsigchain_compute_row_hash(rel, newtuple, &actor);
	row_pk = pgsigchain_get_row_pk_text(rel, newtuple);

	prev_hash = get_prev_hash(table_oid);
	chain_hash = compute_chain_hash(prev_hash, row_hash);

	insert_chain_log(table_oid, row_pk, row_hash, prev_hash, chain_hash,
					 "INSERT", NULL, NULL, &actor);

	check_auto_finalize(table_oid);

	SPI_finish();

	PG_RETURN_POINTER(newtuple);
}

/*
 * pgsigchain_audit_trigger — BEFORE INSERT/UPDATE/DELETE trigger for audit mode.
 * Allows all operations but logs them in chain_log.
 */
PG_FUNCTION_INFO_V1(pgsigchain_audit_trigger);

Datum
pgsigchain_audit_trigger(PG_FUNCTION_ARGS)
{
	TriggerData *trigdata = (TriggerData *) fcinfo->context;
	Relation	 rel;
	Oid			 table_oid;
	char		*row_pk;
	char		*row_hash;
	char		*new_row_hash = NULL;
	char		*prev_hash;
	char		*chain_hash;
	const char	*operation;
	HeapTuple	 return_tuple;
	PgsigchainActor	 actor;

	if (!CALLED_AS_TRIGGER(fcinfo))
		ereport(ERROR,
				(errcode(ERRCODE_E_R_I_E_TRIGGER_PROTOCOL_VIOLATED),
				 errmsg("pgsigchain_audit_trigger: not called as trigger")));

	rel = trigdata->tg_relation;
	table_oid = RelationGetRelid(rel);

	SPI_connect();

	/* Serialize chain extension per table so concurrent txns can't read the
	 * same prev_hash and bifurcate the chain. Released at xact end. */
	{
		Oid		argtypes[1] = {INT8OID};
		Datum	values[1] = {Int64GetDatum((int64) table_oid)};

		if (SPI_execute_with_args("SELECT pg_advisory_xact_lock($1)",
								  1, argtypes, values, NULL, false, 0) != SPI_OK_SELECT)
			ereport(ERROR,
					(errcode(ERRCODE_INTERNAL_ERROR),
					 errmsg("pgsigchain: failed to acquire advisory lock")));
	}

	capture_actor(&actor);

	if (TRIGGER_FIRED_BY_INSERT(trigdata->tg_event))
	{
		HeapTuple newtuple = trigdata->tg_trigtuple;

		operation = "INSERT";
		row_hash = pgsigchain_compute_row_hash(rel, newtuple, &actor);
		row_pk = pgsigchain_get_row_pk_text(rel, newtuple);
		return_tuple = newtuple;
	}
	else if (TRIGGER_FIRED_BY_UPDATE(trigdata->tg_event))
	{
		HeapTuple oldtuple = trigdata->tg_trigtuple;
		HeapTuple newtuple = trigdata->tg_newtuple;

		operation = "UPDATE";
		row_hash = pgsigchain_compute_row_hash(rel, oldtuple, &actor);
		new_row_hash = pgsigchain_compute_row_hash(rel, newtuple, &actor);
		row_pk = pgsigchain_get_row_pk_text(rel, oldtuple);
		return_tuple = newtuple;
	}
	else if (TRIGGER_FIRED_BY_DELETE(trigdata->tg_event))
	{
		HeapTuple oldtuple = trigdata->tg_trigtuple;

		operation = "DELETE";
		row_hash = pgsigchain_compute_row_hash(rel, oldtuple, &actor);
		row_pk = pgsigchain_get_row_pk_text(rel, oldtuple);
		return_tuple = oldtuple;
	}
	else
	{
		SPI_finish();
		PG_RETURN_POINTER(trigdata->tg_trigtuple);
	}

	prev_hash = get_prev_hash(table_oid);
	chain_hash = compute_chain_hash(prev_hash, row_hash);

	insert_chain_log(table_oid, row_pk, row_hash, prev_hash, chain_hash,
					 operation, new_row_hash, NULL, &actor);

	check_auto_finalize(table_oid);

	SPI_finish();

	PG_RETURN_POINTER(return_tuple);
}
