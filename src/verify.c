#include "pgsigchain.h"
#include "hash.h"
#include "protect.h"
#include "chain.h"

#include "access/heapam.h"
#include "access/relscan.h"
#include "access/table.h"
#include "catalog/namespace.h"
#include "executor/executor.h"
#include "executor/spi.h"
#include "executor/tuptable.h"
#include "funcapi.h"
#include "utils/builtins.h"
#include "utils/lsyscache.h"
#include "utils/regproc.h"
#include "utils/snapmgr.h"
#include "utils/tuplestore.h"
#include "miscadmin.h"

/* Fallback prototype: chain.h may not yet expose this; symbol resolves at link time. */
extern char *pgsigchain_get_row_pk_text(Relation rel, HeapTuple tuple);

/*
 * pgsigchain.verify_chain(table_name) -> boolean
 */
PG_FUNCTION_INFO_V1(pgsigchain_verify_chain);

Datum
pgsigchain_verify_chain(PG_FUNCTION_ARGS)
{
	text   *table_name_text = PG_GETARG_TEXT_P(0);
	char   *table_name = text_to_cstring(table_name_text);
	Oid		relid;
	int		ret;
	int		n_rows;

	relid = pgsigchain_resolve_protected_table(table_name);

	SPI_connect();

	{
		Oid		argtypes[1] = {OIDOID};
		Datum	values[1];
		char	nulls[1] = {' '};

		values[0] = ObjectIdGetDatum(relid);

		ret = SPI_execute_with_args(
			"SELECT row_hash, prev_hash, chain_hash "
			"FROM pgsigchain.chain_log WHERE table_oid = $1 ORDER BY id",
			1, argtypes, values, nulls, true, 0);
	}

	if (ret != SPI_OK_SELECT)
	{
		SPI_finish();
		ereport(ERROR,
				(errcode(ERRCODE_INTERNAL_ERROR),
				 errmsg("pgsigchain: failed to query chain_log")));
	}

	n_rows = SPI_processed;

	for (int i = 0; i < n_rows; i++)
	{
		char   *row_hash;
		char   *prev_hash;
		char   *stored_chain_hash;
		char   *computed_chain_hash;
		char   *concat;
		size_t	plen, rlen;

		row_hash = SPI_getvalue(SPI_tuptable->vals[i],
								SPI_tuptable->tupdesc, 1);
		prev_hash = SPI_getvalue(SPI_tuptable->vals[i],
								 SPI_tuptable->tupdesc, 2);
		stored_chain_hash = SPI_getvalue(SPI_tuptable->vals[i],
										  SPI_tuptable->tupdesc, 3);

		plen = strlen(prev_hash);
		rlen = strlen(row_hash);
		concat = palloc(plen + rlen + 1);
		memcpy(concat, prev_hash, plen);
		memcpy(concat + plen, row_hash, rlen);
		concat[plen + rlen] = '\0';

		computed_chain_hash = pgsigchain_compute_sha256(concat, plen + rlen);
		pfree(concat);

		if (strcmp(computed_chain_hash, stored_chain_hash) != 0)
		{
			pfree(computed_chain_hash);
			SPI_finish();
			PG_RETURN_BOOL(false);
		}

		pfree(computed_chain_hash);
	}

	SPI_finish();
	PG_RETURN_BOOL(true);
}

/*
 * pgsigchain.verify_row(table_name, row_pk) -> boolean
 */
PG_FUNCTION_INFO_V1(pgsigchain_verify_row);

Datum
pgsigchain_verify_row(PG_FUNCTION_ARGS)
{
	text   *table_name_text = PG_GETARG_TEXT_P(0);
	text   *row_pk_text = PG_GETARG_TEXT_P(1);
	char   *table_name = text_to_cstring(table_name_text);
	char   *row_pk = text_to_cstring(row_pk_text);
	Oid		relid;
	int		ret;
	char   *row_hash;
	char   *prev_hash;
	char   *stored_chain_hash;
	char   *computed_chain_hash;
	char   *concat;
	size_t	plen, rlen;
	bool	valid;

	relid = pgsigchain_resolve_protected_table(table_name);

	SPI_connect();

	{
		Oid		argtypes[2] = {OIDOID, TEXTOID};
		Datum	values[2];
		char	nulls[2] = {' ', ' '};

		values[0] = ObjectIdGetDatum(relid);
		values[1] = CStringGetTextDatum(row_pk);

		ret = SPI_execute_with_args(
			"SELECT row_hash, prev_hash, chain_hash FROM pgsigchain.chain_log "
			"WHERE table_oid = $1 AND row_pk = $2 "
			"ORDER BY id DESC LIMIT 1",
			2, argtypes, values, nulls, true, 1);

		if (ret != SPI_OK_SELECT || SPI_processed == 0)
		{
			SPI_finish();
			ereport(ERROR,
					(errcode(ERRCODE_NO_DATA_FOUND),
					 errmsg("pgsigchain: no chain_log entry for row pk \"%s\"", row_pk)));
		}

		row_hash = pstrdup(SPI_getvalue(SPI_tuptable->vals[0],
										 SPI_tuptable->tupdesc, 1));
		prev_hash = pstrdup(SPI_getvalue(SPI_tuptable->vals[0],
										  SPI_tuptable->tupdesc, 2));
		stored_chain_hash = pstrdup(SPI_getvalue(SPI_tuptable->vals[0],
												  SPI_tuptable->tupdesc, 3));
	}

	SPI_finish();

	plen = strlen(prev_hash);
	rlen = strlen(row_hash);
	concat = palloc(plen + rlen + 1);
	memcpy(concat, prev_hash, plen);
	memcpy(concat + plen, row_hash, rlen);
	concat[plen + rlen] = '\0';

	computed_chain_hash = pgsigchain_compute_sha256(concat, plen + rlen);
	pfree(concat);

	valid = (strcmp(computed_chain_hash, stored_chain_hash) == 0);
	pfree(computed_chain_hash);

	PG_RETURN_BOOL(valid);
}

/*
 * pgsigchain.verify_data(table_name) -> boolean
 *
 * Recompute each live row's hash and compare to the latest chain_log entry.
 * Detects tampering that bypasses triggers.
 */
PG_FUNCTION_INFO_V1(pgsigchain_verify_data);

Datum
pgsigchain_verify_data(PG_FUNCTION_ARGS)
{
	text		   *table_name_text = PG_GETARG_TEXT_P(0);
	char		   *table_name = text_to_cstring(table_name_text);
	Oid				relid;
	Relation		rel;
	TableScanDesc	scan;
	TupleTableSlot *slot;
	bool			ok = true;

	relid = pgsigchain_resolve_protected_table(table_name);

	rel = table_open(relid, AccessShareLock);
	slot = table_slot_create(rel, NULL);
	scan = table_beginscan(rel, GetActiveSnapshot(), 0, NULL);

	SPI_connect();

	while (table_scan_getnextslot(scan, ForwardScanDirection, slot))
	{
		HeapTuple	tuple;
		char	   *row_pk_hex;
		char	   *stored_row_hash;
		char	   *computed_row_hash;
		PgsigchainActor	actor;
		bool		isnull;
		Datum		val;
		int			ret;
		Oid			argtypes[2] = {OIDOID, TEXTOID};
		Datum		values[2];
		char		nulls[2] = {' ', ' '};

		tuple = ExecCopySlotHeapTuple(slot);
		row_pk_hex = pgsigchain_get_row_pk_text(rel, tuple);

		values[0] = ObjectIdGetDatum(relid);
		values[1] = CStringGetTextDatum(row_pk_hex);

		ret = SPI_execute_with_args(
			"SELECT row_hash, actor_user, actor_app, actor_addr, actor_pid "
			"FROM pgsigchain.chain_log "
			"WHERE table_oid = $1 AND row_pk = $2 "
			"ORDER BY id DESC LIMIT 1",
			2, argtypes, values, nulls, true, 1);

		if (ret != SPI_OK_SELECT || SPI_processed == 0)
		{
			heap_freetuple(tuple);
			ok = false;
			break;
		}

		stored_row_hash = SPI_getvalue(SPI_tuptable->vals[0],
									   SPI_tuptable->tupdesc, 1);

		actor.user = SPI_getvalue(SPI_tuptable->vals[0], SPI_tuptable->tupdesc, 2);
		actor.app_name = SPI_getvalue(SPI_tuptable->vals[0], SPI_tuptable->tupdesc, 3);
		actor.addr = SPI_getvalue(SPI_tuptable->vals[0], SPI_tuptable->tupdesc, 4);
		val = SPI_getbinval(SPI_tuptable->vals[0], SPI_tuptable->tupdesc, 5, &isnull);
		actor.pid = isnull ? 0 : DatumGetInt32(val);

		computed_row_hash = pgsigchain_compute_row_hash(rel, tuple, &actor);

		if (stored_row_hash == NULL ||
			strcmp(computed_row_hash, stored_row_hash) != 0)
		{
			heap_freetuple(tuple);
			ok = false;
			break;
		}

		heap_freetuple(tuple);
	}

	SPI_finish();

	table_endscan(scan);
	ExecDropSingleTupleTableSlot(slot);
	table_close(rel, AccessShareLock);

	PG_RETURN_BOOL(ok);
}

/*
 * pgsigchain.find_tampered_rows(table_name) ->
 *   SETOF (row_pk, chain_log_id, expected_hash, actual_hash, recorded_actor, recorded_at)
 *
 * Forensic helper: scan the live table and return every row whose recomputed
 * hash does not match the latest chain_log entry, OR which has no chain_log
 * entry at all (orphan: insert that bypassed the trigger).
 */
PG_FUNCTION_INFO_V1(pgsigchain_find_tampered_rows);

Datum
pgsigchain_find_tampered_rows(PG_FUNCTION_ARGS)
{
	text		   *table_name_text = PG_GETARG_TEXT_P(0);
	char		   *table_name = text_to_cstring(table_name_text);
	ReturnSetInfo  *rsinfo = (ReturnSetInfo *) fcinfo->resultinfo;
	TupleDesc		tupdesc;
	Tuplestorestate *tupstore;
	MemoryContext	per_query_ctx;
	MemoryContext	oldcontext;
	Oid				relid;
	Relation		rel;
	TableScanDesc	scan;
	TupleTableSlot *slot;

	if (rsinfo == NULL || !IsA(rsinfo, ReturnSetInfo) ||
		!(rsinfo->allowedModes & SFRM_Materialize))
		ereport(ERROR,
				(errcode(ERRCODE_FEATURE_NOT_SUPPORTED),
				 errmsg("pgsigchain: set-returning function called in a context "
						"that does not accept a set")));

	if (get_call_result_type(fcinfo, NULL, &tupdesc) != TYPEFUNC_COMPOSITE)
		ereport(ERROR,
				(errcode(ERRCODE_FEATURE_NOT_SUPPORTED),
				 errmsg("pgsigchain: function returning record called in context "
						"that cannot accept type record")));

	per_query_ctx = rsinfo->econtext->ecxt_per_query_memory;
	oldcontext = MemoryContextSwitchTo(per_query_ctx);

	tupstore = tuplestore_begin_heap(true, false, work_mem);
	rsinfo->returnMode = SFRM_Materialize;
	rsinfo->setResult = tupstore;
	rsinfo->setDesc = tupdesc;
	tupdesc = CreateTupleDescCopy(tupdesc);

	MemoryContextSwitchTo(oldcontext);

	relid = pgsigchain_resolve_protected_table(table_name);

	rel = table_open(relid, AccessShareLock);
	slot = table_slot_create(rel, NULL);
	scan = table_beginscan(rel, GetActiveSnapshot(), 0, NULL);

	SPI_connect();

	while (table_scan_getnextslot(scan, ForwardScanDirection, slot))
	{
		HeapTuple	tuple;
		char	   *row_pk_hex;
		char	   *stored_row_hash;
		char	   *computed_row_hash;
		PgsigchainActor	actor;
		bool		isnull;
		Datum		val;
		Datum		stored_op_at = (Datum) 0;
		bool		stored_op_at_isnull = true;
		int64		chain_log_id = 0;
		int			ret;
		Oid			argtypes[2] = {OIDOID, TEXTOID};
		Datum		params[2];
		char		nullsp[2] = {' ', ' '};
		Datum		out[6];
		bool		out_nulls[6] = {false, false, false, false, false, false};

		tuple = ExecCopySlotHeapTuple(slot);
		row_pk_hex = pgsigchain_get_row_pk_text(rel, tuple);

		params[0] = ObjectIdGetDatum(relid);
		params[1] = CStringGetTextDatum(row_pk_hex);

		ret = SPI_execute_with_args(
			"SELECT id, row_hash, actor_user, actor_app, actor_addr, actor_pid, created_at "
			"FROM pgsigchain.chain_log "
			"WHERE table_oid = $1 AND row_pk = $2 "
			"ORDER BY id DESC LIMIT 1",
			2, argtypes, params, nullsp, true, 1);

		if (ret != SPI_OK_SELECT || SPI_processed == 0)
		{
			/* Row exists in the table but no chain_log entry — orphan insert. */
			out[0] = CStringGetTextDatum(row_pk_hex);
			out_nulls[1] = true;
			out_nulls[2] = true;
			out[3] = CStringGetTextDatum("(no chain_log entry — orphan row)");
			out_nulls[4] = true;
			out_nulls[5] = true;
			tuplestore_putvalues(tupstore, tupdesc, out, out_nulls);
			heap_freetuple(tuple);
			continue;
		}

		val = SPI_getbinval(SPI_tuptable->vals[0], SPI_tuptable->tupdesc, 1, &isnull);
		chain_log_id = isnull ? 0 : DatumGetInt64(val);
		stored_row_hash = SPI_getvalue(SPI_tuptable->vals[0], SPI_tuptable->tupdesc, 2);
		actor.user = SPI_getvalue(SPI_tuptable->vals[0], SPI_tuptable->tupdesc, 3);
		actor.app_name = SPI_getvalue(SPI_tuptable->vals[0], SPI_tuptable->tupdesc, 4);
		actor.addr = SPI_getvalue(SPI_tuptable->vals[0], SPI_tuptable->tupdesc, 5);
		val = SPI_getbinval(SPI_tuptable->vals[0], SPI_tuptable->tupdesc, 6, &isnull);
		actor.pid = isnull ? 0 : DatumGetInt32(val);
		stored_op_at = SPI_getbinval(SPI_tuptable->vals[0], SPI_tuptable->tupdesc, 7,
									 &stored_op_at_isnull);

		computed_row_hash = pgsigchain_compute_row_hash(rel, tuple, &actor);

		if (stored_row_hash &&
			strcmp(computed_row_hash, stored_row_hash) == 0)
		{
			heap_freetuple(tuple);
			continue;	/* clean row */
		}

		out[0] = CStringGetTextDatum(row_pk_hex);
		out[1] = Int64GetDatum(chain_log_id);
		out[2] = CStringGetTextDatum(stored_row_hash ? stored_row_hash : "");
		out[3] = CStringGetTextDatum(computed_row_hash);
		if (actor.user) out[4] = CStringGetTextDatum(actor.user);
		else            out_nulls[4] = true;
		if (stored_op_at_isnull) out_nulls[5] = true;
		else					 out[5] = stored_op_at;

		tuplestore_putvalues(tupstore, tupdesc, out, out_nulls);
		heap_freetuple(tuple);
	}

	SPI_finish();

	table_endscan(scan);
	ExecDropSingleTupleTableSlot(slot);
	table_close(rel, AccessShareLock);

	return (Datum) 0;
}

/*
 * pgsigchain.status() -> SETOF (schema_name, table_name, mode, protected_at, chain_length, block_count)
 */
PG_FUNCTION_INFO_V1(pgsigchain_status);

Datum
pgsigchain_status(PG_FUNCTION_ARGS)
{
	FuncCallContext    *funcctx;
	TupleDesc			tupdesc;

	if (SRF_IS_FIRSTCALL())
	{
		MemoryContext	oldcontext;
		int				ret;

		funcctx = SRF_FIRSTCALL_INIT();
		oldcontext = MemoryContextSwitchTo(funcctx->multi_call_memory_ctx);

		SPI_connect();

		ret = SPI_execute(
			"SELECT pt.schema_name, pt.table_name, pt.mode, pt.protected_at, "
			"       COALESCE(cl.cnt, 0) AS chain_length, "
			"       COALESCE(bl.cnt, 0) AS block_count "
			"FROM pgsigchain.protected_tables pt "
			"LEFT JOIN ("
			"  SELECT table_oid, COUNT(*) AS cnt FROM pgsigchain.chain_log GROUP BY table_oid"
			") cl ON cl.table_oid = pt.table_oid "
			"LEFT JOIN ("
			"  SELECT table_oid, COUNT(*) AS cnt FROM pgsigchain.blocks GROUP BY table_oid"
			") bl ON bl.table_oid = pt.table_oid "
			"ORDER BY pt.protected_at",
			true, 0);

		if (ret != SPI_OK_SELECT)
			ereport(ERROR,
					(errcode(ERRCODE_INTERNAL_ERROR),
					 errmsg("pgsigchain: failed to query status")));

		funcctx->max_calls = SPI_processed;

		if (get_call_result_type(fcinfo, NULL, &tupdesc) != TYPEFUNC_COMPOSITE)
			ereport(ERROR,
					(errcode(ERRCODE_FEATURE_NOT_SUPPORTED),
					 errmsg("function returning record called in context "
							"that cannot accept type record")));

		funcctx->tuple_desc = BlessTupleDesc(tupdesc);

		if (SPI_processed > 0)
			funcctx->user_fctx = SPI_tuptable;

		MemoryContextSwitchTo(oldcontext);
	}

	funcctx = SRF_PERCALL_SETUP();

	if (funcctx->call_cntr < funcctx->max_calls)
	{
		SPITupleTable  *tuptable = (SPITupleTable *) funcctx->user_fctx;
		HeapTuple		spi_tuple;
		Datum			values[6];
		bool			nulls[6] = {false, false, false, false, false, false};
		HeapTuple		result_tuple;
		Datum			result;
		char		   *val;

		spi_tuple = tuptable->vals[funcctx->call_cntr];

		/* schema_name */
		val = SPI_getvalue(spi_tuple, tuptable->tupdesc, 1);
		values[0] = CStringGetTextDatum(val);

		/* table_name */
		val = SPI_getvalue(spi_tuple, tuptable->tupdesc, 2);
		values[1] = CStringGetTextDatum(val);

		/* mode */
		val = SPI_getvalue(spi_tuple, tuptable->tupdesc, 3);
		values[2] = CStringGetTextDatum(val);

		/* protected_at */
		values[3] = SPI_getbinval(spi_tuple, tuptable->tupdesc, 4, &nulls[3]);

		/* chain_length */
		val = SPI_getvalue(spi_tuple, tuptable->tupdesc, 5);
		values[4] = Int64GetDatum(atol(val));

		/* block_count */
		val = SPI_getvalue(spi_tuple, tuptable->tupdesc, 6);
		values[5] = Int64GetDatum(atol(val));

		result_tuple = heap_form_tuple(funcctx->tuple_desc, values, nulls);
		result = HeapTupleGetDatum(result_tuple);

		SRF_RETURN_NEXT(funcctx, result);
	}
	else
	{
		SPI_finish();
		SRF_RETURN_DONE(funcctx);
	}
}
