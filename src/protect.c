#include "protect.h"

#include "access/htup_details.h"
#include "access/table.h"
#include "catalog/indexing.h"
#include "catalog/namespace.h"
#include "catalog/pg_class.h"
#include "executor/spi.h"
#include "utils/builtins.h"
#include "utils/lsyscache.h"
#include "utils/regproc.h"
#include "utils/rel.h"
#include "utils/syscache.h"

/*
 * Resolve a table name (optionally schema-qualified) to its OID.
 * Also validates that the table has a primary key.
 */
static Oid
resolve_table(const char *table_name, char **schema_out, char **name_out)
{
	RangeVar   *rv;
	Oid			relid;
	Relation	rel;
	List	   *indexoidlist;
	ListCell   *lc;
	bool		has_pk = false;

	rv = makeRangeVarFromNameList(stringToQualifiedNameList(table_name
#if PG_VERSION_NUM >= 160000
                                                            , NULL
#endif
                                                            ));
	relid = RangeVarGetRelid(rv, AccessShareLock, false);

	rel = table_open(relid, AccessShareLock);

	*schema_out = pstrdup(get_namespace_name(RelationGetNamespace(rel)));
	*name_out = pstrdup(RelationGetRelationName(rel));

	/* Check for primary key */
	indexoidlist = RelationGetIndexList(rel);
	foreach(lc, indexoidlist)
	{
		Oid			indexoid = lfirst_oid(lc);
		HeapTuple	indexTuple;
		Form_pg_index indexForm;

		indexTuple = SearchSysCache1(INDEXRELID, ObjectIdGetDatum(indexoid));
		if (!HeapTupleIsValid(indexTuple))
			continue;

		indexForm = (Form_pg_index) GETSTRUCT(indexTuple);
		if (indexForm->indisprimary)
			has_pk = true;

		ReleaseSysCache(indexTuple);
		if (has_pk)
			break;
	}
	list_free(indexoidlist);

	table_close(rel, AccessShareLock);

	if (!has_pk)
		ereport(ERROR,
				(errcode(ERRCODE_INVALID_TABLE_DEFINITION),
				 errmsg("pgsigchain: table \"%s\" must have a primary key", table_name)));

	return relid;
}

/*
 * Shared utility: resolve table name to OID, verifying it is protected.
 * Connects/disconnects SPI internally.
 */
Oid
pgsigchain_resolve_protected_table(const char *table_name)
{
	RangeVar   *rv;
	Oid			relid;
	int			ret;
	char		query[256];

	rv = makeRangeVarFromNameList(stringToQualifiedNameList(table_name
#if PG_VERSION_NUM >= 160000
                                                            , NULL
#endif
                                                            ));
	relid = RangeVarGetRelid(rv, AccessShareLock, false);

	SPI_connect();
	snprintf(query, sizeof(query),
			 "SELECT 1 FROM pgsigchain.protected_tables WHERE table_oid = %u",
			 relid);
	ret = SPI_execute(query, true, 1);
	if (ret != SPI_OK_SELECT || SPI_processed == 0)
	{
		SPI_finish();
		ereport(ERROR,
				(errcode(ERRCODE_UNDEFINED_OBJECT),
				 errmsg("pgsigchain: table \"%s\" is not protected", table_name)));
	}
	SPI_finish();

	return relid;
}

PG_FUNCTION_INFO_V1(pgsigchain_protect);

Datum
pgsigchain_protect(PG_FUNCTION_ARGS)
{
	text   *table_name_text = PG_GETARG_TEXT_P(0);
	char   *table_name = text_to_cstring(table_name_text);
	char   *mode = "immutable";
	int		auto_finalize = 0;
	bool	has_auto_finalize = false;
	char   *schema_name;
	char   *rel_name;
	Oid		relid;
	int		ret;
	char	query[512];

	/* Optional mode parameter */
	if (PG_NARGS() >= 2 && !PG_ARGISNULL(1))
		mode = text_to_cstring(PG_GETARG_TEXT_P(1));

	/* Optional auto_finalize parameter */
	if (PG_NARGS() >= 3 && !PG_ARGISNULL(2))
	{
		auto_finalize = PG_GETARG_INT32(2);
		has_auto_finalize = true;
	}

	/* Validate mode */
	if (strcmp(mode, "immutable") != 0 && strcmp(mode, "audit") != 0)
		ereport(ERROR,
				(errcode(ERRCODE_INVALID_PARAMETER_VALUE),
				 errmsg("pgsigchain: mode must be 'immutable' or 'audit'")));

	relid = resolve_table(table_name, &schema_name, &rel_name);

	SPI_connect();

	/* Check if already protected */
	snprintf(query, sizeof(query),
			 "SELECT 1 FROM pgsigchain.protected_tables WHERE table_oid = %u",
			 relid);
	ret = SPI_execute(query, true, 1);
	if (ret == SPI_OK_SELECT && SPI_processed > 0)
	{
		SPI_finish();
		ereport(ERROR,
				(errcode(ERRCODE_DUPLICATE_OBJECT),
				 errmsg("pgsigchain: table \"%s\" is already protected", table_name)));
	}

	/* Register in protected_tables */
	{
		Oid		argtypes[5] = {OIDOID, TEXTOID, TEXTOID, TEXTOID, INT4OID};
		Datum	values[5];
		char	nulls[5] = {' ', ' ', ' ', ' ', ' '};

		values[0] = ObjectIdGetDatum(relid);
		values[1] = CStringGetTextDatum(schema_name);
		values[2] = CStringGetTextDatum(rel_name);
		values[3] = CStringGetTextDatum(mode);
		if (has_auto_finalize)
			values[4] = Int32GetDatum(auto_finalize);
		else
			nulls[4] = 'n';

		ret = SPI_execute_with_args(
			"INSERT INTO pgsigchain.protected_tables "
			"(table_oid, schema_name, table_name, mode, auto_finalize_threshold) "
			"VALUES ($1, $2, $3, $4, $5)",
			5, argtypes, values, nulls, false, 0);

		if (ret != SPI_OK_INSERT)
			ereport(ERROR,
					(errcode(ERRCODE_INTERNAL_ERROR),
					 errmsg("pgsigchain: failed to register table")));
	}

	if (strcmp(mode, "immutable") == 0)
	{
		/* AFTER INSERT so the trigger sees GENERATED ALWAYS AS columns. */
		snprintf(query, sizeof(query),
				 "CREATE TRIGGER pgsigchain_chain_trg "
				 "AFTER INSERT ON %s.%s "
				 "FOR EACH ROW EXECUTE FUNCTION pgsigchain.chain_trigger()",
				 quote_identifier(schema_name), quote_identifier(rel_name));

		ret = SPI_execute(query, false, 0);
		if (ret != SPI_OK_UTILITY)
			ereport(ERROR,
					(errcode(ERRCODE_INTERNAL_ERROR),
					 errmsg("pgsigchain: failed to create chain trigger")));

		/* Create immutable trigger (block UPDATE/DELETE) */
		snprintf(query, sizeof(query),
				 "CREATE TRIGGER pgsigchain_immutable_trg "
				 "BEFORE UPDATE OR DELETE ON %s.%s "
				 "FOR EACH ROW EXECUTE FUNCTION pgsigchain.immutable_trigger()",
				 quote_identifier(schema_name), quote_identifier(rel_name));

		ret = SPI_execute(query, false, 0);
		if (ret != SPI_OK_UTILITY)
			ereport(ERROR,
					(errcode(ERRCODE_INTERNAL_ERROR),
					 errmsg("pgsigchain: failed to create immutable trigger")));
	}
	else /* audit mode */
	{
		/* AFTER so the trigger sees GENERATED ALWAYS AS columns. */
		snprintf(query, sizeof(query),
				 "CREATE TRIGGER pgsigchain_audit_trg "
				 "AFTER INSERT OR UPDATE OR DELETE ON %s.%s "
				 "FOR EACH ROW EXECUTE FUNCTION pgsigchain.audit_trigger()",
				 quote_identifier(schema_name), quote_identifier(rel_name));

		ret = SPI_execute(query, false, 0);
		if (ret != SPI_OK_UTILITY)
			ereport(ERROR,
					(errcode(ERRCODE_INTERNAL_ERROR),
					 errmsg("pgsigchain: failed to create audit trigger")));
	}

	/* Both modes block TRUNCATE — the chain only sees per-row triggers. */
	snprintf(query, sizeof(query),
			 "CREATE TRIGGER pgsigchain_truncate_trg "
			 "BEFORE TRUNCATE ON %s.%s "
			 "FOR EACH STATEMENT EXECUTE FUNCTION pgsigchain.truncate_trigger()",
			 quote_identifier(schema_name), quote_identifier(rel_name));

	ret = SPI_execute(query, false, 0);
	if (ret != SPI_OK_UTILITY)
		ereport(ERROR,
				(errcode(ERRCODE_INTERNAL_ERROR),
				 errmsg("pgsigchain: failed to create truncate trigger")));

	SPI_finish();

	PG_RETURN_VOID();
}

PG_FUNCTION_INFO_V1(pgsigchain_unprotect);

Datum
pgsigchain_unprotect(PG_FUNCTION_ARGS)
{
	text   *table_name_text = PG_GETARG_TEXT_P(0);
	char   *table_name = text_to_cstring(table_name_text);
	bool	force = false;
	char   *schema_name;
	char   *rel_name;
	Oid		relid;
	int		ret;
	char	query[512];
	int64	chain_count = 0;
	int64	block_count = 0;

	/* Optional force parameter */
	if (PG_NARGS() >= 2 && !PG_ARGISNULL(1))
		force = PG_GETARG_BOOL(1);

	relid = resolve_table(table_name, &schema_name, &rel_name);

	SPI_connect();

	/* Check if protected */
	snprintf(query, sizeof(query),
			 "SELECT 1 FROM pgsigchain.protected_tables WHERE table_oid = %u",
			 relid);
	ret = SPI_execute(query, true, 1);
	if (ret != SPI_OK_SELECT || SPI_processed == 0)
	{
		SPI_finish();
		ereport(ERROR,
				(errcode(ERRCODE_UNDEFINED_OBJECT),
				 errmsg("pgsigchain: table \"%s\" is not protected", table_name)));
	}

	/* Count existing audit data to decide whether deletion is safe */
	{
		Oid		argtypes[1] = {OIDOID};
		Datum	values[1];
		bool	isnull;

		values[0] = ObjectIdGetDatum(relid);

		ret = SPI_execute_with_args(
			"SELECT "
			"  (SELECT COUNT(*) FROM pgsigchain.chain_log WHERE table_oid = $1), "
			"  (SELECT COUNT(*) FROM pgsigchain.blocks WHERE table_oid = $1)",
			1, argtypes, values, NULL, true, 1);

		if (ret != SPI_OK_SELECT || SPI_processed == 0)
		{
			SPI_finish();
			ereport(ERROR,
					(errcode(ERRCODE_INTERNAL_ERROR),
					 errmsg("pgsigchain: failed to inspect audit data")));
		}

		chain_count = DatumGetInt64(SPI_getbinval(SPI_tuptable->vals[0],
												  SPI_tuptable->tupdesc, 1, &isnull));
		if (isnull)
			chain_count = 0;
		block_count = DatumGetInt64(SPI_getbinval(SPI_tuptable->vals[0],
												  SPI_tuptable->tupdesc, 2, &isnull));
		if (isnull)
			block_count = 0;
	}

	/* Refuse the entire operation when audit data exists and force is not set */
	if (!force && (chain_count > 0 || block_count > 0))
	{
		SPI_finish();
		ereport(ERROR,
				(errcode(ERRCODE_OBJECT_NOT_IN_PREREQUISITE_STATE),
				 errmsg("pgsigchain: refusing to unprotect \"%s\" — chain has " INT64_FORMAT
						" entries and " INT64_FORMAT " blocks; pass force => true "
						"to delete all audit data",
						table_name, chain_count, block_count)));
	}

	/* Drop all possible triggers */
	snprintf(query, sizeof(query),
			 "DROP TRIGGER IF EXISTS pgsigchain_chain_trg ON %s.%s",
			 quote_identifier(schema_name), quote_identifier(rel_name));
	SPI_execute(query, false, 0);

	snprintf(query, sizeof(query),
			 "DROP TRIGGER IF EXISTS pgsigchain_immutable_trg ON %s.%s",
			 quote_identifier(schema_name), quote_identifier(rel_name));
	SPI_execute(query, false, 0);

	snprintf(query, sizeof(query),
			 "DROP TRIGGER IF EXISTS pgsigchain_audit_trg ON %s.%s",
			 quote_identifier(schema_name), quote_identifier(rel_name));
	SPI_execute(query, false, 0);

	snprintf(query, sizeof(query),
			 "DROP TRIGGER IF EXISTS pgsigchain_truncate_trg ON %s.%s",
			 quote_identifier(schema_name), quote_identifier(rel_name));
	SPI_execute(query, false, 0);

	/* Remove from protected_tables */
	snprintf(query, sizeof(query),
			 "DELETE FROM pgsigchain.protected_tables WHERE table_oid = %u",
			 relid);
	SPI_execute(query, false, 0);

	/* Clean up chain_log, merkle_nodes, blocks, signing_keys */
	snprintf(query, sizeof(query),
			 "DELETE FROM pgsigchain.chain_log WHERE table_oid = %u", relid);
	SPI_execute(query, false, 0);

	snprintf(query, sizeof(query),
			 "DELETE FROM pgsigchain.merkle_nodes WHERE table_oid = %u", relid);
	SPI_execute(query, false, 0);

	snprintf(query, sizeof(query),
			 "DELETE FROM pgsigchain.blocks WHERE table_oid = %u", relid);
	SPI_execute(query, false, 0);

	snprintf(query, sizeof(query),
			 "DELETE FROM pgsigchain.signing_keys WHERE table_oid = %u", relid);
	SPI_execute(query, false, 0);

	SPI_finish();

	PG_RETURN_VOID();
}
