#include "anchor.h"
#include "protect.h"

#include "catalog/pg_type.h"
#include "executor/spi.h"
#include "fmgr.h"
#include "funcapi.h"
#include "lib/stringinfo.h"
#include "utils/builtins.h"
#include "utils/json.h"
#include "utils/jsonb.h"
#include "utils/lsyscache.h"
#include "utils/timestamp.h"

/*
 * pgsigchain.export_block(table_name TEXT, block_number BIGINT) -> JSONB
 */
PG_FUNCTION_INFO_V1(pgsigchain_export_block);

Datum
pgsigchain_export_block(PG_FUNCTION_ARGS)
{
	text	   *table_name_text = PG_GETARG_TEXT_P(0);
	int64		block_number = PG_GETARG_INT64(1);
	char	   *table_name = text_to_cstring(table_name_text);
	Oid			relid;
	int			ret;
	int64		block_id;
	char	   *block_hash;
	char	   *prev_block_hash;
	char	   *merkle_root;
	int32		entries_count;
	char	   *created_at_str;
	char	   *schema_name;
	char	   *rel_name;
	StringInfoData buf;
	int			n_entries;
	Datum		jsonb_datum;

	relid = pgsigchain_resolve_protected_table(table_name);
	schema_name = get_namespace_name(get_rel_namespace(relid));
	rel_name = get_rel_name(relid);

	SPI_connect();

	{
		Oid		argtypes[2] = {OIDOID, INT8OID};
		Datum	values[2];
		char	nulls[2] = {' ', ' '};

		values[0] = ObjectIdGetDatum(relid);
		values[1] = Int64GetDatum(block_number);

		ret = SPI_execute_with_args(
			"SELECT id, block_hash, prev_block_hash, merkle_root, entries_count, "
			"to_char(created_at, 'YYYY-MM-DD\"T\"HH24:MI:SS.MSOF') "
			"FROM pgsigchain.blocks WHERE table_oid = $1 AND block_number = $2",
			2, argtypes, values, nulls, true, 1);
	}

	if (ret != SPI_OK_SELECT || SPI_processed == 0)
	{
		SPI_finish();
		ereport(ERROR,
				(errcode(ERRCODE_NO_DATA_FOUND),
				 errmsg("pgsigchain: block %ld not found for table \"%s\"",
						block_number, table_name)));
	}

	block_id = atol(SPI_getvalue(SPI_tuptable->vals[0], SPI_tuptable->tupdesc, 1));
	block_hash = pstrdup(SPI_getvalue(SPI_tuptable->vals[0], SPI_tuptable->tupdesc, 2));
	prev_block_hash = pstrdup(SPI_getvalue(SPI_tuptable->vals[0], SPI_tuptable->tupdesc, 3));
	merkle_root = pstrdup(SPI_getvalue(SPI_tuptable->vals[0], SPI_tuptable->tupdesc, 4));
	entries_count = atoi(SPI_getvalue(SPI_tuptable->vals[0], SPI_tuptable->tupdesc, 5));
	created_at_str = pstrdup(SPI_getvalue(SPI_tuptable->vals[0], SPI_tuptable->tupdesc, 6));

	{
		Oid		argtypes[1] = {INT8OID};
		Datum	values[1];
		char	nulls[1] = {' '};

		values[0] = Int64GetDatum(block_id);

		ret = SPI_execute_with_args(
			"SELECT id, row_hash, chain_hash FROM pgsigchain.chain_log "
			"WHERE block_id = $1 ORDER BY id",
			1, argtypes, values, nulls, true, 0);
	}

	if (ret != SPI_OK_SELECT)
	{
		SPI_finish();
		ereport(ERROR,
				(errcode(ERRCODE_INTERNAL_ERROR),
				 errmsg("pgsigchain: failed to query chain_log entries for block")));
	}

	n_entries = SPI_processed;

	/* Build JSON text via StringInfo + escape_json, then convert to JSONB. */
	initStringInfo(&buf);
	appendStringInfoChar(&buf, '{');

	appendStringInfo(&buf, "\"table_oid\":%u,", relid);

	appendStringInfoString(&buf, "\"table_name\":");
	{
		StringInfoData full;
		initStringInfo(&full);
		appendStringInfo(&full, "%s.%s", schema_name, rel_name);
		escape_json(&buf, full.data);
		pfree(full.data);
	}
	appendStringInfoChar(&buf, ',');

	appendStringInfo(&buf, "\"block_number\":%ld,", block_number);
	appendStringInfo(&buf, "\"block_id\":%ld,", block_id);

	appendStringInfoString(&buf, "\"block_hash\":");
	escape_json(&buf, block_hash);
	appendStringInfoChar(&buf, ',');

	appendStringInfoString(&buf, "\"prev_block_hash\":");
	escape_json(&buf, prev_block_hash);
	appendStringInfoChar(&buf, ',');

	appendStringInfoString(&buf, "\"merkle_root\":");
	escape_json(&buf, merkle_root);
	appendStringInfoChar(&buf, ',');

	appendStringInfo(&buf, "\"entries_count\":%d,", entries_count);

	appendStringInfoString(&buf, "\"created_at\":");
	escape_json(&buf, created_at_str);
	appendStringInfoChar(&buf, ',');

	appendStringInfoString(&buf, "\"entries\":[");
	for (int i = 0; i < n_entries; i++)
	{
		char   *eid;
		char   *erow;
		char   *echain;

		eid = SPI_getvalue(SPI_tuptable->vals[i], SPI_tuptable->tupdesc, 1);
		erow = SPI_getvalue(SPI_tuptable->vals[i], SPI_tuptable->tupdesc, 2);
		echain = SPI_getvalue(SPI_tuptable->vals[i], SPI_tuptable->tupdesc, 3);

		if (i > 0)
			appendStringInfoChar(&buf, ',');
		appendStringInfo(&buf, "{\"id\":%s,", eid);
		appendStringInfoString(&buf, "\"row_hash\":");
		escape_json(&buf, erow);
		appendStringInfoChar(&buf, ',');
		appendStringInfoString(&buf, "\"chain_hash\":");
		escape_json(&buf, echain);
		appendStringInfoChar(&buf, '}');
	}
	appendStringInfoChar(&buf, ']');
	appendStringInfoChar(&buf, '}');

	SPI_finish();

	jsonb_datum = DirectFunctionCall1(jsonb_in, CStringGetDatum(buf.data));
	pfree(buf.data);

	PG_RETURN_DATUM(jsonb_datum);
}

/*
 * pgsigchain.record_anchor(table_name, block_number, anchor_type, anchor_ref, notes) -> BIGINT
 */
PG_FUNCTION_INFO_V1(pgsigchain_record_anchor);

Datum
pgsigchain_record_anchor(PG_FUNCTION_ARGS)
{
	text	   *table_name_text;
	int64		block_number;
	text	   *anchor_type_text;
	text	   *anchor_ref_text;
	char	   *table_name;
	char	   *anchor_type;
	char	   *anchor_ref;
	char	   *notes = NULL;
	Oid			relid;
	int			ret;
	int64		block_id;
	char	   *block_hash;
	int64		anchor_id;

	if (PG_ARGISNULL(0) || PG_ARGISNULL(1) || PG_ARGISNULL(2) || PG_ARGISNULL(3))
		ereport(ERROR,
				(errcode(ERRCODE_NULL_VALUE_NOT_ALLOWED),
				 errmsg("pgsigchain: table_name, block_number, anchor_type, and anchor_ref must not be NULL")));

	table_name_text = PG_GETARG_TEXT_P(0);
	block_number = PG_GETARG_INT64(1);
	anchor_type_text = PG_GETARG_TEXT_P(2);
	anchor_ref_text = PG_GETARG_TEXT_P(3);

	table_name = text_to_cstring(table_name_text);
	anchor_type = text_to_cstring(anchor_type_text);
	anchor_ref = text_to_cstring(anchor_ref_text);

	if (!PG_ARGISNULL(4))
		notes = text_to_cstring(PG_GETARG_TEXT_P(4));

	relid = pgsigchain_resolve_protected_table(table_name);

	SPI_connect();

	{
		Oid		argtypes[2] = {OIDOID, INT8OID};
		Datum	values[2];
		char	nulls[2] = {' ', ' '};

		values[0] = ObjectIdGetDatum(relid);
		values[1] = Int64GetDatum(block_number);

		ret = SPI_execute_with_args(
			"SELECT id, block_hash FROM pgsigchain.blocks "
			"WHERE table_oid = $1 AND block_number = $2",
			2, argtypes, values, nulls, true, 1);
	}

	if (ret != SPI_OK_SELECT || SPI_processed == 0)
	{
		SPI_finish();
		ereport(ERROR,
				(errcode(ERRCODE_NO_DATA_FOUND),
				 errmsg("pgsigchain: block %ld not found for table \"%s\"",
						block_number, table_name)));
	}

	block_id = atol(SPI_getvalue(SPI_tuptable->vals[0], SPI_tuptable->tupdesc, 1));
	block_hash = pstrdup(SPI_getvalue(SPI_tuptable->vals[0], SPI_tuptable->tupdesc, 2));

	{
		Oid		argtypes[6] = {OIDOID, INT8OID, TEXTOID, TEXTOID, TEXTOID, TEXTOID};
		Datum	values[6];
		char	nulls[6] = {' ', ' ', ' ', ' ', ' ', ' '};

		values[0] = ObjectIdGetDatum(relid);
		values[1] = Int64GetDatum(block_id);
		values[2] = CStringGetTextDatum(anchor_type);
		values[3] = CStringGetTextDatum(anchor_ref);
		values[4] = CStringGetTextDatum(block_hash);
		if (notes != NULL)
			values[5] = CStringGetTextDatum(notes);
		else
			nulls[5] = 'n';

		ret = SPI_execute_with_args(
			"INSERT INTO pgsigchain.anchors "
			"(table_oid, block_id, anchor_type, anchor_ref, block_hash_at_anchor, notes) "
			"VALUES ($1, $2, $3, $4, $5, $6) RETURNING id",
			6, argtypes, values, nulls, false, 0);

		if (ret != SPI_OK_INSERT_RETURNING || SPI_processed == 0)
		{
			SPI_finish();
			ereport(ERROR,
					(errcode(ERRCODE_INTERNAL_ERROR),
					 errmsg("pgsigchain: failed to insert anchor")));
		}

		anchor_id = atol(SPI_getvalue(SPI_tuptable->vals[0], SPI_tuptable->tupdesc, 1));
	}

	SPI_finish();

	PG_RETURN_INT64(anchor_id);
}

/*
 * pgsigchain.verify_anchor(anchor_id) -> BOOLEAN
 */
PG_FUNCTION_INFO_V1(pgsigchain_verify_anchor);

Datum
pgsigchain_verify_anchor(PG_FUNCTION_ARGS)
{
	int64		anchor_id = PG_GETARG_INT64(0);
	int			ret;
	char	   *stored_hash;
	char	   *current_hash;
	bool		valid;

	SPI_connect();

	{
		Oid		argtypes[1] = {INT8OID};
		Datum	values[1];
		char	nulls[1] = {' '};

		values[0] = Int64GetDatum(anchor_id);

		ret = SPI_execute_with_args(
			"SELECT a.block_hash_at_anchor, b.block_hash "
			"FROM pgsigchain.anchors a JOIN pgsigchain.blocks b ON b.id = a.block_id "
			"WHERE a.id = $1",
			1, argtypes, values, nulls, true, 1);
	}

	if (ret != SPI_OK_SELECT || SPI_processed == 0)
	{
		SPI_finish();
		ereport(ERROR,
				(errcode(ERRCODE_NO_DATA_FOUND),
				 errmsg("pgsigchain: anchor %ld not found", anchor_id)));
	}

	stored_hash = pstrdup(SPI_getvalue(SPI_tuptable->vals[0], SPI_tuptable->tupdesc, 1));
	current_hash = pstrdup(SPI_getvalue(SPI_tuptable->vals[0], SPI_tuptable->tupdesc, 2));

	SPI_finish();

	valid = (strcmp(stored_hash, current_hash) == 0);

	PG_RETURN_BOOL(valid);
}

/*
 * pgsigchain.anchor_status(table_name) -> SETOF RECORD
 */
PG_FUNCTION_INFO_V1(pgsigchain_anchor_status);

Datum
pgsigchain_anchor_status(PG_FUNCTION_ARGS)
{
	FuncCallContext	   *funcctx;
	TupleDesc			tupdesc;

	if (SRF_IS_FIRSTCALL())
	{
		MemoryContext	oldcontext;
		text		   *table_name_text = PG_GETARG_TEXT_P(0);
		char		   *table_name = text_to_cstring(table_name_text);
		Oid				relid;
		int				ret;

		funcctx = SRF_FIRSTCALL_INIT();
		oldcontext = MemoryContextSwitchTo(funcctx->multi_call_memory_ctx);

		relid = pgsigchain_resolve_protected_table(table_name);

		SPI_connect();

		{
			Oid		argtypes[1] = {OIDOID};
			Datum	values[1];
			char	nulls[1] = {' '};

			values[0] = ObjectIdGetDatum(relid);

			ret = SPI_execute_with_args(
				"SELECT b.block_number, b.block_hash, "
				"       COUNT(a.id) AS anchor_count, "
				"       COUNT(a.id) FILTER (WHERE a.block_hash_at_anchor != b.block_hash) = 0 AS all_valid, "
				"       MAX(a.created_at) AS last_anchored "
				"FROM pgsigchain.blocks b "
				"LEFT JOIN pgsigchain.anchors a ON a.block_id = b.id "
				"WHERE b.table_oid = $1 "
				"GROUP BY b.id, b.block_number, b.block_hash "
				"ORDER BY b.block_number",
				1, argtypes, values, nulls, true, 0);
		}

		if (ret != SPI_OK_SELECT)
			ereport(ERROR,
					(errcode(ERRCODE_INTERNAL_ERROR),
					 errmsg("pgsigchain: failed to query anchor_status")));

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
		Datum			values[5];
		bool			nulls[5] = {false, false, false, false, false};
		HeapTuple		result_tuple;
		char		   *val;

		spi_tuple = tuptable->vals[funcctx->call_cntr];

		/* block_number */
		val = SPI_getvalue(spi_tuple, tuptable->tupdesc, 1);
		values[0] = Int64GetDatum(atol(val));

		/* block_hash */
		val = SPI_getvalue(spi_tuple, tuptable->tupdesc, 2);
		values[1] = CStringGetTextDatum(val);

		/* anchor_count */
		val = SPI_getvalue(spi_tuple, tuptable->tupdesc, 3);
		values[2] = Int64GetDatum(atol(val));

		/* all_valid */
		val = SPI_getvalue(spi_tuple, tuptable->tupdesc, 4);
		values[3] = BoolGetDatum(val != NULL && (val[0] == 't' || val[0] == 'T'));

		/* last_anchored — NULL when no anchors */
		values[4] = SPI_getbinval(spi_tuple, tuptable->tupdesc, 5, &nulls[4]);

		result_tuple = heap_form_tuple(funcctx->tuple_desc, values, nulls);
		SRF_RETURN_NEXT(funcctx, HeapTupleGetDatum(result_tuple));
	}
	else
	{
		SPI_finish();
		SRF_RETURN_DONE(funcctx);
	}
}
