#include "blocks.h"
#include "hash.h"
#include "protect.h"

#include "catalog/namespace.h"
#include "executor/spi.h"
#include "funcapi.h"
#include "utils/builtins.h"
#include "utils/lsyscache.h"
#include "utils/regproc.h"

/*
 * Build a merkle root in-memory from an array of hashes.
 * Returns palloc'd hex string.
 */
static char *
compute_merkle_root(char **hashes, int count)
{
	char  **current = hashes;
	int		n = count;

	if (n == 0)
		return pstrdup("0");

	while (n > 1)
	{
		int		new_count = (n + 1) / 2;
		char  **next = palloc(sizeof(char *) * new_count);

		for (int i = 0; i < new_count; i++)
		{
			char   *left = current[i * 2];
			char   *right = (i * 2 + 1 < n) ? current[i * 2 + 1] : left;
			size_t	llen = strlen(left);
			size_t	rlen = strlen(right);
			char   *concat = palloc(llen + rlen + 1);

			memcpy(concat, left, llen);
			memcpy(concat + llen, right, rlen);
			concat[llen + rlen] = '\0';

			next[i] = pgsigchain_compute_sha256(concat, llen + rlen);
			pfree(concat);
		}

		if (current != hashes)
			pfree(current);
		current = next;
		n = new_count;
	}

	return current[0];
}

/*
 * Core finalize logic. Assumes SPI is connected.
 */
int64
pgsigchain_do_finalize_block(Oid table_oid)
{
	char	query[512];
	int		ret;
	int		n_entries;
	char  **hashes;
	char   *merkle_root;
	char   *prev_block_hash;
	int64	block_number;
	int64	block_id;
	char   *block_hash;
	char	count_str[32];

	/* Get unfinalized entries */
	snprintf(query, sizeof(query),
			 "SELECT id, row_hash FROM pgsigchain.chain_log "
			 "WHERE table_oid = %u AND block_id IS NULL ORDER BY id",
			 table_oid);
	ret = SPI_execute(query, true, 0);
	if (ret != SPI_OK_SELECT)
		ereport(ERROR,
				(errcode(ERRCODE_INTERNAL_ERROR),
				 errmsg("pgsigchain: failed to query unfinalized entries")));

	n_entries = SPI_processed;
	if (n_entries == 0)
		return 0;

	/* Collect hashes */
	hashes = palloc(sizeof(char *) * n_entries);
	for (int i = 0; i < n_entries; i++)
		hashes[i] = pstrdup(SPI_getvalue(SPI_tuptable->vals[i],
										  SPI_tuptable->tupdesc, 2));

	/* Compute merkle root */
	merkle_root = compute_merkle_root(hashes, n_entries);

	/* Get previous block hash */
	snprintf(query, sizeof(query),
			 "SELECT block_hash, block_number FROM pgsigchain.blocks "
			 "WHERE table_oid = %u ORDER BY block_number DESC LIMIT 1",
			 table_oid);
	ret = SPI_execute(query, true, 1);
	if (ret == SPI_OK_SELECT && SPI_processed > 0)
	{
		prev_block_hash = pstrdup(SPI_getvalue(SPI_tuptable->vals[0],
											    SPI_tuptable->tupdesc, 1));
		block_number = atol(SPI_getvalue(SPI_tuptable->vals[0],
										  SPI_tuptable->tupdesc, 2)) + 1;
	}
	else
	{
		prev_block_hash = pstrdup("0");
		block_number = 1;
	}

	/* block_hash = SHA256(prev_block_hash || merkle_root || entries_count) */
	{
		size_t	plen, mlen, clen;
		char   *concat;

		snprintf(count_str, sizeof(count_str), "%d", n_entries);
		plen = strlen(prev_block_hash);
		mlen = strlen(merkle_root);
		clen = strlen(count_str);
		concat = palloc(plen + mlen + clen + 1);
		memcpy(concat, prev_block_hash, plen);
		memcpy(concat + plen, merkle_root, mlen);
		memcpy(concat + plen + mlen, count_str, clen);
		concat[plen + mlen + clen] = '\0';
		block_hash = pgsigchain_compute_sha256(concat, plen + mlen + clen);
		pfree(concat);
	}

	/* Insert block */
	{
		Oid		argtypes[6] = {OIDOID, INT8OID, TEXTOID, TEXTOID, INT4OID, TEXTOID};
		Datum	values[6];
		char	nulls[6] = {' ', ' ', ' ', ' ', ' ', ' '};

		values[0] = ObjectIdGetDatum(table_oid);
		values[1] = Int64GetDatum(block_number);
		values[2] = CStringGetTextDatum(prev_block_hash);
		values[3] = CStringGetTextDatum(block_hash);
		values[4] = Int32GetDatum(n_entries);
		values[5] = CStringGetTextDatum(merkle_root);

		ret = SPI_execute_with_args(
			"INSERT INTO pgsigchain.blocks "
			"(table_oid, block_number, prev_block_hash, block_hash, entries_count, merkle_root) "
			"VALUES ($1, $2, $3, $4, $5, $6) RETURNING id",
			6, argtypes, values, nulls, false, 0);

		if (ret != SPI_OK_INSERT_RETURNING || SPI_processed == 0)
			ereport(ERROR,
					(errcode(ERRCODE_INTERNAL_ERROR),
					 errmsg("pgsigchain: failed to insert block")));

		block_id = atol(SPI_getvalue(SPI_tuptable->vals[0],
									  SPI_tuptable->tupdesc, 1));
	}

	/* Update chain_log entries with block_id */
	snprintf(query, sizeof(query),
			 "UPDATE pgsigchain.chain_log SET block_id = %ld "
			 "WHERE table_oid = %u AND block_id IS NULL",
			 block_id, table_oid);
	SPI_execute(query, false, 0);

	return block_id;
}

/*
 * pgsigchain.finalize_block(table_name) -> bigint (block_id)
 */
PG_FUNCTION_INFO_V1(pgsigchain_finalize_block);

Datum
pgsigchain_finalize_block(PG_FUNCTION_ARGS)
{
	text   *table_name_text = PG_GETARG_TEXT_P(0);
	char   *table_name = text_to_cstring(table_name_text);
	Oid		relid;
	int64	block_id;

	relid = pgsigchain_resolve_protected_table(table_name);

	SPI_connect();
	block_id = pgsigchain_do_finalize_block(relid);
	SPI_finish();

	if (block_id == 0)
		PG_RETURN_NULL();

	PG_RETURN_INT64(block_id);
}

/*
 * pgsigchain.block_info(table_name) -> SETOF record
 */
PG_FUNCTION_INFO_V1(pgsigchain_block_info);

Datum
pgsigchain_block_info(PG_FUNCTION_ARGS)
{
	FuncCallContext    *funcctx;
	TupleDesc			tupdesc;

	if (SRF_IS_FIRSTCALL())
	{
		MemoryContext	oldcontext;
		text   *table_name_text = PG_GETARG_TEXT_P(0);
		char   *table_name = text_to_cstring(table_name_text);
		Oid		relid;
		int		ret;
		char	query[512];

		funcctx = SRF_FIRSTCALL_INIT();
		oldcontext = MemoryContextSwitchTo(funcctx->multi_call_memory_ctx);

		relid = pgsigchain_resolve_protected_table(table_name);

		SPI_connect();

		snprintf(query, sizeof(query),
				 "SELECT block_number, block_hash, prev_block_hash, "
				 "entries_count, merkle_root, created_at "
				 "FROM pgsigchain.blocks WHERE table_oid = %u ORDER BY block_number",
				 relid);
		ret = SPI_execute(query, true, 0);

		if (ret != SPI_OK_SELECT)
			ereport(ERROR,
					(errcode(ERRCODE_INTERNAL_ERROR),
					 errmsg("pgsigchain: failed to query blocks")));

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
		char		   *val;

		spi_tuple = tuptable->vals[funcctx->call_cntr];

		/* block_number */
		val = SPI_getvalue(spi_tuple, tuptable->tupdesc, 1);
		values[0] = Int64GetDatum(atol(val));

		/* block_hash */
		val = SPI_getvalue(spi_tuple, tuptable->tupdesc, 2);
		values[1] = CStringGetTextDatum(val);

		/* prev_block_hash */
		val = SPI_getvalue(spi_tuple, tuptable->tupdesc, 3);
		values[2] = CStringGetTextDatum(val);

		/* entries_count */
		val = SPI_getvalue(spi_tuple, tuptable->tupdesc, 4);
		values[3] = Int32GetDatum(atoi(val));

		/* merkle_root */
		val = SPI_getvalue(spi_tuple, tuptable->tupdesc, 5);
		values[4] = CStringGetTextDatum(val);

		/* created_at */
		values[5] = SPI_getbinval(spi_tuple, tuptable->tupdesc, 6, &nulls[5]);

		result_tuple = heap_form_tuple(funcctx->tuple_desc, values, nulls);
		SRF_RETURN_NEXT(funcctx, HeapTupleGetDatum(result_tuple));
	}
	else
	{
		SPI_finish();
		SRF_RETURN_DONE(funcctx);
	}
}

/*
 * pgsigchain.verify_blocks(table_name) -> boolean
 */
PG_FUNCTION_INFO_V1(pgsigchain_verify_blocks);

Datum
pgsigchain_verify_blocks(PG_FUNCTION_ARGS)
{
	text   *table_name_text = PG_GETARG_TEXT_P(0);
	char   *table_name = text_to_cstring(table_name_text);
	Oid		relid;
	int		ret;
	char	query[512];
	int		n_blocks;

	relid = pgsigchain_resolve_protected_table(table_name);

	SPI_connect();

	snprintf(query, sizeof(query),
			 "SELECT id, block_number, prev_block_hash, block_hash, "
			 "entries_count, merkle_root "
			 "FROM pgsigchain.blocks WHERE table_oid = %u ORDER BY block_number",
			 relid);
	ret = SPI_execute(query, true, 0);
	if (ret != SPI_OK_SELECT)
	{
		SPI_finish();
		ereport(ERROR,
				(errcode(ERRCODE_INTERNAL_ERROR),
				 errmsg("pgsigchain: failed to query blocks")));
	}

	n_blocks = SPI_processed;

	for (int i = 0; i < n_blocks; i++)
	{
		int64	block_id;
		char   *stored_prev_hash;
		char   *stored_block_hash;
		int		entries_count;
		char   *stored_merkle_root;
		char   *computed_block_hash;
		char   *computed_merkle_root;
		char	count_str[32];
		char  **entry_hashes;
		int		n_entries;
		int		ret2;
		char	q2[256];
		SPITupleTable *saved_tuptable;

		block_id = atol(SPI_getvalue(SPI_tuptable->vals[i],
									  SPI_tuptable->tupdesc, 1));
		stored_prev_hash = pstrdup(SPI_getvalue(SPI_tuptable->vals[i],
												 SPI_tuptable->tupdesc, 3));
		stored_block_hash = pstrdup(SPI_getvalue(SPI_tuptable->vals[i],
												  SPI_tuptable->tupdesc, 4));
		entries_count = atoi(SPI_getvalue(SPI_tuptable->vals[i],
										   SPI_tuptable->tupdesc, 5));
		stored_merkle_root = pstrdup(SPI_getvalue(SPI_tuptable->vals[i],
												   SPI_tuptable->tupdesc, 6));

		/* Save the tuptable pointer since nested SPI will overwrite */
		saved_tuptable = SPI_tuptable;

		/* Recompute merkle root from chain_log entries in this block */
		snprintf(q2, sizeof(q2),
				 "SELECT row_hash FROM pgsigchain.chain_log "
				 "WHERE block_id = %ld ORDER BY id", block_id);
		ret2 = SPI_execute(q2, true, 0);
		if (ret2 != SPI_OK_SELECT)
		{
			SPI_finish();
			PG_RETURN_BOOL(false);
		}

		n_entries = SPI_processed;
		entry_hashes = palloc(sizeof(char *) * n_entries);
		for (int j = 0; j < n_entries; j++)
			entry_hashes[j] = pstrdup(SPI_getvalue(SPI_tuptable->vals[j],
													SPI_tuptable->tupdesc, 1));

		computed_merkle_root = compute_merkle_root(entry_hashes, n_entries);

		if (strcmp(computed_merkle_root, stored_merkle_root) != 0)
		{
			SPI_finish();
			PG_RETURN_BOOL(false);
		}

		/* Recompute block_hash */
		{
			size_t plen, mlen, clen;
			char  *concat;

			snprintf(count_str, sizeof(count_str), "%d", entries_count);
			plen = strlen(stored_prev_hash);
			mlen = strlen(computed_merkle_root);
			clen = strlen(count_str);
			concat = palloc(plen + mlen + clen + 1);
			memcpy(concat, stored_prev_hash, plen);
			memcpy(concat + plen, computed_merkle_root, mlen);
			memcpy(concat + plen + mlen, count_str, clen);
			concat[plen + mlen + clen] = '\0';
			computed_block_hash = pgsigchain_compute_sha256(concat, plen + mlen + clen);
			pfree(concat);
		}

		if (strcmp(computed_block_hash, stored_block_hash) != 0)
		{
			SPI_finish();
			PG_RETURN_BOOL(false);
		}

		/* Restore saved tuptable for next iteration */
		SPI_tuptable = saved_tuptable;

		pfree(entry_hashes);
	}

	SPI_finish();
	PG_RETURN_BOOL(true);
}
