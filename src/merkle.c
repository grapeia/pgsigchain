#include "merkle.h"
#include "hash.h"
#include "protect.h"

#include "access/table.h"
#include "catalog/namespace.h"
#include "executor/spi.h"
#include "utils/array.h"
#include "utils/builtins.h"
#include "utils/lsyscache.h"
#include "utils/regproc.h"

/*
 * pgsigchain.build_merkle(table_name) -> root hash text
 *
 * Builds a Merkle tree from all chain_log entries for the table.
 * Stores nodes in merkle_nodes. Returns the root hash.
 */
PG_FUNCTION_INFO_V1(pgsigchain_build_merkle);

Datum
pgsigchain_build_merkle(PG_FUNCTION_ARGS)
{
	text   *table_name_text = PG_GETARG_TEXT_P(0);
	char   *table_name = text_to_cstring(table_name_text);
	Oid		relid;
	int		ret;
	char	query[512];
	int64	block_id;
	int		n_leaves;
	char  **hashes;
	int		n_hashes;
	int		level;

	relid = pgsigchain_resolve_protected_table(table_name);

	SPI_connect();

	/* Clean existing merkle nodes for this table */
	snprintf(query, sizeof(query),
			 "DELETE FROM pgsigchain.merkle_nodes WHERE table_oid = %u", relid);
	SPI_execute(query, false, 0);

	/* Get new block_id */
	snprintf(query, sizeof(query),
			 "SELECT COALESCE(MAX(block_id), 0) + 1 FROM pgsigchain.merkle_nodes "
			 "WHERE table_oid = %u", relid);
	ret = SPI_execute(query, true, 1);
	if (ret == SPI_OK_SELECT && SPI_processed > 0)
	{
		char *val = SPI_getvalue(SPI_tuptable->vals[0],
								 SPI_tuptable->tupdesc, 1);
		block_id = atol(val);
	}
	else
	{
		block_id = 1;
	}

	/* Get all row hashes (leaves) */
	snprintf(query, sizeof(query),
			 "SELECT row_hash FROM pgsigchain.chain_log "
			 "WHERE table_oid = %u ORDER BY id", relid);
	ret = SPI_execute(query, true, 0);
	if (ret != SPI_OK_SELECT)
		ereport(ERROR,
				(errcode(ERRCODE_INTERNAL_ERROR),
				 errmsg("pgsigchain: failed to query chain_log")));

	n_leaves = SPI_processed;
	if (n_leaves == 0)
	{
		SPI_finish();
		PG_RETURN_NULL();
	}

	/* Collect leaf hashes */
	hashes = palloc(sizeof(char *) * n_leaves);
	for (int i = 0; i < n_leaves; i++)
	{
		char *val = SPI_getvalue(SPI_tuptable->vals[i],
								 SPI_tuptable->tupdesc, 1);
		hashes[i] = pstrdup(val);
	}
	n_hashes = n_leaves;

	/* Insert leaf nodes */
	for (int i = 0; i < n_leaves; i++)
	{
		Oid		argtypes[5] = {OIDOID, INT4OID, INT4OID, TEXTOID, INT8OID};
		Datum	values[5];
		char	nulls[5] = {' ', ' ', ' ', ' ', ' '};

		values[0] = ObjectIdGetDatum(relid);
		values[1] = Int32GetDatum(0);	/* level 0 = leaf */
		values[2] = Int32GetDatum(i);
		values[3] = CStringGetTextDatum(hashes[i]);
		values[4] = Int64GetDatum(block_id);

		SPI_execute_with_args(
			"INSERT INTO pgsigchain.merkle_nodes "
			"(table_oid, level, position, hash, block_id) "
			"VALUES ($1, $2, $3, $4, $5)",
			5, argtypes, values, nulls, false, 0);
	}

	/* Build tree levels bottom-up */
	level = 0;
	while (n_hashes > 1)
	{
		int new_count = (n_hashes + 1) / 2;
		char **new_hashes = palloc(sizeof(char *) * new_count);

		for (int i = 0; i < new_count; i++)
		{
			int left_idx = i * 2;
			int right_idx = i * 2 + 1;
			char *left_hash = hashes[left_idx];
			char *right_hash;
			char *concat;
			size_t llen, rlen;

			if (right_idx < n_hashes)
				right_hash = hashes[right_idx];
			else
				right_hash = left_hash; /* duplicate last node if odd */

			llen = strlen(left_hash);
			rlen = strlen(right_hash);
			concat = palloc(llen + rlen + 1);
			memcpy(concat, left_hash, llen);
			memcpy(concat + llen, right_hash, rlen);
			concat[llen + rlen] = '\0';

			new_hashes[i] = pgsigchain_compute_sha256(concat, llen + rlen);
			pfree(concat);

			/* Insert parent node */
			{
				Oid		argtypes[5] = {OIDOID, INT4OID, INT4OID, TEXTOID, INT8OID};
				Datum	values[5];
				char	nulls[5] = {' ', ' ', ' ', ' ', ' '};

				values[0] = ObjectIdGetDatum(relid);
				values[1] = Int32GetDatum(level + 1);
				values[2] = Int32GetDatum(i);
				values[3] = CStringGetTextDatum(new_hashes[i]);
				values[4] = Int64GetDatum(block_id);

				SPI_execute_with_args(
					"INSERT INTO pgsigchain.merkle_nodes "
					"(table_oid, level, position, hash, block_id) "
					"VALUES ($1, $2, $3, $4, $5)",
					5, argtypes, values, nulls, false, 0);
			}
		}

		pfree(hashes);
		hashes = new_hashes;
		n_hashes = new_count;
		level++;
	}

	/* hashes[0] is the root */
	{
		text *root = cstring_to_text(hashes[0]);
		SPI_finish();
		PG_RETURN_TEXT_P(root);
	}
}

/*
 * pgsigchain.merkle_root(table_name) -> text
 * Returns the current Merkle root hash from stored nodes.
 */
PG_FUNCTION_INFO_V1(pgsigchain_merkle_root);

Datum
pgsigchain_merkle_root(PG_FUNCTION_ARGS)
{
	text   *table_name_text = PG_GETARG_TEXT_P(0);
	char   *table_name = text_to_cstring(table_name_text);
	Oid		relid;
	int		ret;
	char	query[512];

	relid = pgsigchain_resolve_protected_table(table_name);

	SPI_connect();

	snprintf(query, sizeof(query),
			 "SELECT hash FROM pgsigchain.merkle_nodes "
			 "WHERE table_oid = %u "
			 "ORDER BY block_id DESC, level DESC, position ASC LIMIT 1",
			 relid);
	ret = SPI_execute(query, true, 1);

	if (ret != SPI_OK_SELECT || SPI_processed == 0)
	{
		SPI_finish();
		PG_RETURN_NULL();
	}

	{
		char *val = SPI_getvalue(SPI_tuptable->vals[0],
								 SPI_tuptable->tupdesc, 1);
		text *result = cstring_to_text(pstrdup(val));
		SPI_finish();
		PG_RETURN_TEXT_P(result);
	}
}

/*
 * pgsigchain.merkle_proof(table_name, row_pk) -> text[]
 * Returns the Merkle proof path for a given row.
 */
PG_FUNCTION_INFO_V1(pgsigchain_merkle_proof);

Datum
pgsigchain_merkle_proof(PG_FUNCTION_ARGS)
{
	text   *table_name_text = PG_GETARG_TEXT_P(0);
	text   *row_pk_text = PG_GETARG_TEXT_P(1);
	char   *table_name = text_to_cstring(table_name_text);
	char   *row_pk = text_to_cstring(row_pk_text);
	Oid		relid;
	int		ret;
	char	query[512];
	int		position;
	int		max_level;
	Datum  *proof_datums;
	int		proof_count = 0;
	ArrayType *result;

	relid = pgsigchain_resolve_protected_table(table_name);

	SPI_connect();

	/* Find the leaf position for this row_pk via chain_log ordering */
	snprintf(query, sizeof(query),
			 "SELECT rn - 1 AS position FROM ("
			 "  SELECT row_pk, ROW_NUMBER() OVER (ORDER BY id) AS rn "
			 "  FROM pgsigchain.chain_log WHERE table_oid = %u"
			 ") sub WHERE row_pk = '%s' LIMIT 1",
			 relid, row_pk);
	ret = SPI_execute(query, true, 1);
	if (ret != SPI_OK_SELECT || SPI_processed == 0)
	{
		SPI_finish();
		ereport(ERROR,
				(errcode(ERRCODE_NO_DATA_FOUND),
				 errmsg("pgsigchain: row with pk \"%s\" not found in chain_log", row_pk)));
	}
	{
		char *val = SPI_getvalue(SPI_tuptable->vals[0],
								 SPI_tuptable->tupdesc, 1);
		position = atoi(val);
	}

	/* Get max level */
	snprintf(query, sizeof(query),
			 "SELECT MAX(level) FROM pgsigchain.merkle_nodes "
			 "WHERE table_oid = %u AND block_id = ("
			 "  SELECT MAX(block_id) FROM pgsigchain.merkle_nodes WHERE table_oid = %u"
			 ")", relid, relid);
	ret = SPI_execute(query, true, 1);
	if (ret != SPI_OK_SELECT || SPI_processed == 0)
	{
		SPI_finish();
		PG_RETURN_NULL();
	}
	{
		char *val = SPI_getvalue(SPI_tuptable->vals[0],
								 SPI_tuptable->tupdesc, 1);
		max_level = atoi(val);
	}

	/* Collect sibling hashes from each level */
	proof_datums = palloc(sizeof(Datum) * (max_level + 1));

	for (int lvl = 0; lvl < max_level; lvl++)
	{
		int sibling_pos = (position % 2 == 0) ? position + 1 : position - 1;
		char *direction = (position % 2 == 0) ? "R" : "L";

		snprintf(query, sizeof(query),
				 "SELECT hash FROM pgsigchain.merkle_nodes "
				 "WHERE table_oid = %u AND level = %d AND position = %d "
				 "AND block_id = ("
				 "  SELECT MAX(block_id) FROM pgsigchain.merkle_nodes WHERE table_oid = %u"
				 ")",
				 relid, lvl, sibling_pos, relid);
		ret = SPI_execute(query, true, 1);

		if (ret == SPI_OK_SELECT && SPI_processed > 0)
		{
			char *val = SPI_getvalue(SPI_tuptable->vals[0],
									 SPI_tuptable->tupdesc, 1);
			char *entry = palloc(strlen(direction) + 1 + strlen(val) + 1);
			sprintf(entry, "%s:%s", direction, val);
			proof_datums[proof_count++] = CStringGetTextDatum(pstrdup(entry));
			pfree(entry);
		}

		position = position / 2;
	}

	SPI_finish();

	if (proof_count == 0)
		PG_RETURN_NULL();

	result = construct_array(proof_datums, proof_count, TEXTOID, -1, false,
							 TYPALIGN_INT);
	PG_RETURN_ARRAYTYPE_P(result);
}
