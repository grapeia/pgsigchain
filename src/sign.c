#include "sign.h"
#include "hash.h"
#include "protect.h"

#include "catalog/namespace.h"
#include "catalog/pg_type.h"
#include "executor/spi.h"
#include "funcapi.h"
#include "utils/array.h"
#include "utils/builtins.h"
#include "utils/lsyscache.h"
#include "utils/regproc.h"

#include <openssl/evp.h>

/*
 * Sign data with Ed25519 private key.
 */
char *
pgsigchain_sign_data(const char *data, size_t data_len, const char *private_key_hex)
{
	size_t			key_len;
	unsigned char  *key_bytes;
	EVP_PKEY	   *pkey;
	EVP_MD_CTX	   *mdctx;
	unsigned char	sig[64];
	size_t			sig_len = sizeof(sig);

	key_bytes = pgsigchain_hex_to_bytes(private_key_hex, &key_len);
	if (key_len != 32)
	{
		pfree(key_bytes);
		ereport(ERROR,
				(errcode(ERRCODE_INVALID_PARAMETER_VALUE),
				 errmsg("pgsigchain: Ed25519 private key must be 32 bytes")));
	}

	pkey = EVP_PKEY_new_raw_private_key(EVP_PKEY_ED25519, NULL, key_bytes, 32);
	pfree(key_bytes);
	if (!pkey)
		ereport(ERROR,
				(errcode(ERRCODE_INTERNAL_ERROR),
				 errmsg("pgsigchain: failed to create Ed25519 key from private key")));

	mdctx = EVP_MD_CTX_new();
	if (!mdctx)
	{
		EVP_PKEY_free(pkey);
		ereport(ERROR,
				(errcode(ERRCODE_OUT_OF_MEMORY),
				 errmsg("pgsigchain: failed to allocate EVP_MD_CTX")));
	}

	if (EVP_DigestSignInit(mdctx, NULL, NULL, NULL, pkey) != 1 ||
		EVP_DigestSign(mdctx, sig, &sig_len,
					   (const unsigned char *) data, data_len) != 1)
	{
		EVP_MD_CTX_free(mdctx);
		EVP_PKEY_free(pkey);
		ereport(ERROR,
				(errcode(ERRCODE_INTERNAL_ERROR),
				 errmsg("pgsigchain: Ed25519 signing failed")));
	}

	EVP_MD_CTX_free(mdctx);
	EVP_PKEY_free(pkey);

	return pgsigchain_bytes_to_hex(sig, sig_len);
}

/*
 * Verify Ed25519 signature.
 */
bool
pgsigchain_verify_sig(const char *data, size_t data_len,
				const char *signature_hex, const char *public_key_hex)
{
	size_t			key_len, sig_len;
	unsigned char  *key_bytes;
	unsigned char  *sig_bytes;
	EVP_PKEY	   *pkey;
	EVP_MD_CTX	   *mdctx;
	int				result;

	key_bytes = pgsigchain_hex_to_bytes(public_key_hex, &key_len);
	sig_bytes = pgsigchain_hex_to_bytes(signature_hex, &sig_len);

	if (key_len != 32 || sig_len != 64)
	{
		pfree(key_bytes);
		pfree(sig_bytes);
		return false;
	}

	pkey = EVP_PKEY_new_raw_public_key(EVP_PKEY_ED25519, NULL, key_bytes, 32);
	pfree(key_bytes);
	if (!pkey)
	{
		pfree(sig_bytes);
		return false;
	}

	mdctx = EVP_MD_CTX_new();
	if (!mdctx)
	{
		EVP_PKEY_free(pkey);
		pfree(sig_bytes);
		return false;
	}

	if (EVP_DigestVerifyInit(mdctx, NULL, NULL, NULL, pkey) != 1)
	{
		EVP_MD_CTX_free(mdctx);
		EVP_PKEY_free(pkey);
		pfree(sig_bytes);
		return false;
	}

	result = EVP_DigestVerify(mdctx, sig_bytes, sig_len,
							  (const unsigned char *) data, data_len);

	EVP_MD_CTX_free(mdctx);
	EVP_PKEY_free(pkey);
	pfree(sig_bytes);

	return (result == 1);
}

/*
 * pgsigchain.generate_keypair() -> (public_key text, private_key text)
 */
PG_FUNCTION_INFO_V1(pgsigchain_generate_keypair);

Datum
pgsigchain_generate_keypair(PG_FUNCTION_ARGS)
{
	EVP_PKEY_CTX   *ctx;
	EVP_PKEY	   *pkey = NULL;
	unsigned char	priv[32], pub[32];
	size_t			priv_len = 32, pub_len = 32;
	char		   *priv_hex, *pub_hex;
	TupleDesc		tupdesc;
	Datum			values[2];
	bool			nulls[2] = {false, false};
	HeapTuple		result_tuple;

	ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_ED25519, NULL);
	if (!ctx)
		ereport(ERROR,
				(errcode(ERRCODE_INTERNAL_ERROR),
				 errmsg("pgsigchain: failed to create Ed25519 context")));

	if (EVP_PKEY_keygen_init(ctx) != 1 ||
		EVP_PKEY_keygen(ctx, &pkey) != 1)
	{
		EVP_PKEY_CTX_free(ctx);
		ereport(ERROR,
				(errcode(ERRCODE_INTERNAL_ERROR),
				 errmsg("pgsigchain: Ed25519 key generation failed")));
	}
	EVP_PKEY_CTX_free(ctx);

	EVP_PKEY_get_raw_private_key(pkey, priv, &priv_len);
	EVP_PKEY_get_raw_public_key(pkey, pub, &pub_len);
	EVP_PKEY_free(pkey);

	priv_hex = pgsigchain_bytes_to_hex(priv, priv_len);
	pub_hex = pgsigchain_bytes_to_hex(pub, pub_len);

	if (get_call_result_type(fcinfo, NULL, &tupdesc) != TYPEFUNC_COMPOSITE)
		ereport(ERROR,
				(errcode(ERRCODE_FEATURE_NOT_SUPPORTED),
				 errmsg("function returning record called in context "
						"that cannot accept type record")));

	tupdesc = BlessTupleDesc(tupdesc);
	values[0] = CStringGetTextDatum(pub_hex);
	values[1] = CStringGetTextDatum(priv_hex);

	result_tuple = heap_form_tuple(tupdesc, values, nulls);
	PG_RETURN_DATUM(HeapTupleGetDatum(result_tuple));
}

/*
 * pgsigchain.set_signing_key(table_name, public_key) -> void
 */
PG_FUNCTION_INFO_V1(pgsigchain_set_signing_key);

Datum
pgsigchain_set_signing_key(PG_FUNCTION_ARGS)
{
	text		   *table_name_text = PG_GETARG_TEXT_P(0);
	text		   *pubkey_text = PG_GETARG_TEXT_P(1);
	char		   *table_name = text_to_cstring(table_name_text);
	char		   *pubkey_hex = text_to_cstring(pubkey_text);
	Oid				relid;
	int				ret;
	size_t			key_len;
	unsigned char  *key_bytes;
	EVP_PKEY	   *pkey;

	if (strlen(pubkey_hex) != 64)
		ereport(ERROR,
				(errcode(ERRCODE_INVALID_PARAMETER_VALUE),
				 errmsg("pgsigchain: public key must be 64 hex characters (32 bytes)")));

	key_bytes = pgsigchain_hex_to_bytes(pubkey_hex, &key_len);
	if (key_len != 32)
	{
		pfree(key_bytes);
		ereport(ERROR,
				(errcode(ERRCODE_INVALID_PARAMETER_VALUE),
				 errmsg("pgsigchain: public key must decode to 32 bytes")));
	}

	pkey = EVP_PKEY_new_raw_public_key(EVP_PKEY_ED25519, NULL, key_bytes, 32);
	pfree(key_bytes);
	if (!pkey)
		ereport(ERROR,
				(errcode(ERRCODE_INVALID_PARAMETER_VALUE),
				 errmsg("pgsigchain: invalid Ed25519 public key")));
	EVP_PKEY_free(pkey);

	relid = pgsigchain_resolve_protected_table(table_name);

	SPI_connect();

	{
		Oid		argtypes[3] = {OIDOID, TEXTOID, TEXTOID};
		Datum	values[3];
		char	nulls[3] = {' ', ' ', ' '};

		values[0] = ObjectIdGetDatum(relid);
		values[1] = CStringGetTextDatum(pubkey_hex);
		values[2] = CStringGetTextDatum("Ed25519");

		ret = SPI_execute_with_args(
			"INSERT INTO pgsigchain.signing_keys "
			"(table_oid, public_key, key_algorithm) "
			"VALUES ($1, $2, $3) "
			"ON CONFLICT (table_oid) DO UPDATE SET "
			"public_key = EXCLUDED.public_key, "
			"key_algorithm = EXCLUDED.key_algorithm",
			3, argtypes, values, nulls, false, 0);

		if (ret != SPI_OK_INSERT)
			ereport(ERROR,
					(errcode(ERRCODE_INTERNAL_ERROR),
					 errmsg("pgsigchain: failed to set signing key")));
	}

	SPI_finish();

	PG_RETURN_VOID();
}

/*
 * pgsigchain.sign_chain_entry(table_name, chain_log_id, private_key) -> void
 *
 * Signs an existing chain_log entry post-hoc. The private key is supplied per
 * call and never persisted.
 */
PG_FUNCTION_INFO_V1(pgsigchain_sign_chain_entry);

Datum
pgsigchain_sign_chain_entry(PG_FUNCTION_ARGS)
{
	text		   *table_name_text = PG_GETARG_TEXT_P(0);
	int64			chain_log_id = PG_GETARG_INT64(1);
	text		   *privkey_text = PG_GETARG_TEXT_P(2);
	char		   *table_name = text_to_cstring(table_name_text);
	char		   *privkey_hex = text_to_cstring(privkey_text);
	Oid				relid;
	int				ret;
	char		   *chain_hash;
	char		   *registered_pub;
	char		   *derived_pub_hex;
	char		   *signature;
	size_t			key_len;
	unsigned char  *key_bytes;
	EVP_PKEY	   *pkey;
	unsigned char	pub[32];
	size_t			pub_len = 32;

	if (strlen(privkey_hex) != 64)
		ereport(ERROR,
				(errcode(ERRCODE_INVALID_PARAMETER_VALUE),
				 errmsg("pgsigchain: private key must be 64 hex characters (32 bytes)")));

	relid = pgsigchain_resolve_protected_table(table_name);

	SPI_connect();

	{
		Oid		argtypes[2] = {OIDOID, INT8OID};
		Datum	values[2];

		values[0] = ObjectIdGetDatum(relid);
		values[1] = Int64GetDatum(chain_log_id);

		ret = SPI_execute_with_args(
			"SELECT chain_hash FROM pgsigchain.chain_log "
			"WHERE id = $2 AND table_oid = $1",
			2, argtypes, values, NULL, true, 1);

		if (ret != SPI_OK_SELECT || SPI_processed == 0)
		{
			SPI_finish();
			ereport(ERROR,
					(errcode(ERRCODE_NO_DATA_FOUND),
					 errmsg("pgsigchain: chain_log entry %ld not found for table",
							chain_log_id)));
		}

		chain_hash = pstrdup(SPI_getvalue(SPI_tuptable->vals[0],
										   SPI_tuptable->tupdesc, 1));
	}

	{
		Oid		argtypes[1] = {OIDOID};
		Datum	values[1];

		values[0] = ObjectIdGetDatum(relid);

		ret = SPI_execute_with_args(
			"SELECT public_key FROM pgsigchain.signing_keys WHERE table_oid = $1",
			1, argtypes, values, NULL, true, 1);

		if (ret != SPI_OK_SELECT || SPI_processed == 0)
		{
			SPI_finish();
			ereport(ERROR,
					(errcode(ERRCODE_NO_DATA_FOUND),
					 errmsg("pgsigchain: no signing key registered for table")));
		}

		registered_pub = pstrdup(SPI_getvalue(SPI_tuptable->vals[0],
											   SPI_tuptable->tupdesc, 1));
	}

	/* Derive pubkey from supplied privkey and confirm it matches what we have. */
	key_bytes = pgsigchain_hex_to_bytes(privkey_hex, &key_len);
	if (key_len != 32)
	{
		pfree(key_bytes);
		SPI_finish();
		ereport(ERROR,
				(errcode(ERRCODE_INVALID_PARAMETER_VALUE),
				 errmsg("pgsigchain: private key must decode to 32 bytes")));
	}

	pkey = EVP_PKEY_new_raw_private_key(EVP_PKEY_ED25519, NULL, key_bytes, 32);
	pfree(key_bytes);
	if (!pkey)
	{
		SPI_finish();
		ereport(ERROR,
				(errcode(ERRCODE_INVALID_PARAMETER_VALUE),
				 errmsg("pgsigchain: invalid Ed25519 private key")));
	}

	EVP_PKEY_get_raw_public_key(pkey, pub, &pub_len);
	EVP_PKEY_free(pkey);
	derived_pub_hex = pgsigchain_bytes_to_hex(pub, pub_len);

	if (strcmp(derived_pub_hex, registered_pub) != 0)
	{
		SPI_finish();
		ereport(ERROR,
				(errcode(ERRCODE_INVALID_PARAMETER_VALUE),
				 errmsg("pgsigchain: private key does not match registered public key")));
	}

	signature = pgsigchain_sign_data(chain_hash, strlen(chain_hash), privkey_hex);

	{
		Oid		argtypes[2] = {TEXTOID, INT8OID};
		Datum	values[2];

		values[0] = CStringGetTextDatum(signature);
		values[1] = Int64GetDatum(chain_log_id);

		ret = SPI_execute_with_args(
			"UPDATE pgsigchain.chain_log SET signature = $1 WHERE id = $2",
			2, argtypes, values, NULL, false, 0);

		if (ret != SPI_OK_UPDATE)
		{
			SPI_finish();
			ereport(ERROR,
					(errcode(ERRCODE_INTERNAL_ERROR),
					 errmsg("pgsigchain: failed to update chain_log signature")));
		}
	}

	SPI_finish();

	PG_RETURN_VOID();
}

/*
 * pgsigchain.encode_pk(VARIADIC parts TEXT[]) -> text
 *
 * Canonical-encode each element (NULL-aware) and return the hex string. Mirrors
 * what the trigger uses to build row_pk so external callers can derive lookups.
 */
PG_FUNCTION_INFO_V1(pgsigchain_encode_pk);

Datum
pgsigchain_encode_pk(PG_FUNCTION_ARGS)
{
	ArrayType	   *arr;
	Datum		   *elems;
	bool		   *nulls;
	int				nelems;
	StringInfoData	buf;
	char		   *hex;

	if (PG_ARGISNULL(0))
		PG_RETURN_NULL();

	arr = PG_GETARG_ARRAYTYPE_P(0);
	deconstruct_array(arr, TEXTOID, -1, false, 'i', &elems, &nulls, &nelems);

	initStringInfo(&buf);
	for (int i = 0; i < nelems; i++)
	{
		if (nulls[i])
			pgsigchain_canonical_append_field(&buf, NULL, 0, true);
		else
		{
			text   *t = DatumGetTextPP(elems[i]);
			char   *s = VARDATA_ANY(t);
			int		len = VARSIZE_ANY_EXHDR(t);

			pgsigchain_canonical_append_field(&buf, s, len, false);
		}
	}

	hex = pgsigchain_bytes_to_hex((const unsigned char *) buf.data, buf.len);
	pfree(buf.data);

	PG_RETURN_TEXT_P(cstring_to_text(hex));
}

/*
 * pgsigchain.get_public_key(table_name) -> text
 */
PG_FUNCTION_INFO_V1(pgsigchain_get_public_key);

Datum
pgsigchain_get_public_key(PG_FUNCTION_ARGS)
{
	text   *table_name_text = PG_GETARG_TEXT_P(0);
	char   *table_name = text_to_cstring(table_name_text);
	Oid		relid;
	int		ret;
	char	query[256];

	relid = pgsigchain_resolve_protected_table(table_name);

	SPI_connect();

	snprintf(query, sizeof(query),
			 "SELECT public_key FROM pgsigchain.signing_keys WHERE table_oid = %u",
			 relid);
	ret = SPI_execute(query, true, 1);

	if (ret != SPI_OK_SELECT || SPI_processed == 0)
	{
		SPI_finish();
		PG_RETURN_NULL();
	}

	{
		char *val = pstrdup(SPI_getvalue(SPI_tuptable->vals[0],
										  SPI_tuptable->tupdesc, 1));
		SPI_finish();
		PG_RETURN_TEXT_P(cstring_to_text(val));
	}
}

/*
 * pgsigchain.verify_signature(table_name, chain_log_id) -> boolean
 */
PG_FUNCTION_INFO_V1(pgsigchain_verify_signature);

Datum
pgsigchain_verify_signature(PG_FUNCTION_ARGS)
{
	text   *table_name_text = PG_GETARG_TEXT_P(0);
	int64	chain_log_id = PG_GETARG_INT64(1);
	char   *table_name = text_to_cstring(table_name_text);
	Oid		relid;
	int		ret;
	char	query[256];
	char   *chain_hash;
	char   *signature;
	char   *public_key;
	bool	valid;

	relid = pgsigchain_resolve_protected_table(table_name);

	SPI_connect();

	/* Get chain_hash and signature */
	snprintf(query, sizeof(query),
			 "SELECT chain_hash, signature FROM pgsigchain.chain_log WHERE id = %ld",
			 chain_log_id);
	ret = SPI_execute(query, true, 1);
	if (ret != SPI_OK_SELECT || SPI_processed == 0)
	{
		SPI_finish();
		ereport(ERROR,
				(errcode(ERRCODE_NO_DATA_FOUND),
				 errmsg("pgsigchain: chain_log entry %ld not found", chain_log_id)));
	}

	chain_hash = pstrdup(SPI_getvalue(SPI_tuptable->vals[0],
									   SPI_tuptable->tupdesc, 1));
	signature = SPI_getvalue(SPI_tuptable->vals[0], SPI_tuptable->tupdesc, 2);
	if (signature == NULL)
	{
		SPI_finish();
		ereport(ERROR,
				(errcode(ERRCODE_NULL_VALUE_NOT_ALLOWED),
				 errmsg("pgsigchain: chain_log entry %ld has no signature", chain_log_id)));
	}
	signature = pstrdup(signature);

	/* Get public key */
	snprintf(query, sizeof(query),
			 "SELECT public_key FROM pgsigchain.signing_keys WHERE table_oid = %u",
			 relid);
	ret = SPI_execute(query, true, 1);
	if (ret != SPI_OK_SELECT || SPI_processed == 0)
	{
		SPI_finish();
		ereport(ERROR,
				(errcode(ERRCODE_NO_DATA_FOUND),
				 errmsg("pgsigchain: no signing key for table")));
	}
	public_key = pstrdup(SPI_getvalue(SPI_tuptable->vals[0],
									   SPI_tuptable->tupdesc, 1));

	SPI_finish();

	valid = pgsigchain_verify_sig(chain_hash, strlen(chain_hash), signature, public_key);

	PG_RETURN_BOOL(valid);
}
