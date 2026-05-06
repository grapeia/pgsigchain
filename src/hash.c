#include "hash.h"

#include "fmgr.h"
#include "access/htup_details.h"
#include "catalog/pg_type.h"
#include "lib/stringinfo.h"
#include "utils/builtins.h"
#include "utils/lsyscache.h"
#include "utils/rel.h"

#include <openssl/evp.h>

void
pgsigchain_canonical_append_field(StringInfo buf, const char *bytes, int len, bool isnull)
{
	unsigned char	tag;
	unsigned char	be_len[4];

	if (isnull)
	{
		tag = 0x00;
		appendBinaryStringInfo(buf, (const char *) &tag, 1);
		return;
	}

	tag = 0x01;
	appendBinaryStringInfo(buf, (const char *) &tag, 1);

	/* Explicit big-endian length so the encoding is host-order independent. */
	be_len[0] = (unsigned char) ((len >> 24) & 0xff);
	be_len[1] = (unsigned char) ((len >> 16) & 0xff);
	be_len[2] = (unsigned char) ((len >> 8) & 0xff);
	be_len[3] = (unsigned char) (len & 0xff);
	appendBinaryStringInfo(buf, (const char *) be_len, 4);

	if (len > 0)
		appendBinaryStringInfo(buf, bytes, len);
}

char *
pgsigchain_bytes_to_hex(const unsigned char *bytes, size_t len)
{
	char *hex = palloc(len * 2 + 1);
	static const char hexchars[] = "0123456789abcdef";

	for (size_t i = 0; i < len; i++)
	{
		hex[i * 2]     = hexchars[(bytes[i] >> 4) & 0x0f];
		hex[i * 2 + 1] = hexchars[bytes[i] & 0x0f];
	}
	hex[len * 2] = '\0';
	return hex;
}

static unsigned char
hex_nibble(char c)
{
	if (c >= '0' && c <= '9') return c - '0';
	if (c >= 'a' && c <= 'f') return 10 + (c - 'a');
	if (c >= 'A' && c <= 'F') return 10 + (c - 'A');
	ereport(ERROR,
			(errcode(ERRCODE_INVALID_PARAMETER_VALUE),
			 errmsg("pgsigchain: invalid hex character '%c'", c)));
	return 0; /* unreachable */
}

unsigned char *
pgsigchain_hex_to_bytes(const char *hex, size_t *out_len)
{
	size_t			hex_len = strlen(hex);
	size_t			byte_len;
	unsigned char  *bytes;

	if (hex_len % 2 != 0)
		ereport(ERROR,
				(errcode(ERRCODE_INVALID_PARAMETER_VALUE),
				 errmsg("pgsigchain: hex string must have even length")));

	byte_len = hex_len / 2;
	bytes = palloc(byte_len);

	for (size_t i = 0; i < byte_len; i++)
		bytes[i] = (hex_nibble(hex[i * 2]) << 4) | hex_nibble(hex[i * 2 + 1]);

	*out_len = byte_len;
	return bytes;
}

char *
pgsigchain_compute_sha256(const char *data, size_t len)
{
	EVP_MD_CTX	   *ctx;
	unsigned char	hash[EVP_MAX_MD_SIZE];
	unsigned int	hash_len;

	ctx = EVP_MD_CTX_new();
	if (!ctx)
		ereport(ERROR,
				(errcode(ERRCODE_OUT_OF_MEMORY),
				 errmsg("pgsigchain: failed to allocate EVP_MD_CTX")));

	if (EVP_DigestInit_ex(ctx, EVP_sha256(), NULL) != 1 ||
		EVP_DigestUpdate(ctx, data, len) != 1 ||
		EVP_DigestFinal_ex(ctx, hash, &hash_len) != 1)
	{
		EVP_MD_CTX_free(ctx);
		ereport(ERROR,
				(errcode(ERRCODE_INTERNAL_ERROR),
				 errmsg("pgsigchain: SHA-256 computation failed")));
	}

	EVP_MD_CTX_free(ctx);
	return pgsigchain_bytes_to_hex(hash, hash_len);
}

static void
append_actor_text(StringInfo buf, const char *s)
{
	if (s == NULL)
		pgsigchain_canonical_append_field(buf, NULL, 0, true);
	else
		pgsigchain_canonical_append_field(buf, s, strlen(s), false);
}

char *
pgsigchain_compute_row_hash(Relation rel, HeapTuple tuple, const PgsigchainActor *actor)
{
	TupleDesc		tupdesc = RelationGetDescr(rel);
	StringInfoData	buf;
	char		   *result;
	char			pid_buf[16];

	initStringInfo(&buf);

	for (int i = 0; i < tupdesc->natts; i++)
	{
		Form_pg_attribute att = TupleDescAttr(tupdesc, i);
		Datum	val;
		bool	isnull;
		Oid		typsend;
		bool	typIsVarlena;
		bytea  *binval;

		if (att->attisdropped)
			continue;

		val = heap_getattr(tuple, i + 1, tupdesc, &isnull);

		if (isnull)
		{
			pgsigchain_canonical_append_field(&buf, NULL, 0, true);
			continue;
		}

		/* Binary type output is more stable across PG versions and GUCs than text. */
		getTypeBinaryOutputInfo(att->atttypid, &typsend, &typIsVarlena);
		binval = OidSendFunctionCall(typsend, val);
		pgsigchain_canonical_append_field(&buf, VARDATA(binval),
									VARSIZE(binval) - VARHDRSZ, false);
		pfree(binval);
	}

	if (actor != NULL)
	{
		append_actor_text(&buf, actor->user);
		append_actor_text(&buf, actor->app_name);
		append_actor_text(&buf, actor->addr);
		snprintf(pid_buf, sizeof(pid_buf), "%d", actor->pid);
		append_actor_text(&buf, pid_buf);
	}

	result = pgsigchain_compute_sha256(buf.data, buf.len);
	pfree(buf.data);
	return result;
}

/* SQL-callable: pgsigchain.sha256(bytea) -> text */
PG_FUNCTION_INFO_V1(pgsigchain_sha256);

Datum
pgsigchain_sha256(PG_FUNCTION_ARGS)
{
	bytea  *input = PG_GETARG_BYTEA_P(0);
	char   *hex;

	hex = pgsigchain_compute_sha256(VARDATA(input), VARSIZE(input) - VARHDRSZ);
	PG_RETURN_TEXT_P(cstring_to_text(hex));
}
