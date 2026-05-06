#ifndef PGSIGCHAIN_HASH_H
#define PGSIGCHAIN_HASH_H

#include "postgres.h"
#include "access/htup_details.h"
#include "lib/stringinfo.h"
#include "utils/rel.h"

/* Append a single field to buf in canonical form: 1-byte tag (0x00 NULL, 0x01
 * value) + 4-byte big-endian length + raw bytes (length and bytes omitted for
 * NULL). Caller initializes the StringInfo. */
void pgsigchain_canonical_append_field(StringInfo buf, const char *bytes, int len, bool isnull);

/* Convert raw bytes to palloc'd hex string */
char *pgsigchain_bytes_to_hex(const unsigned char *bytes, size_t len);

/* Convert hex string to palloc'd raw bytes. Sets *out_len to byte count. */
unsigned char *pgsigchain_hex_to_bytes(const char *hex, size_t *out_len);

/* Compute SHA-256 of arbitrary data, returns palloc'd hex string (64 chars + null) */
char *pgsigchain_compute_sha256(const char *data, size_t len);

/* Actor identity captured at trigger time. Strings may be NULL. */
typedef struct PgsigchainActor
{
	const char	   *user;		/* current_user */
	const char	   *app_name;	/* application_name */
	const char	   *addr;		/* client addr as text, NULL for local */
	int32			pid;		/* backend pid */
} PgsigchainActor;

/* Compute SHA-256 of all columns in a tuple plus the actor identity.
 * Returns palloc'd hex string. */
char *pgsigchain_compute_row_hash(Relation rel, HeapTuple tuple, const PgsigchainActor *actor);

#endif /* PGSIGCHAIN_HASH_H */
