#ifndef PGSIGCHAIN_SIGN_H
#define PGSIGCHAIN_SIGN_H

#include "postgres.h"
#include "fmgr.h"

/*
 * Sign data with Ed25519 private key.
 * private_key_hex: 64-char hex string (32 bytes).
 * Returns palloc'd hex signature string (128 chars = 64 bytes), or NULL on error.
 */
char *pgsigchain_sign_data(const char *data, size_t data_len, const char *private_key_hex);

/*
 * Verify Ed25519 signature.
 * Returns true if valid.
 */
bool pgsigchain_verify_sig(const char *data, size_t data_len,
					 const char *signature_hex, const char *public_key_hex);

#endif /* PGSIGCHAIN_SIGN_H */
