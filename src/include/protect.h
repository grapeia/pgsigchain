#ifndef PGSIGCHAIN_PROTECT_H
#define PGSIGCHAIN_PROTECT_H

#include "postgres.h"
#include "fmgr.h"

/* Resolve table_name to OID, verifying it is protected. Caller must NOT have SPI connected. */
Oid pgsigchain_resolve_protected_table(const char *table_name);

#endif /* PGSIGCHAIN_PROTECT_H */
