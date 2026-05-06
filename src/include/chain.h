#ifndef PGSIGCHAIN_CHAIN_H
#define PGSIGCHAIN_CHAIN_H

#include "postgres.h"
#include "fmgr.h"
#include "access/htup.h"
#include "utils/rel.h"

extern char *pgsigchain_get_row_pk_text(Relation rel, HeapTuple tuple);

#endif /* PGSIGCHAIN_CHAIN_H */
