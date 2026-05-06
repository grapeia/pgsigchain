#ifndef PGSIGCHAIN_BLOCKS_H
#define PGSIGCHAIN_BLOCKS_H

#include "postgres.h"
#include "fmgr.h"

/*
 * Finalize a block for the given table. Assumes SPI is already connected.
 * Returns the new block_id, or 0 if there were no unfinalized entries.
 */
int64 pgsigchain_do_finalize_block(Oid table_oid);

#endif /* PGSIGCHAIN_BLOCKS_H */
