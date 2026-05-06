EXTENSION = pgsigchain
MODULE_big = pgsigchain
DATA = sql/pgsigchain--0.3.0.sql
OBJS = src/pgsigchain.o src/hash.o src/chain.o src/immutable.o src/merkle.o src/protect.o src/verify.o src/blocks.o src/sign.o src/anchor.o
SHLIB_LINK = -lcrypto
PG_CPPFLAGS = -Isrc/include

REGRESS = pgsigchain_test
REGRESS_OPTS = --inputdir=test

PG_CONFIG ?= pg_config
PGXS := $(shell $(PG_CONFIG) --pgxs)
include $(PGXS)
