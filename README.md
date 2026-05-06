# pgsigchain — PostgreSQL Ledger

> **English** · [Português](README.pt-BR.md)

A PostgreSQL extension that adds a **tamper-evident append-only ledger** to existing tables. Every INSERT is hash-chained (SHA-256), grouped into immutable blocks, optionally signed (Ed25519), and externally anchorable (S3 Object Lock, OpenTimestamps, etc.) — so later rewrites of the log are detectable even by parties who don't trust the database owner.

This is not a blockchain: no decentralization, no consensus, no trustlessness. It's an audit log with cryptographic integrity that can be committed to external evidence.

## What pgsigchain is not

- Not a replacement for distributed audit systems (Merkle trees over networks, Ethereum, etc.).
- Doesn't prevent a superuser from disabling triggers and tampering with the chain — only makes that *detectable* via `verify_chain` + `verify_data` + external anchoring.
- Doesn't protect against the *absence* of events — it can only log what passes through the triggers.
- Absolute time (`created_at`) is not trustworthy — order is. For trustworthy "when", you depend on external anchors.

## Requirements

- Docker and Docker Compose

## Quick Start

```bash
# Build and start
docker compose up -d

# Connect
psql -h localhost -p 5433 -U postgres -d pgsigchain_test
# password: pgsigchain
```

The extension is created automatically in the `pgsigchain_test` database.

## Build without Docker

```bash
# Dependencies (Debian/Ubuntu)
sudo apt install postgresql-server-dev-16 libssl-dev build-essential

# Compile and install
make && sudo make install

# In PostgreSQL
CREATE EXTENSION pgsigchain;
```

## Usage

### Protect a table

```sql
CREATE TABLE ledger (
    id SERIAL PRIMARY KEY,
    amount INT NOT NULL,
    description TEXT
);

-- Default mode: immutable, no auto-finalization
SELECT pgsigchain.protect('ledger');
```

The table must have a **primary key**. Full signature:

```sql
pgsigchain.protect(table_name TEXT, mode TEXT DEFAULT 'immutable', auto_finalize INT DEFAULT NULL)
```

- `mode = 'immutable'` (default) — blocks UPDATE/DELETE, records only INSERT
- `mode = 'audit'` — allows and records INSERT/UPDATE/DELETE
- `auto_finalize = N` — automatically finalizes a block every N entries

### Insert data

```sql
INSERT INTO ledger (amount, description) VALUES (100, 'deposit');
INSERT INTO ledger (amount, description) VALUES (-50, 'withdrawal');
INSERT INTO ledger (amount, description) VALUES (200, 'bonus');
```

Each operation creates an entry in `pgsigchain.chain_log` with:

| Field | Description |
|---|---|
| `row_pk` | length-prefixed canonical encoding of the PK, hex (see `encode_pk`) |
| `row_hash` | SHA-256 of the columns with length-prefixed canonical encoding |
| `prev_hash` | `chain_hash` of the previous entry (or `0` for the first) |
| `chain_hash` | SHA-256(`prev_hash` \|\| `row_hash`) |
| `operation` | `INSERT`, `UPDATE`, or `DELETE` |
| `new_row_hash` | only for `UPDATE` (audit mode), hash of the new state |

### Modes: immutable vs audit

```sql
-- Immutable mode (default)
SELECT pgsigchain.protect('ledger', 'immutable');
UPDATE ledger SET amount = 999 WHERE id = 1;
-- ERROR: pgsigchain: UPDATE not allowed on protected table "ledger"

-- Audit mode
CREATE TABLE events (id SERIAL PRIMARY KEY, payload JSONB);
SELECT pgsigchain.protect('events', 'audit');

INSERT INTO events (payload) VALUES ('{"type":"login"}');
UPDATE events SET payload = '{"type":"login","ip":"1.2.3.4"}' WHERE id = 1;
DELETE FROM events WHERE id = 1;
-- all operations show up in pgsigchain.chain_log with the `operation` column
```

### Verification

```sql
-- The whole chain (recomputes each chain_hash)
SELECT pgsigchain.verify_chain('ledger');

-- A specific row — uses encoded row_pk
SELECT pgsigchain.verify_row('ledger', pgsigchain.encode_pk('1'));

-- Compares the current table state against the latest recorded hash
-- Detects tampering that bypassed the triggers (e.g., superuser)
SELECT pgsigchain.verify_data('ledger');
```

`verify_data` recomputes the hash of every live row in the table and compares it with the most recent `row_hash` in `chain_log`. Useful for detecting direct `UPDATE`s via `pg_class` or writes that disabled triggers.

### Merkle tree

The Merkle tree is built over the entries of a finalized block.

```sql
SELECT pgsigchain.build_merkle('ledger');
-- b76cffe87fa05aadc84f3e8e921ec8cdde0100c88728f9dba095d3d2f85aa443

SELECT pgsigchain.merkle_root('ledger');

-- Proof for a row (needs the encoded row_pk)
SELECT pgsigchain.merkle_proof('ledger', pgsigchain.encode_pk('1'));
-- {R:eb8e4572...,R:eb0a852f...}
```

The proof returns hashes prefixed by direction (`L` / `R`). With proof + row_hash you can recompute the root.

### Blocks

Entries from `chain_log` are sealed into immutable blocks. Each block has its own Merkle tree and `prev_block_hash`, forming a second-level chain.

```sql
-- Manually finalize: groups pending entries into a new block
SELECT pgsigchain.finalize_block('ledger');
-- 1   (block_number)

-- List all blocks
SELECT * FROM pgsigchain.block_info('ledger');
```

| block_number | block_hash | prev_block_hash | entries_count | merkle_root | created_at |
|---|---|---|---|---|---|
| 1 | a1b2... | 0 | 3 | b76c... | 2026-04-26 ... |

```sql
-- Verify each block_hash matches merkle_root + prev_block_hash
SELECT pgsigchain.verify_blocks('ledger');
```

For automatic finalization, pass `auto_finalize` to `protect`:

```sql
SELECT pgsigchain.protect('ledger', 'immutable', 100);
-- finalizes a block every 100 entries
```

### Digital signatures (Ed25519)

The private key is **never stored in the database**. The flow is operator-driven: the app generates the keypair, registers only the public key, and injects the private key only at signing time.

```sql
-- 1. Generate keypair (ideally on the client side)
SELECT * FROM pgsigchain.generate_keypair();
--  public_key                     | private_key
-- --------------------------------+---------------------------------
--  MCowBQYDK2VwAyEA...             | MC4CAQAwBQYDK2VwBCIEI...

-- 2. Register ONLY the public key for the table
SELECT pgsigchain.set_signing_key('ledger', 'MCowBQYDK2VwAyEA...');

SELECT pgsigchain.get_public_key('ledger');

-- 3. Sign a chain_log entry (the private key lives only inside the call)
SELECT pgsigchain.sign_chain_entry('ledger', 1, 'MC4CAQAwBQYDK2VwBCIEI...');

-- 4. Verify
SELECT pgsigchain.verify_signature('ledger', 1);
-- true
```

The chain trigger **does not sign automatically**. Signing is always an explicit operator action. The signature covers the entry's `chain_hash` and is stored in the `signature` column of `chain_log`.

### Status

```sql
SELECT * FROM pgsigchain.status();
```

| schema_name | table_name | mode | protected_at | chain_length | block_count |
|---|---|---|---|---|---|
| public | ledger | immutable | 2026-04-26 ... | 3 | 1 |

### Who did it (actor capture)

Each `chain_log` entry automatically records who performed the operation:

| Column | Source |
|---|---|
| `actor_user` | `current_user` |
| `actor_app`  | `current_setting('application_name')` |
| `actor_addr` | `inet_client_addr()` (NULL for local connections) |
| `actor_pid`  | `pg_backend_pid()` |

All four fields go into the `row_hash`, so changing an actor column afterwards (via direct UPDATE on `pgsigchain.chain_log`) is detectable by `verify_data`.

### Manifest for set-level anchoring

`pgsigchain.export_manifest()` returns a JSONB with the complete list of protected tables and their current chain heads. Useful for externally anchoring the **set** (not just individual blocks), which protects against meta-tampering on `pgsigchain.protected_tables`:

```sql
SELECT pgsigchain.export_manifest();
```

```json
{
  "generated_at": "2026-04-26T...",
  "extension_version": "0.3.0",
  "tables": [
    {
      "schema": "public", "name": "ledger", "mode": "immutable",
      "protected_at": "...", "chain_length": 3,
      "last_chain_hash": "...", "block_count": 1,
      "last_block_hash": "...", "public_key": null
    }
  ]
}
```

### Unprotect

```sql
-- Refuses by default if there is audit data
SELECT pgsigchain.unprotect('ledger');
-- ERROR: pgsigchain: refusing to delete audit data; pass force => true

-- Force cleanup of chain_log + blocks + merkle_nodes + signing_keys
SELECT pgsigchain.unprotect('ledger', force => true);
```

## Use cases

Real-world operational questions and the SQL flow to answer them — see [`CASES.md`](CASES.md).

## API reference

| Function | Returns | Description |
|---|---|---|
| `pgsigchain.protect(table_name, mode, auto_finalize)` | void | Protect a table. `mode`: `immutable`/`audit`. `auto_finalize`: N entries per block. |
| `pgsigchain.unprotect(table_name, force)` | void | Remove protection. Refuses to delete audit data without `force => true`. |
| `pgsigchain.sha256(data bytea)` | text | SHA-256 of arbitrary data |
| `pgsigchain.encode_pk(VARIADIC parts text[])` | text | Length-prefixed canonical encoding of the PK (hex) |
| `pgsigchain.verify_chain(table_name)` | boolean | Validates the entire hash chain |
| `pgsigchain.verify_row(table_name, row_pk)` | boolean | Validates one row from chain_log (use `encode_pk` on the PK) |
| `pgsigchain.verify_data(table_name)` | boolean | Compares the table's current state vs the last recorded hash |
| `pgsigchain.find_tampered_rows(table_name)` | setof record | Lists altered rows + expected/actual hash + original actor |
| `pgsigchain.build_merkle(table_name)` | text | Builds the Merkle tree, returns root |
| `pgsigchain.merkle_root(table_name)` | text | Returns stored root hash |
| `pgsigchain.merkle_proof(table_name, row_pk)` | text[] | Merkle proof for the row (use `encode_pk`) |
| `pgsigchain.finalize_block(table_name)` | bigint | Seals pending entries into a new block; returns block_number |
| `pgsigchain.block_info(table_name)` | setof record | Lists blocks (number, hash, prev_hash, entries, merkle_root, created_at) |
| `pgsigchain.verify_blocks(table_name)` | boolean | Verifies the integrity of the block chain |
| `pgsigchain.generate_keypair()` | (text, text) | Generates Ed25519 pair `(public_key, private_key)` |
| `pgsigchain.set_signing_key(table_name, public_key)` | void | Registers the table's public key |
| `pgsigchain.get_public_key(table_name)` | text | Returns the registered public key |
| `pgsigchain.sign_chain_entry(table_name, chain_log_id, private_key)` | void | Signs an entry (private key is not persisted) |
| `pgsigchain.verify_signature(table_name, chain_log_id)` | boolean | Verifies the signature of an entry |
| `pgsigchain.status()` | setof record | Lists protected tables with chain_length and block_count |
| `pgsigchain.export_manifest()` | jsonb | Portable snapshot of the protected set (for external anchoring) |
| `pgsigchain.audit_check(table_name)` | setof record | Runs verify_chain + verify_data + verify_blocks + verify_anchor |
| `pgsigchain.check_all()` | setof record | `audit_check` over every protected table |
| `pgsigchain.check_all_and_notify(channel)` | boolean | Runs check_all; if anything fails, fires `pg_notify(channel, json)` and returns false |
| `pgsigchain.export_block(table_name, block_number)` | jsonb | Exports a block as JSON for external anchoring |
| `pgsigchain.record_anchor(table, block_number, type, ref, notes)` | bigint | Records a pointer to off-DB evidence |
| `pgsigchain.verify_anchor(anchor_id)` | boolean | Confirms the block still matches the anchor |
| `pgsigchain.anchor_status(table_name)` | setof record | Per block: anchor_count, all_valid, last_anchored |

## Internal tables

All in the `pgsigchain` schema. Marked with `pg_extension_config_dump`, so `pg_dump` preserves the contents.

- **`pgsigchain.protected_tables`** — table registry (oid, schema, name, mode, auto_finalize_threshold)
- **`pgsigchain.chain_log`** — chained log (row_pk, row_hash, prev_hash, chain_hash, operation, new_row_hash, block_id, signature, actor_user, actor_app, actor_addr, actor_pid)
- **`pgsigchain.blocks`** — finalized blocks (block_number, prev_block_hash, block_hash, entries_count, merkle_root)
- **`pgsigchain.merkle_nodes`** — Merkle tree nodes per block (level, position, hash, left_child, right_child, block_id)
- **`pgsigchain.signing_keys`** — public key per table (Ed25519). Private keys are never stored.
- **`pgsigchain.anchors`** — external anchoring records (block_id, anchor_type, anchor_ref, block_hash_at_anchor, notes)

`TRUNCATE` on a protected table is blocked in both modes — without that, it would be a silent bypass (deleting all rows without touching `chain_log`).

## How it works

```
INSERT/UPDATE/DELETE row
    |
    v
[chain_trigger | audit_trigger]
    |
    +---> row_pk = encode_pk(pk1, pk2, ...)         (length-prefixed, hex)
    +---> row_hash = SHA-256(canonical(col1,...,colN))  (length-prefixed)
    +---> prev_hash = chain_hash of the last entry (or "0")
    +---> chain_hash = SHA-256(prev_hash || row_hash)
    +---> INSERT INTO pgsigchain.chain_log
    +---> if auto_finalize threshold reached -> finalize_block()


UPDATE/DELETE in immutable mode
    |
    v
[immutable_trigger]  ->  ERROR: not allowed


finalize_block
    |
    v
pending entries -> Merkle tree -> merkle_root
    |
    +---> block_hash = SHA-256(prev_block_hash || merkle_root || entries_count)
    +---> INSERT INTO pgsigchain.blocks
    +---> chain_log.block_id = new block
```

The length-prefixed canonical encoding (`len(c1)||c1||len(c2)||c2||...`) eliminates ambiguities of plain concatenation (e.g., `"ab"+"c"` vs `"a"+"bc"`), preventing hash collisions between distinct rows.

## Project layout

```
pgsigchain/
├── Makefile              # PGXS build
├── pgsigchain.control    # Extension metadata
├── Dockerfile            # Container build
├── docker-compose.yml
├── sql/
│   └── pgsigchain--0.3.0.sql   # Schema and function declarations
├── src/
│   ├── pgsigchain.c      # Entry point
│   ├── hash.c            # SHA-256 (OpenSSL EVP)
│   ├── chain.c           # Chain trigger (immutable + audit)
│   ├── immutable.c       # Blocks UPDATE/DELETE
│   ├── merkle.c          # Merkle tree
│   ├── blocks.c          # finalize_block, block_info, verify_blocks
│   ├── sign.c            # Ed25519 keypair, sign, verify
│   ├── protect.c         # protect/unprotect, encode_pk
│   └── verify.c          # verify_chain/row/data + status
├── src/include/          # Headers
└── test/                 # Regression tests
```

## License

PostgreSQL License — see [`LICENSE`](LICENSE).
