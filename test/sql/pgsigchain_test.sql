-- pgsigchain extension regression tests

CREATE EXTENSION pgsigchain;

-- ============================================================================
-- Section A: Basics — sha256, protect, immutable mode
-- ============================================================================

-- SHA-256 deterministic
SELECT pgsigchain.sha256('hello'::bytea);
SELECT pgsigchain.sha256(''::bytea);
SELECT pgsigchain.sha256('hello'::bytea) = pgsigchain.sha256('hello'::bytea) AS deterministic;

-- Protect a simple table with SERIAL PK in immutable mode
CREATE TABLE test_ledger (
    id SERIAL PRIMARY KEY,
    amount INT NOT NULL,
    description TEXT
);

SELECT pgsigchain.protect('test_ledger');

-- Should show the table as protected
SELECT schema_name, table_name FROM pgsigchain.status();

-- INSERT creates chain_log entries
INSERT INTO test_ledger (amount, description) VALUES (100, 'deposit');
INSERT INTO test_ledger (amount, description) VALUES (-50, 'withdrawal');
INSERT INTO test_ledger (amount, description) VALUES (200, 'bonus');

SELECT COUNT(*) AS chain_entries FROM pgsigchain.chain_log;

-- First entry has prev_hash = '0'
SELECT prev_hash FROM pgsigchain.chain_log ORDER BY id LIMIT 1;

-- Verify chain integrity
SELECT pgsigchain.verify_chain('test_ledger');

-- Immutability — UPDATE should fail
\set ON_ERROR_ROLLBACK on
\set ON_ERROR_STOP off

UPDATE test_ledger SET amount = 999 WHERE id = 1;

\set ON_ERROR_STOP on
\set ON_ERROR_ROLLBACK off

-- Immutability — DELETE should fail
\set ON_ERROR_ROLLBACK on
\set ON_ERROR_STOP off

DELETE FROM test_ledger WHERE id = 1;

\set ON_ERROR_STOP on
\set ON_ERROR_ROLLBACK off

-- ============================================================================
-- Section B: verify_data on the live table
-- ============================================================================
SELECT pgsigchain.verify_data('test_ledger');

-- ============================================================================
-- Section C: Merkle tree (uses encode_pk for proof lookup)
-- ============================================================================
SELECT pgsigchain.build_merkle('test_ledger') IS NOT NULL AS merkle_built;
SELECT pgsigchain.merkle_root('test_ledger') IS NOT NULL AS has_root;
SELECT array_length(pgsigchain.merkle_proof('test_ledger', pgsigchain.encode_pk('1')), 1) > 0 AS has_proof;

-- ============================================================================
-- Section D: verify_row with new PK encoding
-- ============================================================================
SELECT pgsigchain.verify_row('test_ledger', pgsigchain.encode_pk('1'));

-- ============================================================================
-- Section E: Composite PK with comma in column value
-- ============================================================================
CREATE TABLE composite_t (
    a TEXT,
    b TEXT,
    payload TEXT,
    PRIMARY KEY (a, b)
);

SELECT pgsigchain.protect('composite_t');

-- Row whose `a` contains a comma — would have collided under old encoding
INSERT INTO composite_t (a, b, payload) VALUES ('foo,bar', 'baz', 'first');

SELECT pgsigchain.verify_row('composite_t', pgsigchain.encode_pk('foo,bar', 'baz'));

-- Distinct row whose `b` contains the comma instead
INSERT INTO composite_t (a, b, payload) VALUES ('foo', 'bar,baz', 'second');

SELECT pgsigchain.verify_row('composite_t', pgsigchain.encode_pk('foo', 'bar,baz'));

-- The two row_pk values should be distinct in chain_log
SELECT COUNT(DISTINCT row_pk) AS distinct_row_pks
  FROM pgsigchain.chain_log
 WHERE row_pk IN (pgsigchain.encode_pk('foo,bar', 'baz'), pgsigchain.encode_pk('foo', 'bar,baz'));

-- ============================================================================
-- Section F: unprotect refusal when chain_log is non-empty
-- ============================================================================
\set ON_ERROR_ROLLBACK on
\set ON_ERROR_STOP off

SELECT pgsigchain.unprotect('test_ledger');

\set ON_ERROR_STOP on
\set ON_ERROR_ROLLBACK off

-- Force-unprotect succeeds
SELECT pgsigchain.unprotect('test_ledger', force => true);

-- After force-unprotect, no chain_log entries remain for that table
SELECT COUNT(*) AS remaining_entries
  FROM pgsigchain.chain_log
 WHERE table_oid = 'test_ledger'::regclass;

-- And UPDATE now works
UPDATE test_ledger SET amount = 999 WHERE id = 1;
SELECT amount FROM test_ledger WHERE id = 1;

-- ============================================================================
-- Section G: Audit mode — INSERT/UPDATE/DELETE all logged
-- ============================================================================
CREATE TABLE audit_t (
    id SERIAL PRIMARY KEY,
    note TEXT
);

SELECT pgsigchain.protect('audit_t', 'audit');

INSERT INTO audit_t (note) VALUES ('original');
UPDATE audit_t SET note = 'modified' WHERE id = 1;
DELETE FROM audit_t WHERE id = 1;

-- Three entries in operation order: INSERT, UPDATE, DELETE
SELECT operation
  FROM pgsigchain.chain_log
 WHERE table_oid = 'audit_t'::regclass
 ORDER BY id;

-- UPDATE entry has non-null new_row_hash
SELECT new_row_hash IS NOT NULL AS update_has_new_hash
  FROM pgsigchain.chain_log
 WHERE table_oid = 'audit_t'::regclass
   AND operation = 'UPDATE';

-- ============================================================================
-- Section H: Block finalize on the audit table
-- ============================================================================
SELECT pgsigchain.finalize_block('audit_t') IS NOT NULL AS finalized;

SELECT block_number, entries_count
  FROM pgsigchain.block_info('audit_t');

SELECT pgsigchain.verify_blocks('audit_t');

-- ============================================================================
-- Section I: Protect error cases
-- ============================================================================

-- Table without primary key fails to protect
CREATE TABLE no_pk_table (data TEXT);

\set ON_ERROR_ROLLBACK on
\set ON_ERROR_STOP off

SELECT pgsigchain.protect('no_pk_table');

\set ON_ERROR_STOP on
\set ON_ERROR_ROLLBACK off

-- Double-protect fails
\set ON_ERROR_ROLLBACK on
\set ON_ERROR_STOP off

SELECT pgsigchain.protect('audit_t');

\set ON_ERROR_STOP on
\set ON_ERROR_ROLLBACK off

-- ============================================================================
-- Section J: Digital signatures (operator-driven flow)
-- ============================================================================
CREATE TABLE sig_t (
    id SERIAL PRIMARY KEY,
    val INT
);

SELECT pgsigchain.protect('sig_t');

CREATE TEMP TABLE keypair AS
SELECT public_key, private_key FROM pgsigchain.generate_keypair();

SELECT pgsigchain.set_signing_key('sig_t', (SELECT public_key FROM keypair));

SELECT pgsigchain.get_public_key('sig_t') = (SELECT public_key FROM keypair) AS pubkey_matches;

INSERT INTO sig_t (val) VALUES (42);

SELECT signature IS NULL AS unsigned_initially
  FROM pgsigchain.chain_log
 WHERE table_oid = 'sig_t'::regclass
 ORDER BY id DESC LIMIT 1;

WITH target AS (
    SELECT id FROM pgsigchain.chain_log
     WHERE table_oid = 'sig_t'::regclass
     ORDER BY id DESC LIMIT 1
)
SELECT pgsigchain.sign_chain_entry('sig_t', (SELECT id FROM target), (SELECT private_key FROM keypair));

SELECT signature IS NOT NULL AS signed_now
  FROM pgsigchain.chain_log
 WHERE table_oid = 'sig_t'::regclass
 ORDER BY id DESC LIMIT 1;

SELECT pgsigchain.verify_signature('sig_t',
    (SELECT id FROM pgsigchain.chain_log
      WHERE table_oid = 'sig_t'::regclass
      ORDER BY id DESC LIMIT 1));

CREATE TEMP TABLE wrong_keypair AS
SELECT public_key, private_key FROM pgsigchain.generate_keypair();

INSERT INTO sig_t (val) VALUES (99);

\set ON_ERROR_ROLLBACK on
\set ON_ERROR_STOP off

SELECT pgsigchain.sign_chain_entry('sig_t',
    (SELECT id FROM pgsigchain.chain_log
      WHERE table_oid = 'sig_t'::regclass
      ORDER BY id DESC LIMIT 1),
    (SELECT private_key FROM wrong_keypair));

\set ON_ERROR_STOP on
\set ON_ERROR_ROLLBACK off

-- ============================================================================
-- Section K: Exotic column types
-- ============================================================================
CREATE TABLE exotic_t (
    id SERIAL PRIMARY KEY,
    payload JSONB,
    blob BYTEA,
    tags TEXT[],
    counts INT[]
);

SELECT pgsigchain.protect('exotic_t');

INSERT INTO exotic_t (payload, blob, tags, counts) VALUES
    ('{"a":1,"b":[2,3]}'::jsonb, '\xdeadbeef'::bytea, ARRAY['x','y,z',''], ARRAY[1,2,3]);

INSERT INTO exotic_t (payload, blob, tags, counts) VALUES
    ('{"nested":{"k":"v"}}'::jsonb, '\xcafebabe'::bytea, ARRAY['hello','world'], ARRAY[10,20]);

INSERT INTO exotic_t (payload, blob, tags, counts) VALUES
    (NULL, NULL, NULL, NULL);

SELECT pgsigchain.verify_chain('exotic_t');
SELECT pgsigchain.verify_data('exotic_t');
SELECT pgsigchain.verify_row('exotic_t', pgsigchain.encode_pk('1'));

-- ============================================================================
-- Section L: External anchoring
-- ============================================================================
CREATE TABLE anchor_t (
    id SERIAL PRIMARY KEY,
    msg TEXT
);

SELECT pgsigchain.protect('anchor_t');

INSERT INTO anchor_t (msg) VALUES ('one'), ('two'), ('three');

SELECT pgsigchain.finalize_block('anchor_t') > 0 AS block_finalized;

-- export_block produces a JSONB envelope with all the fields we need
SELECT
    (env->>'block_number')::bigint = 1                   AS block_number_ok,
    env ? 'block_hash'                                   AS has_block_hash,
    env ? 'merkle_root'                                  AS has_merkle_root,
    (env->>'entries_count')::int = 3                     AS entries_count_ok,
    jsonb_array_length(env->'entries') = 3               AS entries_array_ok
FROM (SELECT pgsigchain.export_block('anchor_t', 1) AS env) e;

-- record an anchor for block 1
SELECT pgsigchain.record_anchor(
    'anchor_t', 1,
    'manual',
    'paper-printout-2026-04-26',
    'kept in office safe'
) > 0 AS anchor_recorded;

-- a second anchor (different external system)
SELECT pgsigchain.record_anchor(
    'anchor_t', 1,
    's3-versionid',
    's3://bucket/anchor.json#v=abc123',
    NULL
) > 0 AS second_anchor_recorded;

-- both anchors verify against the live block
SELECT bool_and(pgsigchain.verify_anchor(id)) AS all_anchors_valid
FROM pgsigchain.anchors WHERE table_oid = 'anchor_t'::regclass;

-- anchor_status: 1 block, 2 anchors, all_valid true
SELECT block_number, anchor_count, all_valid
FROM pgsigchain.anchor_status('anchor_t');

-- Tamper detection: forge a chain of events that changes the block_hash and
-- check verify_anchor returns false. We simulate by directly UPDATEing
-- pgsigchain.blocks (which is allowed — anchors aren't supposed to trust the DB).
UPDATE pgsigchain.blocks SET block_hash = 'tampered_hash'
 WHERE table_oid = 'anchor_t'::regclass AND block_number = 1;

SELECT bool_or(pgsigchain.verify_anchor(id)) AS any_anchor_valid_after_tamper
FROM pgsigchain.anchors WHERE table_oid = 'anchor_t'::regclass;

SELECT all_valid AS all_valid_after_tamper
FROM pgsigchain.anchor_status('anchor_t');

-- ============================================================================
-- Section M: GENERATED ALWAYS AS columns are visible to the trigger
-- ============================================================================
CREATE TABLE gen_t (
    id SERIAL PRIMARY KEY,
    a INT NOT NULL,
    b INT NOT NULL,
    sum_ab INT GENERATED ALWAYS AS (a + b) STORED
);

SELECT pgsigchain.protect('gen_t');

INSERT INTO gen_t (a, b) VALUES (2, 3);
INSERT INTO gen_t (a, b) VALUES (10, 20);

-- Hashes from two distinct (a,b) pairs must differ — proves the trigger saw
-- the populated sum_ab column too (otherwise both would hash with sum=NULL
-- only via a+b, which still differs; but more importantly verify_data must pass)
SELECT COUNT(DISTINCT row_hash) AS distinct_hashes
  FROM pgsigchain.chain_log WHERE table_oid = 'gen_t'::regclass;

SELECT pgsigchain.verify_chain('gen_t');
SELECT pgsigchain.verify_data('gen_t');

-- ============================================================================
-- Section N: audit_check convenience wrapper
-- ============================================================================

-- anchor_t had its block_hash tampered in Section L; chain/data are intact,
-- but block and anchor checks must now fail.
SELECT check_name, passed
  FROM pgsigchain.audit_check('anchor_t')
 ORDER BY check_name;

-- composite_t was never tampered and has no blocks/anchors — all clean.
SELECT check_name, passed, details
  FROM pgsigchain.audit_check('composite_t')
 ORDER BY check_name;

-- ============================================================================
-- Section O: Actor capture (current_user, application_name, addr, pid)
-- ============================================================================
CREATE TABLE actor_t (
    id SERIAL PRIMARY KEY,
    note TEXT
);

SELECT pgsigchain.protect('actor_t');

INSERT INTO actor_t (note) VALUES ('first');
INSERT INTO actor_t (note) VALUES ('second');

-- Trigger captured current_user — should match the session's current_user
SELECT actor_user = current_user::text AS user_captured,
       actor_pid = pg_backend_pid() AS pid_captured
  FROM pgsigchain.chain_log
 WHERE table_oid = 'actor_t'::regclass
 ORDER BY id DESC LIMIT 1;

-- Both rows share the same actor (same session), so user/pid columns are uniform
SELECT COUNT(DISTINCT actor_user) = 1 AS one_user,
       COUNT(DISTINCT actor_pid) = 1  AS one_pid
  FROM pgsigchain.chain_log
 WHERE table_oid = 'actor_t'::regclass;

-- verify_data must succeed (it has to fetch the actor from chain_log and
-- include it when recomputing the row_hash)
SELECT pgsigchain.verify_data('actor_t');

-- Tampering with the actor column changes the recomputed hash → verify_data
-- must now fail. We bypass triggers by UPDATEing pgsigchain.chain_log directly.
UPDATE pgsigchain.chain_log
   SET actor_user = 'attacker'
 WHERE table_oid = 'actor_t'::regclass
   AND id = (SELECT MIN(id) FROM pgsigchain.chain_log
              WHERE table_oid = 'actor_t'::regclass);

SELECT pgsigchain.verify_data('actor_t') AS verify_after_actor_tamper;

-- ============================================================================
-- Section P: TRUNCATE blocked on protected tables (both modes)
-- ============================================================================
\set ON_ERROR_ROLLBACK on
\set ON_ERROR_STOP off

-- composite_t is in immutable mode
TRUNCATE composite_t;

-- audit_t is in audit mode — TRUNCATE should also be blocked
TRUNCATE audit_t;

\set ON_ERROR_STOP on
\set ON_ERROR_ROLLBACK off

-- ============================================================================
-- Section Q: export_manifest
-- ============================================================================

-- Manifest has top-level keys
SELECT m ? 'generated_at'    AS has_generated_at,
       m ? 'extension_version' AS has_version,
       m ? 'tables'          AS has_tables,
       jsonb_typeof(m->'tables') = 'array' AS tables_is_array
  FROM (SELECT pgsigchain.export_manifest() AS m) e;

-- Each protected table appears once with the expected keys
SELECT jsonb_array_length(m->'tables') AS table_count
  FROM (SELECT pgsigchain.export_manifest() AS m) e;

-- Spot-check: composite_t is in there with a chain_length > 0
SELECT (t->>'chain_length')::int > 0 AS composite_has_entries
  FROM jsonb_array_elements(pgsigchain.export_manifest()->'tables') t
 WHERE t->>'name' = 'composite_t';

-- ============================================================================
-- Section R: find_tampered_rows — forensic listing of mismatches
-- ============================================================================
CREATE TABLE forensic_t (
    id SERIAL PRIMARY KEY,
    val TEXT
);

SELECT pgsigchain.protect('forensic_t');

INSERT INTO forensic_t (val) VALUES ('alpha');
INSERT INTO forensic_t (val) VALUES ('beta');
INSERT INTO forensic_t (val) VALUES ('gamma');

-- Clean state: zero tampered rows
SELECT COUNT(*) AS clean_count FROM pgsigchain.find_tampered_rows('forensic_t');

-- Tamper one row by bypassing the trigger (simulate an attacker with SQL access)
ALTER TABLE forensic_t DISABLE TRIGGER pgsigchain_chain_trg;
ALTER TABLE forensic_t DISABLE TRIGGER pgsigchain_immutable_trg;
UPDATE forensic_t SET val = 'COMPROMISED' WHERE id = 2;
ALTER TABLE forensic_t ENABLE TRIGGER pgsigchain_immutable_trg;
ALTER TABLE forensic_t ENABLE TRIGGER pgsigchain_chain_trg;

-- find_tampered_rows must list exactly that row, with both hashes and the
-- ORIGINAL actor (the attacker bypassed the trigger so no new entry exists)
SELECT row_pk = pgsigchain.encode_pk('2')      AS pk_matches,
       chain_log_id IS NOT NULL          AS has_log_id,
       expected_hash <> actual_hash      AS hashes_differ,
       recorded_actor IS NOT NULL        AS has_actor
  FROM pgsigchain.find_tampered_rows('forensic_t');

SELECT COUNT(*) AS tampered_count FROM pgsigchain.find_tampered_rows('forensic_t');

-- verify_data agrees
SELECT pgsigchain.verify_data('forensic_t') AS verify_after_tamper;

-- ============================================================================
-- Section S: check_all + check_all_and_notify (monitoring helpers)
-- ============================================================================

-- check_all returns rows for every (table, check) combination
SELECT COUNT(*) > 0  AS has_rows,
       COUNT(DISTINCT table_name) > 1 AS multiple_tables,
       COUNT(DISTINCT check_name) = 4 AS four_check_names
  FROM pgsigchain.check_all();

-- The forensic_t we tampered with earlier should have a verify_data failure
SELECT passed
  FROM pgsigchain.check_all()
 WHERE table_name = 'public.forensic_t'
   AND check_name = 'verify_data';

-- check_all_and_notify returns false when there are failures.
-- (We don't LISTEN here because psql prints the NOTIFY payload — which
--  contains a timestamp + PID — and that breaks deterministic regression.
--  In real use, a listener in another session would consume the payload.)
SELECT pgsigchain.check_all_and_notify('pgsigchain_test_chan') AS all_clean;

-- ============================================================================
-- Cleanup
-- ============================================================================
SELECT pgsigchain.unprotect('composite_t', force => true);
SELECT pgsigchain.unprotect('audit_t', force => true);
SELECT pgsigchain.unprotect('sig_t', force => true);
SELECT pgsigchain.unprotect('exotic_t', force => true);
SELECT pgsigchain.unprotect('anchor_t', force => true);
SELECT pgsigchain.unprotect('gen_t', force => true);
SELECT pgsigchain.unprotect('actor_t', force => true);
SELECT pgsigchain.unprotect('forensic_t', force => true);

DROP TABLE test_ledger;
DROP TABLE composite_t;
DROP TABLE audit_t;
DROP TABLE no_pk_table;
DROP TABLE sig_t;
DROP TABLE exotic_t;
DROP TABLE anchor_t;
DROP TABLE gen_t;
DROP TABLE actor_t;
DROP TABLE forensic_t;
DROP TABLE keypair;
DROP TABLE wrong_keypair;
DROP EXTENSION pgsigchain;
