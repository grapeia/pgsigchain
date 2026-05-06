-- pgsigchain: Tamper-evident append-only audit log for PostgreSQL — signed hash chain
-- Version 0.3.0

\echo Use "CREATE EXTENSION pgsigchain" to load this extension. \quit

-- ============================================================================
-- Internal tables
-- ============================================================================

CREATE TABLE pgsigchain.protected_tables (
    table_oid               OID PRIMARY KEY,
    schema_name             TEXT NOT NULL,
    table_name              TEXT NOT NULL,
    mode                    TEXT NOT NULL DEFAULT 'immutable',
    auto_finalize_threshold INT,
    protected_at            TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE pgsigchain.blocks (
    id              BIGSERIAL PRIMARY KEY,
    table_oid       OID NOT NULL,
    block_number    BIGINT NOT NULL,
    prev_block_hash TEXT NOT NULL,
    block_hash      TEXT NOT NULL,
    entries_count   INT NOT NULL,
    merkle_root     TEXT NOT NULL,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE UNIQUE INDEX ON pgsigchain.blocks (table_oid, block_number);

CREATE TABLE pgsigchain.chain_log (
    id              BIGSERIAL PRIMARY KEY,
    table_oid       OID NOT NULL,
    row_pk          TEXT NOT NULL,
    row_hash        TEXT NOT NULL,
    prev_hash       TEXT NOT NULL,
    chain_hash      TEXT NOT NULL,
    operation       TEXT NOT NULL DEFAULT 'INSERT',
    new_row_hash    TEXT,
    block_id        BIGINT REFERENCES pgsigchain.blocks(id) ON DELETE CASCADE,
    signature       TEXT,
    actor_user      TEXT,
    actor_app       TEXT,
    actor_addr      TEXT,
    actor_pid       INT,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX ON pgsigchain.chain_log (table_oid, id);
CREATE INDEX ON pgsigchain.chain_log (table_oid, row_pk);

CREATE TABLE pgsigchain.merkle_nodes (
    id           BIGSERIAL PRIMARY KEY,
    table_oid    OID NOT NULL,
    level        INT NOT NULL,
    position     INT NOT NULL,
    hash         TEXT NOT NULL,
    left_child   BIGINT REFERENCES pgsigchain.merkle_nodes(id),
    right_child  BIGINT REFERENCES pgsigchain.merkle_nodes(id),
    block_id     BIGINT NOT NULL,
    created_at   TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX ON pgsigchain.merkle_nodes (table_oid, block_id, level);

CREATE TABLE pgsigchain.signing_keys (
    id              BIGSERIAL PRIMARY KEY,
    table_oid       OID NOT NULL UNIQUE,
    public_key      TEXT NOT NULL,
    key_algorithm   TEXT NOT NULL DEFAULT 'Ed25519',
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- External anchoring: operator-recorded references to off-DB immutable storage
CREATE TABLE pgsigchain.anchors (
    id                   BIGSERIAL PRIMARY KEY,
    table_oid            OID NOT NULL,
    block_id             BIGINT NOT NULL REFERENCES pgsigchain.blocks(id) ON DELETE CASCADE,
    anchor_type          TEXT NOT NULL,
    anchor_ref           TEXT NOT NULL,
    block_hash_at_anchor TEXT NOT NULL,
    notes                TEXT,
    created_at           TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX ON pgsigchain.anchors (table_oid, block_id);
CREATE INDEX ON pgsigchain.anchors (block_id);

-- ============================================================================
-- C functions — hashing
-- ============================================================================

CREATE FUNCTION pgsigchain.sha256(data BYTEA)
RETURNS TEXT
AS '$libdir/pgsigchain', 'pgsigchain_sha256'
LANGUAGE C IMMUTABLE STRICT;

-- ============================================================================
-- C functions — triggers (internal)
-- ============================================================================

CREATE FUNCTION pgsigchain.chain_trigger()
RETURNS TRIGGER
AS '$libdir/pgsigchain', 'pgsigchain_chain_trigger'
LANGUAGE C;

CREATE FUNCTION pgsigchain.immutable_trigger()
RETURNS TRIGGER
AS '$libdir/pgsigchain', 'pgsigchain_immutable_trigger'
LANGUAGE C;

CREATE FUNCTION pgsigchain.audit_trigger()
RETURNS TRIGGER
AS '$libdir/pgsigchain', 'pgsigchain_audit_trigger'
LANGUAGE C;

CREATE FUNCTION pgsigchain.truncate_trigger()
RETURNS TRIGGER
AS '$libdir/pgsigchain', 'pgsigchain_truncate_trigger'
LANGUAGE C;

-- ============================================================================
-- C functions — protect / unprotect
-- ============================================================================

CREATE FUNCTION pgsigchain.protect(
    table_name TEXT,
    mode TEXT DEFAULT 'immutable',
    auto_finalize INT DEFAULT NULL
)
RETURNS VOID
AS '$libdir/pgsigchain', 'pgsigchain_protect'
LANGUAGE C VOLATILE;

CREATE FUNCTION pgsigchain.unprotect(table_name TEXT, force BOOLEAN DEFAULT false)
RETURNS VOID
AS '$libdir/pgsigchain', 'pgsigchain_unprotect'
LANGUAGE C VOLATILE;

-- ============================================================================
-- C functions — verification
-- ============================================================================

CREATE FUNCTION pgsigchain.verify_chain(table_name TEXT)
RETURNS BOOLEAN
AS '$libdir/pgsigchain', 'pgsigchain_verify_chain'
LANGUAGE C VOLATILE STRICT;

CREATE FUNCTION pgsigchain.verify_row(table_name TEXT, row_pk TEXT)
RETURNS BOOLEAN
AS '$libdir/pgsigchain', 'pgsigchain_verify_row'
LANGUAGE C VOLATILE STRICT;

-- ============================================================================
-- C functions — Merkle tree
-- ============================================================================

CREATE FUNCTION pgsigchain.build_merkle(table_name TEXT)
RETURNS TEXT
AS '$libdir/pgsigchain', 'pgsigchain_build_merkle'
LANGUAGE C VOLATILE STRICT;

CREATE FUNCTION pgsigchain.merkle_root(table_name TEXT)
RETURNS TEXT
AS '$libdir/pgsigchain', 'pgsigchain_merkle_root'
LANGUAGE C VOLATILE STRICT;

CREATE FUNCTION pgsigchain.merkle_proof(table_name TEXT, row_pk TEXT)
RETURNS TEXT[]
AS '$libdir/pgsigchain', 'pgsigchain_merkle_proof'
LANGUAGE C VOLATILE STRICT;

-- ============================================================================
-- C functions — blocks
-- ============================================================================

CREATE FUNCTION pgsigchain.finalize_block(table_name TEXT)
RETURNS BIGINT
AS '$libdir/pgsigchain', 'pgsigchain_finalize_block'
LANGUAGE C VOLATILE STRICT;

CREATE FUNCTION pgsigchain.block_info(
    table_name TEXT,
    OUT block_number BIGINT,
    OUT block_hash TEXT,
    OUT prev_block_hash TEXT,
    OUT entries_count INT,
    OUT merkle_root TEXT,
    OUT created_at TIMESTAMPTZ
)
RETURNS SETOF RECORD
AS '$libdir/pgsigchain', 'pgsigchain_block_info'
LANGUAGE C VOLATILE STRICT;

CREATE FUNCTION pgsigchain.verify_blocks(table_name TEXT)
RETURNS BOOLEAN
AS '$libdir/pgsigchain', 'pgsigchain_verify_blocks'
LANGUAGE C VOLATILE STRICT;

-- ============================================================================
-- C functions — digital signatures (Ed25519)
-- ============================================================================

CREATE FUNCTION pgsigchain.generate_keypair(
    OUT public_key TEXT,
    OUT private_key TEXT
)
RETURNS RECORD
AS '$libdir/pgsigchain', 'pgsigchain_generate_keypair'
LANGUAGE C VOLATILE;

CREATE FUNCTION pgsigchain.set_signing_key(table_name TEXT, public_key TEXT)
RETURNS VOID
AS '$libdir/pgsigchain', 'pgsigchain_set_signing_key'
LANGUAGE C VOLATILE STRICT;

CREATE FUNCTION pgsigchain.sign_chain_entry(
    table_name TEXT,
    chain_log_id BIGINT,
    private_key TEXT
) RETURNS VOID
AS '$libdir/pgsigchain', 'pgsigchain_sign_chain_entry'
LANGUAGE C VOLATILE STRICT;

CREATE FUNCTION pgsigchain.get_public_key(table_name TEXT)
RETURNS TEXT
AS '$libdir/pgsigchain', 'pgsigchain_get_public_key'
LANGUAGE C VOLATILE STRICT;

CREATE FUNCTION pgsigchain.verify_signature(table_name TEXT, chain_log_id BIGINT)
RETURNS BOOLEAN
AS '$libdir/pgsigchain', 'pgsigchain_verify_signature'
LANGUAGE C VOLATILE STRICT;

CREATE FUNCTION pgsigchain.verify_data(table_name TEXT) RETURNS BOOLEAN
AS '$libdir/pgsigchain', 'pgsigchain_verify_data'
LANGUAGE C VOLATILE STRICT;

CREATE FUNCTION pgsigchain.find_tampered_rows(
    table_name        TEXT,
    OUT row_pk        TEXT,
    OUT chain_log_id  BIGINT,
    OUT expected_hash TEXT,
    OUT actual_hash   TEXT,
    OUT recorded_actor TEXT,
    OUT recorded_at   TIMESTAMPTZ
)
RETURNS SETOF RECORD
AS '$libdir/pgsigchain', 'pgsigchain_find_tampered_rows'
LANGUAGE C VOLATILE STRICT;

CREATE FUNCTION pgsigchain.encode_pk(VARIADIC parts TEXT[]) RETURNS TEXT
AS '$libdir/pgsigchain', 'pgsigchain_encode_pk'
LANGUAGE C IMMUTABLE;

-- ============================================================================
-- C functions — status
-- ============================================================================

CREATE FUNCTION pgsigchain.status(
    OUT schema_name TEXT,
    OUT table_name TEXT,
    OUT mode TEXT,
    OUT protected_at TIMESTAMPTZ,
    OUT chain_length BIGINT,
    OUT block_count BIGINT
)
RETURNS SETOF RECORD
AS '$libdir/pgsigchain', 'pgsigchain_status'
LANGUAGE C VOLATILE;

-- ============================================================================
-- C functions — external anchoring
-- ============================================================================

CREATE FUNCTION pgsigchain.export_block(table_name TEXT, block_number BIGINT)
RETURNS JSONB
AS '$libdir/pgsigchain', 'pgsigchain_export_block'
LANGUAGE C VOLATILE STRICT;

CREATE FUNCTION pgsigchain.record_anchor(
    table_name   TEXT,
    block_number BIGINT,
    anchor_type  TEXT,
    anchor_ref   TEXT,
    notes        TEXT DEFAULT NULL
) RETURNS BIGINT
AS '$libdir/pgsigchain', 'pgsigchain_record_anchor'
LANGUAGE C VOLATILE;

CREATE FUNCTION pgsigchain.verify_anchor(anchor_id BIGINT)
RETURNS BOOLEAN
AS '$libdir/pgsigchain', 'pgsigchain_verify_anchor'
LANGUAGE C VOLATILE STRICT;

CREATE FUNCTION pgsigchain.anchor_status(
    table_name        TEXT,
    OUT block_number  BIGINT,
    OUT block_hash    TEXT,
    OUT anchor_count  BIGINT,
    OUT all_valid     BOOLEAN,
    OUT last_anchored TIMESTAMPTZ
) RETURNS SETOF RECORD
AS '$libdir/pgsigchain', 'pgsigchain_anchor_status'
LANGUAGE C VOLATILE STRICT;

-- ============================================================================
-- Convenience: run all verification checks and return a structured report
-- ============================================================================

CREATE FUNCTION pgsigchain.audit_check(table_name TEXT)
RETURNS TABLE(check_name TEXT, passed BOOLEAN, details TEXT)
LANGUAGE plpgsql STABLE AS $$
DECLARE
    relid       OID := table_name::regclass;
    block_count BIGINT;
    anchor_total BIGINT;
    anchor_invalid BIGINT;
BEGIN
    -- Hash chain consistency
    RETURN QUERY SELECT 'verify_chain'::TEXT, pgsigchain.verify_chain(table_name), NULL::TEXT;

    -- Live row data still matches stored hashes
    RETURN QUERY SELECT 'verify_data'::TEXT, pgsigchain.verify_data(table_name), NULL::TEXT;

    -- Block hashes (only meaningful if blocks have been finalized)
    SELECT COUNT(*) INTO block_count FROM pgsigchain.blocks WHERE table_oid = relid;
    IF block_count > 0 THEN
        RETURN QUERY SELECT 'verify_blocks'::TEXT,
                            pgsigchain.verify_blocks(table_name),
                            block_count::TEXT || ' block(s)';
    ELSE
        RETURN QUERY SELECT 'verify_blocks'::TEXT, true,
                            'no blocks finalized'::TEXT;
    END IF;

    -- External anchors
    SELECT COUNT(*),
           COUNT(*) FILTER (WHERE NOT pgsigchain.verify_anchor(id))
      INTO anchor_total, anchor_invalid
      FROM pgsigchain.anchors WHERE table_oid = relid;
    IF anchor_total = 0 THEN
        RETURN QUERY SELECT 'verify_anchors'::TEXT, true,
                            'no anchors recorded'::TEXT;
    ELSE
        RETURN QUERY SELECT 'verify_anchors'::TEXT,
                            anchor_invalid = 0,
                            anchor_total::TEXT || ' anchor(s), '
                              || anchor_invalid::TEXT || ' invalid';
    END IF;
END;
$$;

-- ============================================================================
-- Monitoring: aggregate audit_check across every protected table
-- ============================================================================

CREATE FUNCTION pgsigchain.check_all()
RETURNS TABLE(table_name TEXT, check_name TEXT, passed BOOLEAN, details TEXT)
LANGUAGE plpgsql STABLE AS $$
DECLARE
    pt RECORD;
    qualified_name TEXT;
BEGIN
    FOR pt IN SELECT p.schema_name AS schema_name, p.table_name AS tname
                FROM pgsigchain.protected_tables p
               ORDER BY p.schema_name, p.table_name
    LOOP
        qualified_name := quote_ident(pt.schema_name) || '.' || quote_ident(pt.tname);
        table_name  := pt.schema_name || '.' || pt.tname;
        FOR check_name, passed, details IN
            SELECT c.check_name, c.passed, c.details
              FROM pgsigchain.audit_check(qualified_name) c
        LOOP
            RETURN NEXT;
        END LOOP;
    END LOOP;
END;
$$;

-- Run every check, send a NOTIFY on the given channel when any fails.
-- Returns true when everything passed, false otherwise.
-- Payload is a JSON object: {"failures": [{"table": ..., "check": ..., "details": ...}, ...]}
CREATE FUNCTION pgsigchain.check_all_and_notify(channel TEXT DEFAULT 'pgsigchain_alert')
RETURNS BOOLEAN LANGUAGE plpgsql AS $$
DECLARE
    failures JSONB;
    payload  TEXT;
BEGIN
    SELECT jsonb_agg(jsonb_build_object(
        'table',   table_name,
        'check',   check_name,
        'details', details
    )) INTO failures
      FROM pgsigchain.check_all()
     WHERE NOT passed;

    IF failures IS NULL THEN
        RETURN true;
    END IF;

    payload := jsonb_build_object(
        'detected_at', now(),
        'failures',    failures
    )::TEXT;

    -- pg_notify truncates payloads above 8000 bytes; trim defensively.
    PERFORM pg_notify(channel, left(payload, 7900));
    RETURN false;
END;
$$;

-- ============================================================================
-- Manifest: portable summary of every protected table for external commitment
-- ============================================================================

CREATE FUNCTION pgsigchain.export_manifest()
RETURNS JSONB
LANGUAGE SQL STABLE AS $$
    SELECT jsonb_build_object(
        'generated_at', now(),
        'extension_version', '0.3.0',
        'tables', COALESCE((
            SELECT jsonb_agg(jsonb_build_object(
                'schema',          pt.schema_name,
                'name',            pt.table_name,
                'mode',            pt.mode,
                'protected_at',    pt.protected_at,
                'chain_length',    (SELECT COUNT(*) FROM pgsigchain.chain_log
                                     WHERE table_oid = pt.table_oid),
                'last_chain_hash', (SELECT chain_hash FROM pgsigchain.chain_log
                                     WHERE table_oid = pt.table_oid
                                     ORDER BY id DESC LIMIT 1),
                'block_count',     (SELECT COUNT(*) FROM pgsigchain.blocks
                                     WHERE table_oid = pt.table_oid),
                'last_block_hash', (SELECT block_hash FROM pgsigchain.blocks
                                     WHERE table_oid = pt.table_oid
                                     ORDER BY block_number DESC LIMIT 1),
                'public_key',      (SELECT public_key FROM pgsigchain.signing_keys
                                     WHERE table_oid = pt.table_oid)
            ) ORDER BY pt.schema_name, pt.table_name)
            FROM pgsigchain.protected_tables pt
        ), '[]'::jsonb)
    );
$$;

-- ============================================================================
-- Mark internal tables as user data so pg_dump preserves their contents
-- ============================================================================

SELECT pg_catalog.pg_extension_config_dump('pgsigchain.protected_tables', '');
SELECT pg_catalog.pg_extension_config_dump('pgsigchain.chain_log', '');
SELECT pg_catalog.pg_extension_config_dump('pgsigchain.blocks', '');
SELECT pg_catalog.pg_extension_config_dump('pgsigchain.merkle_nodes', '');
SELECT pg_catalog.pg_extension_config_dump('pgsigchain.signing_keys', '');
SELECT pg_catalog.pg_extension_config_dump('pgsigchain.anchors', '');

-- Also dump the sequences backing the BIGSERIAL columns so IDs survive dump/restore
SELECT pg_catalog.pg_extension_config_dump('pgsigchain.blocks_id_seq', '');
SELECT pg_catalog.pg_extension_config_dump('pgsigchain.chain_log_id_seq', '');
SELECT pg_catalog.pg_extension_config_dump('pgsigchain.merkle_nodes_id_seq', '');
SELECT pg_catalog.pg_extension_config_dump('pgsigchain.signing_keys_id_seq', '');
SELECT pg_catalog.pg_extension_config_dump('pgsigchain.anchors_id_seq', '');
