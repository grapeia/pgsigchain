# pgsigchain — Use cases

> **English** · [Português](CASES.pt-BR.md)
>
> Back to [README](README.md).

Real-world operational questions and the SQL flow to answer them.

## "Was this record changed without going through the trigger?"

Suspicion: someone ran `ALTER TABLE ... DISABLE TRIGGER`, modified the row, and re-enabled the trigger.

```sql
SELECT pgsigchain.protect('accounts');
-- ... normal operation for days/months ...

SELECT pgsigchain.verify_data('accounts');
-- t = every row still matches the INSERT hash
-- f = some row was tampered with behind the trigger
```

`verify_data` reads each row from the live table, recomputes the hash with the same canonical encoding, and compares against the most recent `row_hash` in `chain_log`. It doesn't matter how the change came in — if it changed and the log wasn't updated, you get `f`.

## "Who recorded this entry?"

```sql
SELECT operation, created_at,
       actor_user, actor_app, actor_addr, actor_pid
  FROM pgsigchain.chain_log
 WHERE table_oid = 'accounts'::regclass
   AND row_pk = pgsigchain.encode_pk('1234')
 ORDER BY id;
```

Every INSERT/UPDATE/DELETE carries `current_user`, `application_name`, client IP, and backend pid automatically.

## "Did someone forge attribution (modify `actor_user` retroactively)?"

```sql
-- Attacker with direct SQL does:
UPDATE pgsigchain.chain_log SET actor_user = 'alice'
 WHERE id = 42;

-- You run:
SELECT pgsigchain.verify_data('accounts');
-- f
```

The four actor fields go into `row_hash`. Tampering with any of them after the fact breaks verification.

## "How do I prove to a third party that this record exists and never changed?"

```sql
-- 1. Seal a block
SELECT pgsigchain.finalize_block('accounts');  -- → block_number

-- 2. (once) register the public key so third parties know it
SELECT pgsigchain.set_signing_key('accounts', '<pubkey hex>');

-- 3. Sign the entry with the privkey (privkey lives only in the call)
SELECT pgsigchain.sign_chain_entry('accounts', <chain_log_id>, '<privkey hex>');

-- 4. Export the block and the Merkle proof of the record
SELECT pgsigchain.export_block('accounts', 1);
SELECT pgsigchain.merkle_proof('accounts', pgsigchain.encode_pk('1234'));

-- 5. Anchor the block to something immutable and store the ref
SELECT pgsigchain.record_anchor(
    'accounts', 1,
    'opentimestamps', 'https://ots.example/proof/abc',
    'commit of block 1'
);
```

The third party verifies three things: (a) the Merkle proof matches the block's `merkle_root`, (b) the block is signed by the known pubkey, (c) the external anchor points to the same `block_hash`.

## "I detected tampering — what now?"

`verify_data` tells you **whether** something changed. `find_tampered_rows` tells you **what**:

```sql
SELECT * FROM pgsigchain.find_tampered_rows('accounts');
--   row_pk    | chain_log_id | expected_hash | actual_hash | recorded_actor | recorded_at
-- -----------+--------------+---------------+-------------+----------------+-------------
--  04...0a   | 142          | 8f3a...        | bd11...      | alice          | 2026-04-12 ...
--  04...0c   |              |                | (no chain_log entry — orphan row) |  |
```

Each conflicting row becomes a line. You see:

- `row_pk` — which row was altered (canonical hex; decode against the live table by PK)
- `expected_hash` vs `actual_hash` — confirms it changed
- `recorded_actor` + `recorded_at` — who performed the last *legitimate* INSERT/UPDATE on the row (not who tampered — the illicit change didn't go through the trigger, so it has no actor of its own)
- `chain_log_id IS NULL` — orphan row (inserted bypassing the trigger, e.g., `DISABLE TRIGGER`)

Typical forensic flow:

```sql
-- 1. Locate
SELECT * FROM pgsigchain.find_tampered_rows('accounts');

-- 2. Compare against backup/replica to see what changed
--    (pgsigchain only stores the hash, not the original value — historical
--    content has to come from outside)

-- 3. Cross-reference against PG session audit
--    (pg_audit, log_statement=all, pg_stat_activity, etc.) to see
--    which session ran ALTER TRIGGER + UPDATE around the time in question.

-- 4. If tampering happened AFTER an external anchor, the invalidated
--    anchor proves the rewrite occurred after the commit:
SELECT * FROM pgsigchain.audit_check('accounts');
--   verify_data    | f       (rows altered)
--   verify_anchors | t/f     (if f, it happened after the anchor)
```

**What pgsigchain gives you:** *what changed* (rows and hashes), *since when the last valid state held* (via anchor or last `verify_data` from cron), *who made the previous legitimate version* (original actor).

**What pgsigchain does NOT give you:** *the previous content* (only the hash), *who did the tampering* (the illicit change didn't go through the trigger), *the exact moment of tampering* (only "between my last anchor and now"). For those three you need backups/replicas + Postgres audit log + periodic monitoring.

## "The whole chain was rewritten by a DBA — would I notice?"

Worst case: a superuser has full access and rebuilds `pgsigchain.chain_log` from scratch.

```sql
-- Beforehand (at a controlled checkpoint): anchor externally
SELECT pgsigchain.finalize_block('accounts');
SELECT pgsigchain.record_anchor(
    'accounts', 1,
    's3-versionid', 's3://audit/manifest.json#v=abc',
    NULL
);

-- Later, audit:
SELECT * FROM pgsigchain.audit_check('accounts');
--    check_name    | passed
-- -----------------+--------
--  verify_chain    | t       (rewritten chain is still internally consistent)
--  verify_data     | t       (data matches the rewritten chain)
--  verify_blocks   | f       (recomputed block_hash doesn't match the stored one)
--  verify_anchors  | f       (external anchor points to a different hash)
```

Without external anchors, silent rewrites are undetectable inside the DB. With anchors, any tampering with the block invalidates the anchor — and since the anchor lives outside the database, the attacker can't change it.

## "Did someone try to wipe everything with `TRUNCATE`?"

```sql
TRUNCATE accounts;
-- ERROR: pgsigchain: TRUNCATE not allowed on protected table "accounts"
```

A `BEFORE TRUNCATE` trigger aborts. Without it, TRUNCATE would slip past the per-row triggers and `verify_data` would misleadingly return `t` (zero rows = zero mismatches).

## "There's a system writing data — how do I monitor it in production?"

pgsigchain is **pull-based**: nothing notifies on its own. Someone — cron, app, internal scheduler — has to call `verify_*` periodically. The helpers for this are:

```sql
-- Run audit_check on ALL protected tables
SELECT * FROM pgsigchain.check_all();
--    table_name    |   check_name   | passed |       details
-- -----------------+----------------+--------+---------------------
--  public.accounts | verify_chain   | t      |
--  public.accounts | verify_data    | t      |
--  public.accounts | verify_blocks  | t      | 3 block(s)
--  public.accounts | verify_anchors | t      | 2 anchor(s), 0 invalid
--  public.events   | verify_chain   | t      |
--  ...

-- Same thing, but: returns false if anything failed and emits NOTIFY with JSON payload
SELECT pgsigchain.check_all_and_notify('pgsigchain_alert');
-- false  → the NOTIFY 'pgsigchain_alert' carries {"detected_at":"...","failures":[...]}
-- true   → all clean, no NOTIFY sent
```

Three common ways to wire this in production:

### 1. External cron + alerts (simplest)

`/etc/cron.d/pgsigchain-monitor`:

```cron
* * * * * postgres psql -tA -d app -c "SELECT NOT pgsigchain.check_all_and_notify();" \
    | grep -q t && curl -X POST -d "pgsigchain tampering detected" $SLACK_WEBHOOK_URL
```

Every minute runs `check_all_and_notify`. If it returns `t` (= a check failed), it fires a Slack/PagerDuty webhook. Simple, no extra dependencies.

### 2. pg_cron + LISTEN inside the app

Schedule inside Postgres (`pg_cron`):

```sql
SELECT cron.schedule('pgsigchain-monitor', '* * * * *',
    $$SELECT pgsigchain.check_all_and_notify('pgsigchain_alert')$$);
```

Node.js listener (any Postgres driver with pub/sub works):

```js
const client = new pg.Client(...);
await client.connect();
await client.query('LISTEN pgsigchain_alert');
client.on('notification', msg => {
    const payload = JSON.parse(msg.payload);
    alertOnCall(payload);  // PagerDuty, Sentry, etc.
});
```

Cron *inside* the database, alerts via the native channel, sub-second latency between detection and alert.

### 3. Sidecar / app-side (for ad-hoc checks)

If the application already has admin routes, expose an endpoint that calls `check_all`:

```python
@app.route('/admin/integrity')
def integrity():
    rows = db.execute("SELECT * FROM pgsigchain.check_all()").fetchall()
    failures = [r for r in rows if not r.passed]
    return {'ok': not failures, 'failures': failures}, 503 if failures else 200
```

Plug it into a Kubernetes/load balancer healthcheck, an internal dashboard, or an oncall runbook.

### When to run

There's no single rule — depends on volume and criticality. Common patterns:

- **Every minute** — financial systems / strict compliance. `verify_data` on a 100k-row table takes ~1s; on 10M rows it can exceed 10s. Combine `verify_chain` (fast, only reads the log) at high frequency with `verify_data` (expensive, scans the table) at lower frequency.
- **Hourly** — normal auditing. Sufficient to detect tampering before the next backup cycle.
- **At every deploy / schema change** — gate it in the pipeline: if `check_all` fails, block the deploy.
- **Before/after every external anchor** — guarantees that what you're anchoring is still intact.

### Cost of each check

| Check | Approximate cost | Run frequently? |
|---|---|---|
| `verify_chain` | O(N) sequential over the table's `chain_log`; fast (fits in seconds for millions of entries) | Yes, it's light |
| `verify_data` | O(M) scan of the live table + 1 lookup in `chain_log` per row | No — expensive on large tables |
| `verify_blocks` | O(B) rows in `pgsigchain.blocks`; very fast | Yes |
| `verify_anchor` | O(1) per anchor | Yes, trivial |

Common strategy: `verify_chain` + `verify_blocks` + `verify_anchors` every minute; `verify_data` hourly or per anchor; `find_tampered_rows` only on demand once something has failed.

## "Which tables are protected and in what state?"

```sql
-- Quick view:
SELECT * FROM pgsigchain.status();

-- Portable snapshot for anchoring the whole set:
SELECT pgsigchain.export_manifest();
```

`export_manifest()` returns a JSONB with each protected table + last `chain_hash`, `block_hash`, and pubkey. Anchoring this JSON externally protects against meta-tampering on `pgsigchain.protected_tables`.
