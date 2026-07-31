// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The **Postgres** backend for busbar's durable governance store — the shared, multi-node `db`
//! plugin. Implements `busbar_api::Store` over a mutex-guarded synchronous `postgres` client,
//! depending only on the `busbar-api` contract (plus the `postgres` driver), never on the engine.
//!
//! It mirrors the SQLite backend's schema and semantics exactly (same tables, same UPSERT shapes,
//! same JSON encoding of `allowed_pools`) so `store: sqlite` and `store: postgres` are drop-in
//! interchangeable — the only differences are the SQL dialect (`$N` params, `EXCLUDED`, `GREATEST`,
//! `BIGINT`/`BOOLEAN`) and that Postgres is a shared server, which is the whole point: one database
//! behind a fleet of busbar nodes means virtual keys, budgets, and usage are shared across the
//! cluster instead of siloed per node.
//!
//! Like SQLite, it is a **single mutex-guarded connection** used off the request hot path (key CRUD
//! + the write-behind usage flush), so serializing access on one connection is correct and simple.
//!
//! "Off the hot path" means off the **reactor**: the one request-triggered read that exists (the
//! revocation denylist re-sync, at most once per node per staleness window) is SCHEDULED onto the
//! blocking pool and bounded to one outstanding call — no request ever waits on this connection,
//! and no Tokio worker thread is ever parked inside it. That property is load-bearing precisely
//! because of the two limitations below: with neither a reconnect nor a statement timeout, a call
//! into this client can block forever, so it must never block anything that has to keep running.
//!
//! ## Known limitations (documented honestly, not papered over)
//!
//! - **No TLS in this build (`NoTls`).** Run the connection over a trusted network segment, a local
//!   socket, or a TLS-terminating proxy (pgbouncer/stunnel). The Redis store, by contrast, speaks
//!   `rediss://` natively.
//! - **No automatic reconnect.** A persistently dropped connection surfaces as store errors on the
//!   (write-behind, retried-per-tick) flush path and on admin operations; the budget flusher
//!   re-marks unflushed deltas dirty and retries every tick, so accrued spend is not lost across a
//!   brief outage, but a permanently broken connection requires a process restart (let your
//!   supervisor handle it). The Redis store implements one-shot transparent reconnect.

use busbar_api::{
    AuditRecord, AwsCredential, MeteringDelta, MeteringRow, ModelTokens, Store, StoreError,
    StoreResult, TierTokens, UsageDelta, UsageLedger, VirtualKey,
};
use postgres::types::ToSql;
use postgres::{Client, NoTls, Row};
use std::sync::Mutex;

// postgres driver error -> the api's backend-agnostic `StoreError` (the contract crate stays
// storage-free, so the `From` impl that powers `?` cannot live there).
trait IntoStoreResult<T> {
    fn store(self) -> StoreResult<T>;
}
impl<T> IntoStoreResult<T> for Result<T, postgres::Error> {
    fn store(self) -> StoreResult<T> {
        self.map_err(|e| StoreError(e.to_string()))
    }
}

/// True when a postgres error is SQLSTATE 42P01 (`undefined_table`) - the ONE case migrate() treats
/// as an unversioned (version 0) database. Every other error class (connection, timeout, permission)
/// is transient/fatal and must never be read as "fresh DB". See migrate()'s H1 note.
fn is_undefined_table(e: &postgres::Error) -> bool {
    e.code() == Some(&postgres::error::SqlState::UNDEFINED_TABLE)
}

/// Extract the PASSWORD from a Postgres DSN (L2). Supports both the URL form
/// (`postgres://user:pass@host:5432/db`) and the libpq keyword form (`... password=secret ...`), so
/// a connect-error string can be scrubbed of the secret regardless of which shape the operator used.
fn dsn_password(dsn: &str) -> Option<String> {
    // URL form: `scheme://[user[:pass]@]host...`.
    if let Some(rest) = dsn.split("://").nth(1) {
        if let Some((userinfo, _)) = rest.rsplit_once('@') {
            if let Some((_, pass)) = userinfo.split_once(':') {
                if !pass.is_empty() {
                    return Some(pass.to_string());
                }
            }
        }
    }
    // libpq keyword form: whitespace-separated `key=value` pairs; find `password=...`.
    for tok in dsn.split_whitespace() {
        if let Some(v) = tok.strip_prefix("password=") {
            if !v.is_empty() {
                return Some(v.to_string());
            }
        }
    }
    None
}

/// Percent-DECODE a URL component (`%40` -> `@`). A malformed escape is left verbatim. So the scrub
/// redacts BOTH the raw and decoded forms of a URL-embedded password.
fn percent_decode(s: &str) -> String {
    let bytes = s.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' && i + 2 < bytes.len() {
            let hi = (bytes[i + 1] as char).to_digit(16);
            let lo = (bytes[i + 2] as char).to_digit(16);
            if let (Some(hi), Some(lo)) = (hi, lo) {
                out.push((hi * 16 + lo) as u8);
                i += 3;
                continue;
            }
        }
        out.push(bytes[i]);
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

/// Replace every occurrence of `secret` (in BOTH raw and percent-decoded forms) with `<redacted>`.
fn scrub(msg: String, secret: Option<&str>) -> String {
    let Some(s) = secret.filter(|s| !s.is_empty()) else {
        return msg;
    };
    let mut out = msg;
    if out.contains(s) {
        out = out.replace(s, "<redacted>");
    }
    let decoded = percent_decode(s);
    if decoded != s && !decoded.is_empty() && out.contains(&decoded) {
        out = out.replace(&decoded, "<redacted>");
    }
    out
}

/// Store schema version, mirrored from the SQLite backend's `PRAGMA user_version` in a tiny
/// `busbar_schema` table. v2 (1.5.0 dev) = the token-ledger cost model; v3 = the 1.5.0 PURE-AUTH
/// key shape (inline limit columns dropped, `budget_group` renamed `key_group`, `allowed_pools`
/// nullable for the C6 NULL-vs-`'[]'` grant intent - see the SQLite backend's `SCHEMA_VERSION`
/// doc). v4 = the usage ledger's REQUEST-COUNT SPLIT: `usage_windows` gains a `billable_requests`
/// column (admitted minus non-2xx refunds - the fee base) alongside `requests` (the admission
/// count). 1.5.0 is unreleased, so a pre-v4 database is dropped and recreated - a bump, never a
/// migration.
const SCHEMA_VERSION: i64 = 4;

// Same tables/columns as the SQLite backend, in Postgres types: INTEGER -> BIGINT, the enabled flag
// as BOOLEAN. `CREATE TABLE IF NOT EXISTS` is idempotent, so migrate() is safe to run every open.
const SCHEMA: &str = "
CREATE TABLE IF NOT EXISTS busbar_schema (
    version BIGINT PRIMARY KEY
);
CREATE TABLE IF NOT EXISTS virtual_keys (
    id               TEXT PRIMARY KEY,
    key_hash         TEXT NOT NULL UNIQUE,
    name             TEXT NOT NULL,
    -- NULLABLE JSON array (v3): NULL = the pool grant was OMITTED at mint = ALL pools; '[]' = an
    -- explicit empty grant = NO pools (C6: the two must never collapse into each other).
    allowed_pools    TEXT,
    enabled          BOOLEAN NOT NULL DEFAULT TRUE,
    created_at       BIGINT NOT NULL,
    -- The key's groups: binding (VirtualKey.group); key_group because GROUP is an SQL keyword.
    key_group        TEXT,
    labels           TEXT NOT NULL DEFAULT '{}'
);
CREATE TABLE IF NOT EXISTS aws_credentials (
    access_key_id     TEXT PRIMARY KEY,
    key_id            TEXT NOT NULL,
    secret_access_key TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_aws_credentials_key_id ON aws_credentials (key_id);
-- The TOKEN LEDGER (v2): per-(bucket, window) request counts + per-(bucket, window, model) tier
-- token counts. `bucket_id` is a virtual key's id OR a budget-group bucket id. NO spend column:
-- dollars are derived at read time from `ledger x rate_card` in the engine.
CREATE TABLE IF NOT EXISTS usage_windows (
    bucket_id    TEXT NOT NULL,
    window_start BIGINT NOT NULL,
    -- ADMISSION count (never refunded): the requests-LIMIT truth.
    requests     BIGINT NOT NULL DEFAULT 0,
    -- v4: admitted MINUS non-2xx refunds - the FEE BASE for the 2xx-only charge. Persisted and
    -- accumulated exactly like `requests`, just with its own signed delta.
    billable_requests BIGINT NOT NULL DEFAULT 0,
    PRIMARY KEY (bucket_id, window_start)
);
CREATE TABLE IF NOT EXISTS usage_ledger (
    bucket_id          TEXT NOT NULL,
    window_start       BIGINT NOT NULL,
    model              TEXT NOT NULL,
    tokens_input       BIGINT NOT NULL DEFAULT 0,
    tokens_output      BIGINT NOT NULL DEFAULT 0,
    tokens_cache_read  BIGINT NOT NULL DEFAULT 0,
    tokens_cache_write BIGINT NOT NULL DEFAULT 0,
    PRIMARY KEY (bucket_id, window_start, model)
);
CREATE TABLE IF NOT EXISTS usage_metering (
    key_id                TEXT NOT NULL,
    bucket                BIGINT NOT NULL,
    model                 TEXT NOT NULL,
    provider              TEXT NOT NULL,
    tokens_input          BIGINT NOT NULL DEFAULT 0,
    tokens_output         BIGINT NOT NULL DEFAULT 0,
    tokens_cache_read     BIGINT NOT NULL DEFAULT 0,
    tokens_cache_creation BIGINT NOT NULL DEFAULT 0,
    requests              BIGINT NOT NULL DEFAULT 0,
    PRIMARY KEY (key_id, bucket, model, provider)
);
-- The admin AUDIT log's durable home (mirrors the SQLite backend). Append-only; `seq` is the engine's
-- monotonic sequence (PK). The engine owns the hash chain; the store persists each record verbatim
-- (upsert on `seq` so a replay is idempotent) and returns them oldest-first for boot restore.
CREATE TABLE IF NOT EXISTS audit_log (
    seq       BIGINT PRIMARY KEY,
    ts        BIGINT NOT NULL,
    action    TEXT NOT NULL,
    resource  TEXT NOT NULL,
    outcome   TEXT NOT NULL,
    principal TEXT NOT NULL,
    prev_hash TEXT NOT NULL,
    hash      TEXT NOT NULL
);
-- The signed-token REVOCATION denylist (1.5.0), mirroring the SQLite backend: a stateless minted
-- token is revoked by recording its subject id here. `sub` is the PRIMARY KEY (idempotent add).
CREATE TABLE IF NOT EXISTS denylist (
    sub        TEXT PRIMARY KEY,
    reason     TEXT NOT NULL DEFAULT '',
    created_at BIGINT NOT NULL DEFAULT 0
);
";

/// Postgres `Store` backend (durable, shared across a cluster). A single mutex-guarded connection —
/// governance is off the request hot path, so serializing access is fine.
pub struct PostgresStore {
    client: Mutex<Client>,
}

/// Clamp a `u64` into `i64` for a BIGINT column (a value above `i64::MAX` pins to `i64::MAX`, never
/// wraps) — mirrors the SQLite backend.
fn clamp(v: u64) -> i64 {
    i64::try_from(v).unwrap_or(i64::MAX)
}

/// Read a signed BIGINT back as a `u64`, clamping a (corrupt / direct-DB) negative to 0 instead of
/// wrapping via `as` — mirrors the SQLite backend's DI-3 posture.
fn read_u64(v: i64) -> u64 {
    v.max(0) as u64
}

impl PostgresStore {
    /// Connect to Postgres with the given libpq connection string / URL (e.g.
    /// `postgres://user:pass@host:5432/dbname`) and ensure the schema. TLS is not wired in this
    /// build (`NoTls`); front the database with a TLS-terminating proxy or a local socket.
    pub fn connect(conn_str: &str) -> StoreResult<Self> {
        // A connect error's string can embed the DSN (and thus the password). Scrub it before it
        // leaves the crate, matching the Redis backend. Handles both the URL form
        // (`postgres://user:pass@host/db`) and the libpq keyword form (`password=secret`), in raw and
        // percent-decoded shapes.
        let secret = dsn_password(conn_str);
        let client = Client::connect(conn_str, NoTls)
            .map_err(|e| StoreError(scrub(e.to_string(), secret.as_deref())))?;
        let store = Self {
            client: Mutex::new(client),
        };
        store.migrate()?;
        Ok(store)
    }

    /// Poison-recovering lock of the client (mirrors the SQLite backend): the guard is reachable off
    /// the hot path, and continuing after a recovered guard is safe because the driver rolls back a
    /// panicked statement.
    fn lock(&self) -> std::sync::MutexGuard<'_, Client> {
        self.client.lock().unwrap_or_else(|p| p.into_inner())
    }

    /// Open a transaction that gives every statement inside it ONE consistent snapshot, taken at the
    /// transaction's first statement. Plain `client.transaction()` defaults to READ COMMITTED, which
    /// does NOT give this: each statement gets its OWN fresh snapshot as of that statement's start, so
    /// a concurrent commit landing between two SELECTs in the same READ-COMMITTED transaction is
    /// visible to the second but invisible to the first — a torn read. `get_usage` (its only current
    /// caller: a requests-row SELECT followed by a model-rows SELECT, both needing to describe the
    /// SAME point in time) depends on this. `pub(crate)` so `tests.rs` can prove the isolation level
    /// this function actually opens, rather than a hand-rolled duplicate of the transaction-open call.
    pub(crate) fn snapshot_consistent_tx<'a>(
        client: &'a mut Client,
    ) -> StoreResult<postgres::Transaction<'a>> {
        client
            .build_transaction()
            .isolation_level(postgres::IsolationLevel::RepeatableRead)
            .start()
            .store()
    }

    /// A fixed, arbitrary-but-stable `pg_advisory_lock` key scoping every `migrate()` call across
    /// every process/connection that ever opens this crate's schema. See `migrate()`'s doc comment
    /// for why this exists.
    const MIGRATE_LOCK_KEY: i64 = 0x6275_7362_6172_5f70; // ASCII "busbar_p", picked for stability/legibility only

    fn migrate(&self) -> StoreResult<()> {
        let mut client = self.lock();
        // CONCURRENCY (session-level advisory lock): `CREATE TABLE IF NOT EXISTS` is idempotent
        // PER STATEMENT but NOT atomic under CONCURRENT DDL - two sessions can both see a table as
        // "missing" and both attempt to create it; one loses a race on the table's implicit row
        // type and fails with "duplicate key value violates unique constraint
        // pg_type_typname_nsp_index" rather than a clean no-op. This is routine here: multiple
        // independent processes (this crate's own live-DB unit test AND the plugin adapter's
        // dlopen e2e test, run concurrently by `cargo test --workspace`, or simply two nodes
        // booting against a fresh database at once in production) can all call `connect()` ->
        // `migrate()` against the SAME database at the SAME time. `pg_advisory_lock` makes the
        // whole migrate body single-flight across every concurrent connection: the first caller
        // performs the CREATEs, every other caller blocks here until it's done and then finds the
        // schema already at its target version (a cheap, correct no-op). Released in every exit
        // path below, including error paths, so a failed migrate never wedges other connections.
        client
            .batch_execute(&format!(
                "SELECT pg_advisory_lock({})",
                Self::MIGRATE_LOCK_KEY
            ))
            .store()?;
        let result = Self::migrate_locked(&mut client);
        // Always release, even on error - never leave the lock held because migrate_locked bailed.
        let _ = client.batch_execute(&format!(
            "SELECT pg_advisory_unlock({})",
            Self::MIGRATE_LOCK_KEY
        ));
        result
    }

    /// The actual migration body, run while holding `MIGRATE_LOCK_KEY` (see `migrate()`).
    fn migrate_locked(client: &mut Client) -> StoreResult<()> {
        // SCHEMA-VERSION BUMP (v4, the 1.5.0 billable-requests ledger split; see SCHEMA_VERSION). A
        // pre-v4 database - one that still carries the legacy `usage_counters` table, or a
        // `virtual_keys` with the old inline-limit columns, or a `usage_windows` without
        // `billable_requests` - is DROPPED and recreated (1.5.0 is unreleased: bump, not migrate). A
        // fresh or already-v4 database passes straight through the idempotent CREATEs.
        //
        // H1 (data-loss): the version read must never CONFLATE a transient read error with a fresh
        // DB. We ensure the version table exists FIRST, then read; a *transient* read failure
        // (connection blip, lock timeout, permission) PROPAGATES and fails boot rather than
        // defaulting to 0 and dropping every governance table on a healthy v2 DB. Only a genuine
        // "relation does not exist" (SQLSTATE 42P01) counts as an unversioned (version 0) database.
        client
            .batch_execute("CREATE TABLE IF NOT EXISTS busbar_schema (version BIGINT PRIMARY KEY)")
            .store()?;
        let version: i64 =
            match client.query_opt("SELECT COALESCE(MAX(version), 0) FROM busbar_schema", &[]) {
                Ok(Some(r)) => r.get(0),
                // No rows -> an empty (freshly created) version table -> version 0.
                Ok(None) => 0,
                // A genuinely-absent table is the only non-fatal "unversioned" signal (version 0). Any
                // OTHER error (transient/connection/permission) MUST fail boot - never silently 0.
                Err(e) if is_undefined_table(&e) => 0,
                Err(e) => return Err(StoreError(e.to_string())),
            };
        // Wrap the legacy DROP + full CREATE + version-INSERT in ONE transaction so a crash between
        // the drop and the recreate cannot leave a half-initialised DB that a re-run re-drops (L3).
        let mut tx = client.transaction().store()?;
        if version < SCHEMA_VERSION {
            let legacy: bool = tx
                .query_one("SELECT to_regclass('usage_counters') IS NOT NULL OR to_regclass('virtual_keys') IS NOT NULL", &[])
                .store()?
                .get(0);
            if legacy {
                tx.batch_execute(
                    "DROP TABLE IF EXISTS virtual_keys;
                         DROP TABLE IF EXISTS aws_credentials;
                         DROP TABLE IF EXISTS usage_counters;
                         DROP TABLE IF EXISTS usage_windows;
                         DROP TABLE IF EXISTS usage_ledger;
                         DROP TABLE IF EXISTS usage_metering;
                         DROP TABLE IF EXISTS audit_log;
                         DROP TABLE IF EXISTS denylist;",
                )
                .store()?;
            }
        }
        tx.batch_execute(SCHEMA).store()?;
        tx.execute(
            "INSERT INTO busbar_schema (version) VALUES ($1) ON CONFLICT (version) DO NOTHING",
            &[&SCHEMA_VERSION],
        )
        .store()?;
        tx.commit().store()?;
        Ok(())
    }
}

// `labels` encoding - identical to the SQLite backend: a JSON object in the `labels TEXT` column.
fn labels_to_storage(labels: &std::collections::BTreeMap<String, String>) -> String {
    serde_json::to_string(labels).unwrap_or_else(|_| "{}".to_string())
}
fn labels_from_storage(stored: &str) -> std::collections::BTreeMap<String, String> {
    serde_json::from_str(stored).unwrap_or_default()
}

// `allowed_pools` encoding - identical to the SQLite backend (v3): SQL NULL = the grant was
// OMITTED (ALL pools); a JSON array = the exhaustive grant, including the explicit empty grant
// (NO pools). A malformed direct-DB value reads as the EMPTY grant (fail-restrictive, never a
// silent widen to "all pools").
fn pools_to_storage(pools: &Option<Vec<String>>) -> Option<String> {
    pools
        .as_ref()
        .map(|p| serde_json::to_string(p).unwrap_or_else(|_| "[]".to_string()))
}
fn pools_from_storage(stored: Option<String>) -> Option<Vec<String>> {
    let stored = stored?;
    Some(serde_json::from_str::<Vec<String>>(stored.trim()).unwrap_or_default())
}

/// Map a `virtual_keys` row (in the fixed SELECT column order) to a `VirtualKey`.
fn row_to_key(r: &Row) -> VirtualKey {
    VirtualKey {
        id: r.get(0),
        key_hash: r.get(1),
        name: r.get(2),
        allowed_pools: pools_from_storage(r.get::<_, Option<String>>(3)),
        enabled: r.get(4),
        created_at: read_u64(r.get::<_, i64>(5)),
        group: r.get(6),
        labels: labels_from_storage(&r.get::<_, String>(7)),
    }
}

const KEY_COLUMNS: &str = "id,key_hash,name,allowed_pools,enabled,created_at,key_group,labels";

impl Store for PostgresStore {
    fn put_key(&self, key: &VirtualKey) -> StoreResult<()> {
        let pools = pools_to_storage(&key.allowed_pools);
        let labels = labels_to_storage(&key.labels);
        let created = clamp(key.created_at);
        self.lock()
            .execute(
                "INSERT INTO virtual_keys
                    (id,key_hash,name,allowed_pools,enabled,created_at,key_group,labels)
                 VALUES ($1,$2,$3,$4,$5,$6,$7,$8)
                 ON CONFLICT (id) DO UPDATE SET
                    key_hash=EXCLUDED.key_hash, name=EXCLUDED.name, allowed_pools=EXCLUDED.allowed_pools,
                    enabled=EXCLUDED.enabled, key_group=EXCLUDED.key_group, labels=EXCLUDED.labels",
                &[
                    &key.id, &key.key_hash, &key.name, &pools, &key.enabled, &created, &key.group,
                    &labels,
                ],
            )
            .store()?;
        Ok(())
    }

    fn get_key(&self, id: &str) -> StoreResult<Option<VirtualKey>> {
        let sql = format!("SELECT {KEY_COLUMNS} FROM virtual_keys WHERE id=$1");
        let row = self.lock().query_opt(&sql, &[&id]).store()?;
        Ok(row.map(|r| row_to_key(&r)))
    }

    fn list_keys(&self) -> StoreResult<Vec<VirtualKey>> {
        let sql = format!("SELECT {KEY_COLUMNS} FROM virtual_keys ORDER BY created_at");
        let rows = self.lock().query(&sql, &[]).store()?;
        Ok(rows.iter().map(row_to_key).collect())
    }

    fn delete_key(&self, id: &str) -> StoreResult<()> {
        // Atomic: the key row, its usage counters, and its AWS credentials go together or not at all,
        // so a revoked key can never leave an orphaned credential (an auth-bypass) or stale usage.
        let mut client = self.lock();
        let mut tx = client.transaction().store()?;
        tx.execute("DELETE FROM virtual_keys WHERE id=$1", &[&id])
            .store()?;
        tx.execute("DELETE FROM usage_windows WHERE bucket_id=$1", &[&id])
            .store()?;
        tx.execute("DELETE FROM usage_ledger WHERE bucket_id=$1", &[&id])
            .store()?;
        // The raw per-(key_id,bucket,model,provider) billing ledger also keys on this id and must not
        // survive a hard delete: an orphaned row here silently corrupts cost reconstruction if the id
        // is ever reused. (Operators who want to retire a key while KEEPING its billing/audit history
        // have two non-destructive paths that never reach this method: PATCH /keys/{id} enabled:false,
        // or POST /keys/{id}/revoke — both documented in admin-api.md as preserving history. DELETE is
        // the deliberate hard-purge primitive, so it must purge everything, this table included.)
        tx.execute("DELETE FROM usage_metering WHERE key_id=$1", &[&id])
            .store()?;
        tx.execute("DELETE FROM aws_credentials WHERE key_id=$1", &[&id])
            .store()?;
        tx.commit().store()?;
        Ok(())
    }

    fn get_usage(&self, bucket_id: &str, window_start: u64) -> StoreResult<UsageLedger> {
        let ws = clamp(window_start);
        let mut client = self.lock();
        let mut tx = Self::snapshot_consistent_tx(&mut client)?;
        let (requests, billable_requests): (u64, u64) = tx
            .query_opt(
                "SELECT requests, billable_requests
                 FROM usage_windows WHERE bucket_id=$1 AND window_start=$2",
                &[&bucket_id, &ws],
            )
            .store()?
            .map(|r| (read_u64(r.get::<_, i64>(0)), read_u64(r.get::<_, i64>(1))))
            .unwrap_or((0, 0));
        let rows = tx
            .query(
                "SELECT model, tokens_input, tokens_output, tokens_cache_read, tokens_cache_write
                 FROM usage_ledger WHERE bucket_id=$1 AND window_start=$2 ORDER BY model",
                &[&bucket_id, &ws],
            )
            .store()?;
        tx.commit().store()?;
        Ok(UsageLedger {
            requests,
            billable_requests,
            models: rows
                .iter()
                .map(|r| ModelTokens {
                    model: r.get(0),
                    tokens: TierTokens {
                        input: read_u64(r.get::<_, i64>(1)),
                        output: read_u64(r.get::<_, i64>(2)),
                        cache_read: read_u64(r.get::<_, i64>(3)),
                        cache_write: read_u64(r.get::<_, i64>(4)),
                    },
                })
                .collect(),
        })
    }

    fn put_usage(
        &self,
        bucket_id: &str,
        window_start: u64,
        ledger: &UsageLedger,
    ) -> StoreResult<()> {
        // ABSOLUTE overwrite (memory is authoritative): replace the whole (bucket, window) record -
        // the requests row AND every model row - in ONE transaction, so a re-flush is idempotent
        // and a reader never sees half a ledger.
        let ws = clamp(window_start);
        let rq = clamp(ledger.requests);
        let brq = clamp(ledger.billable_requests);
        let mut client = self.lock();
        let mut tx = client.transaction().store()?;
        tx.execute(
            "DELETE FROM usage_ledger WHERE bucket_id=$1 AND window_start=$2",
            &[&bucket_id, &ws],
        )
        .store()?;
        tx.execute(
            "INSERT INTO usage_windows (bucket_id, window_start, requests, billable_requests)
             VALUES ($1,$2,$3,$4)
             ON CONFLICT (bucket_id, window_start) DO UPDATE SET
                requests = EXCLUDED.requests,
                billable_requests = EXCLUDED.billable_requests",
            &[&bucket_id, &ws, &rq, &brq],
        )
        .store()?;
        for m in &ledger.models {
            let (ti, to, tcr, tcw) = (
                clamp(m.tokens.input),
                clamp(m.tokens.output),
                clamp(m.tokens.cache_read),
                clamp(m.tokens.cache_write),
            );
            tx.execute(
                "INSERT INTO usage_ledger
                    (bucket_id, window_start, model,
                     tokens_input, tokens_output, tokens_cache_read, tokens_cache_write)
                 VALUES ($1,$2,$3,$4,$5,$6,$7)",
                &[&bucket_id, &ws, &m.model, &ti, &to, &tcr, &tcw],
            )
            .store()?;
        }
        tx.commit().store()?;
        Ok(())
    }

    fn add_usage(&self, bucket_id: &str, window_start: u64, delta: &UsageDelta) -> StoreResult<()> {
        // ADDITIVE fleet-honest accumulate: the signed requests delta plus every per-model tier
        // delta land in ONE transaction, each counter floored at 0 (GREATEST). N nodes flushing
        // deltas sum to the true fleet total, where `put_usage`'s absolute overwrite is
        // last-writer-wins. No dollar delta crosses this wire.
        let ws = clamp(window_start);
        let mut client = self.lock();
        let mut tx = client.transaction().store()?;
        tx.execute(
            // `$N::bigint` casts anchor the parameter type inside GREATEST (whose bare `0` would
            // otherwise make Postgres infer int4 and fail to serialize the i64 binding). The
            // `billable_requests` axis accumulates exactly like `requests`, floored at 0.
            "INSERT INTO usage_windows (bucket_id, window_start, requests, billable_requests)
             VALUES ($1,$2,GREATEST(0,$3::bigint),GREATEST(0,$4::bigint))
             ON CONFLICT (bucket_id, window_start) DO UPDATE SET
                requests = GREATEST(0, usage_windows.requests + $3::bigint),
                billable_requests = GREATEST(0, usage_windows.billable_requests + $4::bigint)",
            &[&bucket_id, &ws, &delta.requests, &delta.billable_requests],
        )
        .store()?;
        for m in &delta.models {
            tx.execute(
                "INSERT INTO usage_ledger
                    (bucket_id, window_start, model,
                     tokens_input, tokens_output, tokens_cache_read, tokens_cache_write)
                 VALUES ($1,$2,$3,GREATEST(0,$4::bigint),GREATEST(0,$5::bigint),GREATEST(0,$6::bigint),GREATEST(0,$7::bigint))
                 ON CONFLICT (bucket_id, window_start, model) DO UPDATE SET
                    tokens_input       = GREATEST(0, usage_ledger.tokens_input + $4::bigint),
                    tokens_output      = GREATEST(0, usage_ledger.tokens_output + $5::bigint),
                    tokens_cache_read  = GREATEST(0, usage_ledger.tokens_cache_read + $6::bigint),
                    tokens_cache_write = GREATEST(0, usage_ledger.tokens_cache_write + $7::bigint)",
                &[
                    &bucket_id,
                    &ws,
                    &m.model,
                    &m.tokens.input,
                    &m.tokens.output,
                    &m.tokens.cache_read,
                    &m.tokens.cache_write,
                ],
            )
            .store()?;
        }
        tx.commit().store()?;
        Ok(())
    }

    fn add_metering(&self, d: &MeteringDelta) -> StoreResult<()> {
        let (bucket, ti, to, tcr, tcc) = (
            clamp(d.bucket),
            clamp(d.tokens_input),
            clamp(d.tokens_output),
            clamp(d.tokens_cache_read),
            clamp(d.tokens_cache_creation),
        );
        let requests = clamp(d.requests);
        self.lock()
            .execute(
                "INSERT INTO usage_metering (key_id, bucket, model, provider,
                     tokens_input, tokens_output, tokens_cache_read, tokens_cache_creation, requests)
                 VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9)
                 ON CONFLICT (key_id, bucket, model, provider) DO UPDATE SET
                     tokens_input          = usage_metering.tokens_input + EXCLUDED.tokens_input,
                     tokens_output         = usage_metering.tokens_output + EXCLUDED.tokens_output,
                     tokens_cache_read     = usage_metering.tokens_cache_read + EXCLUDED.tokens_cache_read,
                     tokens_cache_creation = usage_metering.tokens_cache_creation + EXCLUDED.tokens_cache_creation,
                     requests              = usage_metering.requests + EXCLUDED.requests",
                &[
                    &d.key_id, &bucket, &d.model, &d.provider, &ti, &to, &tcr, &tcc, &requests,
                ],
            )
            .store()?;
        Ok(())
    }

    fn list_metering(&self, bucket: u64) -> StoreResult<Vec<MeteringRow>> {
        let b = clamp(bucket);
        let rows = self
            .lock()
            .query(
                "SELECT key_id, model, provider,
                    tokens_input, tokens_output, tokens_cache_read, tokens_cache_creation, requests
                 FROM usage_metering WHERE bucket=$1",
                &[&b],
            )
            .store()?;
        Ok(rows
            .iter()
            .map(|r| MeteringRow {
                key_id: r.get(0),
                model: r.get(1),
                provider: r.get(2),
                tokens_input: read_u64(r.get::<_, i64>(3)),
                tokens_output: read_u64(r.get::<_, i64>(4)),
                tokens_cache_read: read_u64(r.get::<_, i64>(5)),
                tokens_cache_creation: read_u64(r.get::<_, i64>(6)),
                requests: read_u64(r.get::<_, i64>(7)),
            })
            .collect())
    }

    fn put_aws_credential(&self, cred: &AwsCredential) -> StoreResult<()> {
        self.lock()
            .execute(
                "INSERT INTO aws_credentials (access_key_id, key_id, secret_access_key)
                 VALUES ($1,$2,$3)
                 ON CONFLICT (access_key_id) DO UPDATE SET
                    key_id=EXCLUDED.key_id, secret_access_key=EXCLUDED.secret_access_key",
                &[&cred.access_key_id, &cred.key_id, &cred.secret_access_key],
            )
            .store()?;
        Ok(())
    }

    fn put_key_with_aws_credential(
        &self,
        key: &VirtualKey,
        cred: &AwsCredential,
    ) -> StoreResult<()> {
        // ATOMIC mint: the bearer key and its AWS credential commit together or not at all.
        let pools = pools_to_storage(&key.allowed_pools);
        let labels = labels_to_storage(&key.labels);
        let created = clamp(key.created_at);
        let mut client = self.lock();
        let mut tx = client.transaction().store()?;
        tx.execute(
            "INSERT INTO virtual_keys
                (id,key_hash,name,allowed_pools,enabled,created_at,key_group,labels)
             VALUES ($1,$2,$3,$4,$5,$6,$7,$8)
             ON CONFLICT (id) DO UPDATE SET
                key_hash=EXCLUDED.key_hash, name=EXCLUDED.name, allowed_pools=EXCLUDED.allowed_pools,
                enabled=EXCLUDED.enabled, key_group=EXCLUDED.key_group, labels=EXCLUDED.labels",
            &[
                &key.id, &key.key_hash, &key.name, &pools, &key.enabled, &created, &key.group,
                &labels,
            ],
        )
        .store()?;
        tx.execute(
            "INSERT INTO aws_credentials (access_key_id, key_id, secret_access_key)
             VALUES ($1,$2,$3)
             ON CONFLICT (access_key_id) DO UPDATE SET
                key_id=EXCLUDED.key_id, secret_access_key=EXCLUDED.secret_access_key",
            &[&cred.access_key_id, &cred.key_id, &cred.secret_access_key],
        )
        .store()?;
        tx.commit().store()?;
        Ok(())
    }

    fn list_aws_credentials(&self) -> StoreResult<Vec<AwsCredential>> {
        let rows = self
            .lock()
            .query(
                "SELECT access_key_id, key_id, secret_access_key FROM aws_credentials",
                &[],
            )
            .store()?;
        Ok(rows
            .iter()
            .map(|r| AwsCredential {
                access_key_id: r.get(0),
                key_id: r.get(1),
                secret_access_key: r.get(2),
            })
            .collect())
    }

    fn append_audit(&self, entry: &AuditRecord) -> StoreResult<()> {
        // Upsert on the `seq` PK: append-only in practice, idempotent if the engine re-writes a record
        // for the same seq (never a UNIQUE violation).
        let (seq, ts) = (clamp(entry.seq), clamp(entry.ts));
        self.lock()
            .execute(
                "INSERT INTO audit_log
                    (seq, ts, action, resource, outcome, principal, prev_hash, hash)
                 VALUES ($1,$2,$3,$4,$5,$6,$7,$8)
                 ON CONFLICT (seq) DO UPDATE SET
                    ts=EXCLUDED.ts, action=EXCLUDED.action, resource=EXCLUDED.resource,
                    outcome=EXCLUDED.outcome, principal=EXCLUDED.principal,
                    prev_hash=EXCLUDED.prev_hash, hash=EXCLUDED.hash",
                &[
                    &seq,
                    &ts,
                    &entry.action,
                    &entry.resource,
                    &entry.outcome,
                    &entry.principal,
                    &entry.prev_hash,
                    &entry.hash,
                ],
            )
            .store()?;
        Ok(())
    }

    fn list_audit(&self) -> StoreResult<Vec<AuditRecord>> {
        let rows = self
            .lock()
            .query(
                "SELECT seq, ts, action, resource, outcome, principal, prev_hash, hash
                 FROM audit_log ORDER BY seq",
                &[],
            )
            .store()?;
        Ok(rows
            .iter()
            .map(|r| AuditRecord {
                seq: read_u64(r.get::<_, i64>(0)),
                ts: read_u64(r.get::<_, i64>(1)),
                action: r.get(2),
                resource: r.get(3),
                outcome: r.get(4),
                principal: r.get(5),
                prev_hash: r.get(6),
                hash: r.get(7),
            })
            .collect())
    }

    fn list_audit_tail(&self, limit: u64) -> StoreResult<Vec<AuditRecord>> {
        // BOUNDED restore read: select only the most-recent `limit` rows at the SOURCE (a `LIMIT` on
        // a descending scan), then reverse into oldest-first. Without this override the trait default
        // materializes the ENTIRE (never-pruned) durable audit log before truncating in memory, which
        // over the plugin ABI can exceed the response cap or OOM on a large log. Mirrors the SQLite
        // backend's `LIMIT`ed tail query.
        let rows = self
            .lock()
            .query(
                "SELECT seq, ts, action, resource, outcome, principal, prev_hash, hash
                 FROM audit_log ORDER BY seq DESC LIMIT $1",
                &[&i64::try_from(limit).unwrap_or(i64::MAX)],
            )
            .store()?;
        let mut out: Vec<AuditRecord> = rows
            .iter()
            .map(|r| AuditRecord {
                seq: read_u64(r.get::<_, i64>(0)),
                ts: read_u64(r.get::<_, i64>(1)),
                action: r.get(2),
                resource: r.get(3),
                outcome: r.get(4),
                principal: r.get(5),
                prev_hash: r.get(6),
                hash: r.get(7),
            })
            .collect();
        out.reverse(); // DESC LIMIT gave newest-first; the restore contract is oldest-first.
        Ok(out)
    }

    fn add_denylist(&self, sub: &str, reason: &str) -> StoreResult<()> {
        // Idempotent revoke (mirrors the SQLite backend): the subject stays denied exactly once; a
        // repeat refreshes the operator reason.
        self.lock()
            .execute(
                "INSERT INTO denylist (sub, reason, created_at) VALUES ($1, $2, 0)
                 ON CONFLICT (sub) DO UPDATE SET reason = EXCLUDED.reason",
                &[&sub, &reason],
            )
            .store()?;
        Ok(())
    }

    fn list_denylist(&self) -> StoreResult<Vec<String>> {
        let rows = self.lock().query("SELECT sub FROM denylist", &[]).store()?;
        Ok(rows.iter().map(|r| r.get(0)).collect())
    }
}

// A tiny compile-time assertion that the param binding types line up (keeps ToSql import used even
// when the integration test is skipped for lack of a live database).
const _: fn() = || {
    fn assert_tosql<T: ToSql>() {}
    assert_tosql::<i64>();
    assert_tosql::<Option<i64>>();
    assert_tosql::<bool>();
};

#[cfg(test)]
mod tests;
