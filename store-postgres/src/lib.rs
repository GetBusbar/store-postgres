// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The **Postgres** backend for busbar's durable governance store — the shared, multi-node `db`
//! plugin. Implements `busbar_api::Store` over a mutex-guarded synchronous `postgres` client,
//! depending only on the `busbar-api` contract (plus the `postgres` driver), never on the engine.
//!
//! Schema v5 (1.5.0, the generic-credentials redesign): `virtual_keys`/`aws_credentials` are
//! replaced by `keys` (pure principal attributes, `generation_hash` instead of `key_hash`,
//! `expires_at`/`deleted_at`/`revision`) and `credentials` (kind-polymorphic row-looked-up
//! credentials — today only `kind='sigv4'`). `DELETE` is a TOMBSTONE, not a hard delete: the `keys`
//! row survives (so `usage_metering.key_id` keeps resolving forever) while every credential row for
//! it is destroyed and `enabled`/`deleted_at` are set, atomically, in the same transaction and the
//! same `revision` stamp — this is what makes revision-delta hydration observe the tombstone AND
//! the credential disappearance as one atomic delta (see `delete_key`'s doc comment for why this
//! matters: a naive implementation that tombstoned the key in one transaction and deleted
//! credentials in another would let a `REPEATABLE READ` hydration snapshot land between them and
//! observe a "deleted" key whose credential is still live).
//!
//! Like the prior schema, this is a **single mutex-guarded connection** used off the request hot
//! path (key CRUD + the write-behind usage flush) — governance is off the reactor entirely.
//!
//! ## Known limitations (documented honestly, not papered over)
//!
//! - **No TLS in this build (`NoTls`).** Run the connection over a trusted network segment, a local
//!   socket, or a TLS-terminating proxy (pgbouncer/stunnel).
//! - **No automatic reconnect.** A persistently dropped connection surfaces as store errors; a
//!   permanently broken connection requires a process restart.
//! - **No partitioning, no LISTEN/NOTIFY-accelerated hydration, no column-level secret grants in
//!   this pass.** The design session that produced this schema recommended all three as scale/perf
//!   layers on top of this contract — deliberately deferred here in favor of getting the
//!   correctness-critical surface (tombstone semantics, revoke fan-out via `revoke_credential`,
//!   hydration-delta soundness, slot-safe credential minting) right first. None of the three change
//!   the `Store` trait's observable behavior; they're purely internal to this crate and can be
//!   added later without another schema bump.

use busbar_api::{
    AuditRecord, CredentialMeta, CredentialSecret, MeteringDelta, MeteringRow, ModelTokens,
    ScopeRef, SecretForm, Store, StoreError, StoreResult, TierTokens, UsageDelta, UsageLedger,
    VirtualKey,
};
use postgres::types::ToSql;
use postgres::{Client, NoTls, Row, Transaction};
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
    if let Some(rest) = dsn.split("://").nth(1) {
        if let Some((userinfo, _)) = rest.rsplit_once('@') {
            if let Some((_, pass)) = userinfo.split_once(':') {
                if !pass.is_empty() {
                    return Some(pass.to_string());
                }
            }
        }
    }
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

/// Store schema version. v5 (1.5.0 generic-credentials redesign): `virtual_keys`/`aws_credentials`
/// -> `keys`/`credentials` (kind-polymorphic, slot-bounded, tombstone-delete, revision-stamped for
/// incremental hydration). 1.5.0 is unreleased, so a pre-v5 database is dropped and recreated - a
/// bump, never a migration.
const SCHEMA_VERSION: i64 = 5;

const SCHEMA: &str = "
CREATE TABLE IF NOT EXISTS busbar_schema (
    version BIGINT PRIMARY KEY
);
CREATE TABLE IF NOT EXISTS store_revision (
    only_row BOOLEAN PRIMARY KEY DEFAULT TRUE CHECK (only_row),
    revision BIGINT NOT NULL DEFAULT 0 CHECK (revision >= 0)
);
INSERT INTO store_revision (only_row, revision) VALUES (TRUE, 0) ON CONFLICT (only_row) DO NOTHING;

CREATE TABLE IF NOT EXISTS keys (
    id              TEXT PRIMARY KEY,
    -- Rotation fingerprint (VirtualKey::generation_hash), NOT a lookup key -- deliberately no
    -- UNIQUE constraint, see the type's own doc for why.
    generation_hash TEXT NOT NULL,
    name            TEXT NOT NULL,
    -- NULL = the pool grant was OMITTED at mint = ALL pools; a JSON array (possibly empty) = the
    -- exhaustive grant (C6: NULL and '[]' must never collapse into each other).
    allowed_pools   TEXT,
    enabled         BOOLEAN NOT NULL DEFAULT TRUE,
    created_at      BIGINT NOT NULL,
    key_group       TEXT,
    labels          TEXT NOT NULL DEFAULT '{}',
    expires_at      BIGINT,
    -- TOMBSTONE marker. NULL = live. The row is never removed once tombstoned; see delete_key.
    deleted_at      BIGINT,
    revision        BIGINT NOT NULL DEFAULT 0,
    CONSTRAINT keys_tombstone_disabled CHECK (deleted_at IS NULL OR enabled = FALSE)
);
CREATE INDEX IF NOT EXISTS idx_keys_revision ON keys (revision);

-- Row-looked-up credentials ONLY (today: sigv4). Bearer/signed-token auth is never represented
-- here -- verify_token never looks up a row, it only compares VirtualKey::generation_hash. Slot
-- bounds cardinality to exactly 2 rows per (key_id, kind), for safe overlap-window rotation.
CREATE TABLE IF NOT EXISTS credentials (
    id            TEXT PRIMARY KEY,
    key_id        TEXT NOT NULL REFERENCES keys(id) ON DELETE CASCADE,
    kind          TEXT NOT NULL CHECK (kind IN ('sigv4')),
    slot          SMALLINT NOT NULL CHECK (slot IN (0, 1)),
    public_id     TEXT NOT NULL,
    secret        TEXT,
    secret_form   TEXT NOT NULL CHECK (secret_form IN ('none', 'recoverable', 'digest')),
    created_at    BIGINT NOT NULL,
    updated_at    BIGINT NOT NULL,
    expires_at    BIGINT,
    revoked_at    BIGINT,
    revoke_reason TEXT,
    revision      BIGINT NOT NULL DEFAULT 0,
    CONSTRAINT credentials_public_id_uniq UNIQUE (kind, public_id),
    CONSTRAINT credentials_slot_uniq UNIQUE (key_id, kind, slot),
    CONSTRAINT credentials_secret_form_matches CHECK ((secret_form = 'none') = (secret IS NULL))
);
CREATE INDEX IF NOT EXISTS idx_credentials_revision ON credentials (revision);
CREATE INDEX IF NOT EXISTS idx_credentials_key_id ON credentials (key_id);

CREATE TABLE IF NOT EXISTS usage_windows (
    bucket_id    TEXT NOT NULL,
    window_start BIGINT NOT NULL,
    requests     BIGINT NOT NULL DEFAULT 0,
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
    key_id             TEXT NOT NULL,
    bucket             BIGINT NOT NULL,
    model              TEXT NOT NULL,
    provider           TEXT NOT NULL,
    tokens_input       BIGINT NOT NULL DEFAULT 0,
    tokens_output      BIGINT NOT NULL DEFAULT 0,
    tokens_cache_read  BIGINT NOT NULL DEFAULT 0,
    tokens_cache_write BIGINT NOT NULL DEFAULT 0,
    requests           BIGINT NOT NULL DEFAULT 0,
    billable_requests  BIGINT NOT NULL DEFAULT 0,
    key_group_at_use   TEXT NOT NULL DEFAULT '',
    pricing_version    TEXT NOT NULL DEFAULT '',
    PRIMARY KEY (key_id, bucket, model, provider)
);
CREATE INDEX IF NOT EXISTS idx_usage_metering_bucket ON usage_metering (bucket);
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
/// wraps).
fn clamp(v: u64) -> i64 {
    i64::try_from(v).unwrap_or(i64::MAX)
}

/// Read a signed BIGINT back as a `u64`, clamping a (corrupt / direct-DB) negative to 0 instead of
/// wrapping via `as`.
fn read_u64(v: i64) -> u64 {
    v.max(0) as u64
}

impl PostgresStore {
    /// Connect to Postgres with the given libpq connection string / URL and ensure the schema. TLS
    /// is not wired in this build (`NoTls`); front the database with a TLS-terminating proxy or a
    /// local socket.
    pub fn connect(conn_str: &str) -> StoreResult<Self> {
        let secret = dsn_password(conn_str);
        let client = Client::connect(conn_str, NoTls)
            .map_err(|e| StoreError(scrub(e.to_string(), secret.as_deref())))?;
        let store = Self {
            client: Mutex::new(client),
        };
        store.migrate()?;
        Ok(store)
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, Client> {
        self.client.lock().unwrap_or_else(|p| p.into_inner())
    }

    /// Open a transaction that gives every statement inside it ONE consistent snapshot, taken at the
    /// transaction's first statement — REPEATABLE READ, not the default READ COMMITTED (which gives
    /// each statement its own fresh snapshot, a torn-read hazard for any multi-statement read like
    /// `get_usage` or the hydration delta queries).
    pub(crate) fn snapshot_consistent_tx<'a>(
        client: &'a mut Client,
    ) -> StoreResult<postgres::Transaction<'a>> {
        client
            .build_transaction()
            .isolation_level(postgres::IsolationLevel::RepeatableRead)
            .start()
            .store()
    }

    const MIGRATE_LOCK_KEY: i64 = 0x6275_7362_6172_5f70; // ASCII "busbar_p"

    fn migrate(&self) -> StoreResult<()> {
        let mut client = self.lock();
        client
            .batch_execute(&format!(
                "SELECT pg_advisory_lock({})",
                Self::MIGRATE_LOCK_KEY
            ))
            .store()?;
        let result = Self::migrate_locked(&mut client);
        let unlocked = client.batch_execute(&format!(
            "SELECT pg_advisory_unlock({})",
            Self::MIGRATE_LOCK_KEY
        ));
        // A migration failure is the more important thing to report; don't mask it with an unlock
        // failure. But if the migration itself SUCCEEDED and the unlock did not, that must not be
        // swallowed: an un-released session-held advisory lock can hang a sibling node's connect()
        // (which takes the same lock before its own migrate) for the remaining lifetime of this
        // process's connection, with previously zero trace that it happened.
        match (result, unlocked) {
            (Ok(()), Err(e)) => Err(StoreError(format!(
                "migrate: schema migration succeeded but releasing the advisory lock failed ({e}); \
                 a sibling node's own migrate() may now hang waiting for this lock"
            ))),
            (result, _) => result,
        }
    }

    fn migrate_locked(client: &mut Client) -> StoreResult<()> {
        client
            .batch_execute("CREATE TABLE IF NOT EXISTS busbar_schema (version BIGINT PRIMARY KEY)")
            .store()?;
        let version: i64 =
            match client.query_opt("SELECT COALESCE(MAX(version), 0) FROM busbar_schema", &[]) {
                Ok(Some(r)) => r.get(0),
                Ok(None) => 0,
                Err(e) if is_undefined_table(&e) => 0,
                Err(e) => return Err(StoreError(e.to_string())),
            };
        let mut tx = client.transaction().store()?;
        if version < SCHEMA_VERSION {
            let legacy: bool = tx
                .query_one(
                    "SELECT to_regclass('usage_counters') IS NOT NULL
                        OR to_regclass('virtual_keys') IS NOT NULL
                        OR to_regclass('aws_credentials') IS NOT NULL",
                    &[],
                )
                .store()?
                .get(0);
            if legacy {
                tx.batch_execute(
                    "DROP TABLE IF EXISTS virtual_keys;
                     DROP TABLE IF EXISTS aws_credentials;
                     DROP TABLE IF EXISTS keys CASCADE;
                     DROP TABLE IF EXISTS credentials;
                     DROP TABLE IF EXISTS usage_counters;
                     DROP TABLE IF EXISTS usage_windows;
                     DROP TABLE IF EXISTS usage_ledger;
                     DROP TABLE IF EXISTS usage_metering;
                     DROP TABLE IF EXISTS audit_log;
                     DROP TABLE IF EXISTS denylist;
                     DROP TABLE IF EXISTS store_revision;",
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

    /// Bump and return the store-global revision INSIDE the caller's already-open transaction. Must
    /// be the FIRST statement of any transaction that mutates `keys`/`credentials`/`denylist` (not
    /// `denylist` directly — `add_denylist` doesn't take a revision param on the trait — but keys
    /// and credentials do): calling it first fixes a single lock-acquisition order
    /// (`store_revision` row, then whatever else the transaction touches) across every mutating
    /// method, which is what makes cross-method deadlock structurally impossible.
    fn next_revision(tx: &mut Transaction<'_>) -> StoreResult<i64> {
        tx.query_one(
            "UPDATE store_revision SET revision = revision + 1 WHERE only_row RETURNING revision",
            &[],
        )
        .store()?
        .try_get(0)
        .store()
    }
}

fn labels_to_storage(labels: &std::collections::BTreeMap<String, String>) -> String {
    serde_json::to_string(labels).unwrap_or_else(|_| "{}".to_string())
}
fn labels_from_storage(stored: &str) -> std::collections::BTreeMap<String, String> {
    serde_json::from_str(stored).unwrap_or_default()
}

// Wire/DB storage format is unchanged by the ScopeRef generalization -- still a plain JSON array
// of bare pool-name strings (or NULL) in the `allowed_pools` TEXT column. Only the Rust-side type
// at this crate's boundary changed (`Vec<String>` -> `Vec<ScopeRef>`); the conversion happens here,
// at construction (`ScopeRef::pool(name)`) and at read (`.value`).
fn pools_to_storage(pools: &Option<Vec<ScopeRef>>) -> Option<String> {
    pools.as_ref().map(|p| {
        let names: Vec<&str> = p.iter().map(|s| s.value.as_str()).collect();
        serde_json::to_string(&names).unwrap_or_else(|_| "[]".to_string())
    })
}
fn pools_from_storage(stored: Option<String>) -> Option<Vec<ScopeRef>> {
    let stored = stored?;
    Some(
        serde_json::from_str::<Vec<String>>(stored.trim())
            .unwrap_or_default()
            .into_iter()
            .map(ScopeRef::pool)
            .collect(),
    )
}

fn row_to_key(r: &Row) -> VirtualKey {
    VirtualKey {
        id: r.get(0),
        generation_hash: r.get(1),
        name: r.get(2),
        allowed_scopes: pools_from_storage(r.get::<_, Option<String>>(3)),
        enabled: r.get(4),
        created_at: read_u64(r.get::<_, i64>(5)),
        group: r.get(6),
        labels: labels_from_storage(&r.get::<_, String>(7)),
        expires_at: r.get::<_, Option<i64>>(8).map(read_u64),
        deleted_at: r.get::<_, Option<i64>>(9).map(read_u64),
        revision: read_u64(r.get::<_, i64>(10)),
    }
}

const KEY_COLUMNS: &str = "id,generation_hash,name,allowed_pools,enabled,created_at,key_group,labels,expires_at,deleted_at,revision";

fn secret_form_to_storage(f: SecretForm) -> &'static str {
    match f {
        SecretForm::None => "none",
        SecretForm::Recoverable => "recoverable",
        SecretForm::Digest => "digest",
    }
}
fn secret_form_from_storage(s: &str) -> SecretForm {
    match s {
        "recoverable" => SecretForm::Recoverable,
        "digest" => SecretForm::Digest,
        _ => SecretForm::None,
    }
}

const CRED_META_COLUMNS: &str = "id,key_id,kind,slot,public_id,secret_form,created_at,updated_at,expires_at,revoked_at,revoke_reason,revision";
/// The row index of `secret` in `SELECT {CRED_META_COLUMNS},secret FROM credentials ...` -- always
/// exactly the column COUNT of CRED_META_COLUMNS (12: id,key_id,kind,slot,public_id,secret_form,
/// created_at,updated_at,expires_at,revoked_at,revoke_reason,revision -- indices 0-11), since every
/// query that reads `secret` builds its SELECT by appending it right after that column list. Named
/// here instead of a bare `12` at each call site; `debug_assert!` below catches drift if
/// CRED_META_COLUMNS' column count ever changes without updating this constant to match, since
/// `str::split` isn't const-evaluable in stable Rust.
const CRED_SECRET_COLUMN_INDEX: usize = 12;

fn row_to_cred_meta(r: &Row) -> CredentialMeta {
    CredentialMeta {
        id: r.get(0),
        key_id: r.get(1),
        kind: r.get(2),
        slot: r.get::<_, i16>(3) as u8,
        public_id: r.get(4),
        secret_form: secret_form_from_storage(r.get::<_, &str>(5)),
        created_at: read_u64(r.get::<_, i64>(6)),
        updated_at: read_u64(r.get::<_, i64>(7)),
        expires_at: r.get::<_, Option<i64>>(8).map(read_u64),
        revoked_at: r.get::<_, Option<i64>>(9).map(read_u64),
        revoke_reason: r.get(10),
        revision: read_u64(r.get::<_, i64>(11)),
    }
}

impl Store for PostgresStore {
    fn put_key(&self, key: &VirtualKey) -> StoreResult<()> {
        let pools = pools_to_storage(&key.allowed_scopes);
        let labels = labels_to_storage(&key.labels);
        let created = clamp(key.created_at);
        let expires = key.expires_at.map(clamp);
        let deleted = key.deleted_at.map(clamp);
        let mut client = self.lock();
        let mut tx = client.transaction().store()?;
        let rev = Self::next_revision(&mut tx)?;
        tx.execute(
            "INSERT INTO keys
                (id,generation_hash,name,allowed_pools,enabled,created_at,key_group,labels,expires_at,deleted_at,revision)
             VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11)
             ON CONFLICT (id) DO UPDATE SET
                generation_hash=EXCLUDED.generation_hash, name=EXCLUDED.name,
                allowed_pools=EXCLUDED.allowed_pools, enabled=EXCLUDED.enabled,
                key_group=EXCLUDED.key_group, labels=EXCLUDED.labels,
                expires_at=EXCLUDED.expires_at, deleted_at=EXCLUDED.deleted_at,
                revision=EXCLUDED.revision",
            &[
                &key.id, &key.generation_hash, &key.name, &pools, &key.enabled, &created,
                &key.group, &labels, &expires, &deleted, &rev,
            ],
        )
        .store()?;
        tx.commit().store()?;
        Ok(())
    }

    fn get_key(&self, id: &str) -> StoreResult<Option<VirtualKey>> {
        let sql = format!("SELECT {KEY_COLUMNS} FROM keys WHERE id=$1");
        let row = self.lock().query_opt(&sql, &[&id]).store()?;
        Ok(row.map(|r| row_to_key(&r)))
    }

    fn list_keys(&self) -> StoreResult<Vec<VirtualKey>> {
        // Deliberately UNFILTERED (tombstoned rows included) -- see the trait doc: this serves both
        // the admin-listing caller (which filters deleted_at.is_none() itself) and list_keys_since's
        // default fallback, which needs tombstones visible to drive credential eviction downstream.
        let sql = format!("SELECT {KEY_COLUMNS} FROM keys ORDER BY created_at");
        let rows = self.lock().query(&sql, &[]).store()?;
        Ok(rows.iter().map(row_to_key).collect())
    }

    fn list_keys_since(&self, since: u64) -> StoreResult<Vec<VirtualKey>> {
        let sql = format!("SELECT {KEY_COLUMNS} FROM keys WHERE revision > $1 ORDER BY revision");
        let rows = self.lock().query(&sql, &[&clamp(since)]).store()?;
        Ok(rows.iter().map(row_to_key).collect())
    }

    fn delete_key(&self, id: &str) -> StoreResult<()> {
        // TOMBSTONE, not a hard delete: the `keys` row survives (billing/audit attribution keeps
        // resolving it forever) while every credential row for it is destroyed. Both happen in ONE
        // transaction stamped with the SAME revision, which is the load-bearing property for
        // hydration soundness: a REPEATABLE READ hydration snapshot can never observe the
        // tombstoned key without the credentials already being gone, so a delta-consumer that
        // reacts to "this key's revision-delta shows deleted_at newly set" by evicting all its
        // cached credentials is provably correct -- there is no window where the credential rows'
        // own (now-nonexistent) deltas would have been needed to convey the deletion.
        let mut client = self.lock();
        let mut tx = client.transaction().store()?;
        let already_deleted: Option<bool> = tx
            .query_opt(
                "SELECT deleted_at IS NOT NULL FROM keys WHERE id=$1",
                &[&id],
            )
            .store()?
            .map(|r| r.get(0));
        match already_deleted {
            None => {
                // Unknown id: idempotent no-op per the trait doc (delete_key is defined idempotent;
                // an unknown id is not distinguished from an already-tombstoned one at this layer).
                tx.commit().store()?;
                return Ok(());
            }
            Some(true) => {
                // Already tombstoned: no-op, not an error.
                tx.commit().store()?;
                return Ok(());
            }
            Some(false) => {}
        }
        let rev = Self::next_revision(&mut tx)?;
        tx.execute("DELETE FROM credentials WHERE key_id=$1", &[&id])
            .store()?;
        // `AND deleted_at IS NULL` re-states the guard the SELECT above already checked, IN the
        // UPDATE's own WHERE clause: under Postgres' READ COMMITTED semantics, an UPDATE takes a row
        // lock and re-evaluates its WHERE against the post-lock committed data, so this closes the
        // TOCTOU window the plain `SELECT` above cannot -- two concurrent delete_key calls on the
        // same id now genuinely serialize (the loser's UPDATE matches 0 rows) instead of both
        // unconditionally overwriting `deleted_at`/`revision` regardless of which committed first.
        let changed = tx
            .execute(
                "UPDATE keys SET enabled=FALSE, deleted_at=$2, revision=$3 \
                 WHERE id=$1 AND deleted_at IS NULL",
                &[&id, &rev, &rev],
            )
            .store()?;
        // A concurrent delete_key committed between our SELECT and this UPDATE: idempotent no-op,
        // same as the `Some(true)` branch above -- not an error.
        if changed == 0 {
            tx.commit().store()?;
            return Ok(());
        }
        tx.commit().store()?;
        Ok(())
    }

    fn scrub_key(&self, id: &str) -> StoreResult<()> {
        // PII-erasure only: null name/labels on an ALREADY-tombstoned key. Errors if unknown or
        // still live -- scrubbing a live key would be silent, un-auditable data loss on an active
        // principal (the trait doc's own guard: go through delete_key first).
        let mut client = self.lock();
        let mut tx = client.transaction().store()?;
        let deleted: Option<bool> = tx
            .query_opt(
                "SELECT deleted_at IS NOT NULL FROM keys WHERE id=$1",
                &[&id],
            )
            .store()?
            .map(|r| r.get(0));
        match deleted {
            None => return Err(StoreError(format!("scrub_key: unknown key {id}"))),
            Some(false) => {
                return Err(StoreError(format!(
                    "scrub_key: key {id} is not tombstoned -- call delete_key first"
                )))
            }
            Some(true) => {}
        }
        let rev = Self::next_revision(&mut tx)?;
        // `AND deleted_at IS NOT NULL` re-states the "must already be tombstoned" guard IN the
        // UPDATE's own WHERE clause, closing the same TOCTOU class as delete_key above: the SELECT
        // this function just ran is not atomic with this write, so without the re-check here a
        // concurrent put_key/put_key_with_credential resurrecting the key between the SELECT and
        // this UPDATE would let scrub_key silently erase name/labels on what is, by the time this
        // statement lands, a LIVE key -- exactly the un-auditable-data-loss-on-an-active-principal
        // this method's own doc comment says it must never do.
        let changed = tx
            .execute(
                "UPDATE keys SET name='', labels='{}', revision=$2 \
                 WHERE id=$1 AND deleted_at IS NOT NULL",
                &[&id, &rev],
            )
            .store()?;
        if changed == 0 {
            return Err(StoreError(format!(
                "scrub_key: key {id} was resurrected (deleted_at cleared) concurrently with this \
                 call -- refusing to scrub a key that is live by the time the write landed"
            )));
        }
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
        if !ledger.models.is_empty() {
            let rows: Vec<(i64, i64, i64, i64)> = ledger
                .models
                .iter()
                .map(|m| {
                    (
                        clamp(m.tokens.input),
                        clamp(m.tokens.output),
                        clamp(m.tokens.cache_read),
                        clamp(m.tokens.cache_write),
                    )
                })
                .collect();
            let mut sql = String::from(
                "INSERT INTO usage_ledger \
                 (bucket_id, window_start, model, tokens_input, tokens_output, tokens_cache_read, tokens_cache_write) \
                 VALUES ",
            );
            let mut params: Vec<&(dyn ToSql + Sync)> = Vec::with_capacity(2 + rows.len() * 5);
            params.push(&bucket_id);
            params.push(&ws);
            for (i, (m, row)) in ledger.models.iter().zip(rows.iter()).enumerate() {
                if i > 0 {
                    sql.push(',');
                }
                let base = 3 + i * 5;
                sql.push_str(&format!(
                    "($1,$2,${},${},${},${},${})",
                    base,
                    base + 1,
                    base + 2,
                    base + 3,
                    base + 4
                ));
                params.push(&m.model);
                params.push(&row.0);
                params.push(&row.1);
                params.push(&row.2);
                params.push(&row.3);
            }
            tx.execute(&sql, &params).store()?;
        }
        tx.commit().store()?;
        Ok(())
    }

    fn add_usage(&self, bucket_id: &str, window_start: u64, delta: &UsageDelta) -> StoreResult<()> {
        let ws = clamp(window_start);
        let mut client = self.lock();
        let mut tx = client.transaction().store()?;
        tx.execute(
            "INSERT INTO usage_windows (bucket_id, window_start, requests, billable_requests)
             VALUES ($1,$2,GREATEST(0,$3::bigint),GREATEST(0,$4::bigint))
             ON CONFLICT (bucket_id, window_start) DO UPDATE SET
                requests = GREATEST(0, usage_windows.requests + $3::bigint),
                billable_requests = GREATEST(0, usage_windows.billable_requests + $4::bigint)",
            &[&bucket_id, &ws, &delta.requests, &delta.billable_requests],
        )
        .store()?;
        if !delta.models.is_empty() {
            // Batched into ONE multi-row INSERT instead of one round trip per model, mirroring
            // put_usage's identical multi-row VALUES-list construction above for the same table.
            let mut sql = String::from(
                "INSERT INTO usage_ledger \
                 (bucket_id, window_start, model, tokens_input, tokens_output, tokens_cache_read, tokens_cache_write) \
                 VALUES ",
            );
            let mut params: Vec<&(dyn ToSql + Sync)> =
                Vec::with_capacity(2 + delta.models.len() * 5);
            params.push(&bucket_id);
            params.push(&ws);
            for (i, m) in delta.models.iter().enumerate() {
                if i > 0 {
                    sql.push(',');
                }
                let base = 3 + i * 5;
                sql.push_str(&format!(
                    "($1,$2,${},GREATEST(0,${}::bigint),GREATEST(0,${}::bigint),GREATEST(0,${}::bigint),GREATEST(0,${}::bigint))",
                    base,
                    base + 1,
                    base + 2,
                    base + 3,
                    base + 4
                ));
                params.push(&m.model);
                params.push(&m.tokens.input);
                params.push(&m.tokens.output);
                params.push(&m.tokens.cache_read);
                params.push(&m.tokens.cache_write);
            }
            sql.push_str(
                " ON CONFLICT (bucket_id, window_start, model) DO UPDATE SET \
                    tokens_input       = GREATEST(0, usage_ledger.tokens_input + EXCLUDED.tokens_input), \
                    tokens_output      = GREATEST(0, usage_ledger.tokens_output + EXCLUDED.tokens_output), \
                    tokens_cache_read  = GREATEST(0, usage_ledger.tokens_cache_read + EXCLUDED.tokens_cache_read), \
                    tokens_cache_write = GREATEST(0, usage_ledger.tokens_cache_write + EXCLUDED.tokens_cache_write)",
            );
            tx.execute(&sql, &params).store()?;
        }
        tx.commit().store()?;
        Ok(())
    }

    fn add_metering(&self, d: &MeteringDelta) -> StoreResult<()> {
        let (bucket, ti, to, tcr, tcw) = (
            clamp(d.bucket),
            clamp(d.tokens_input),
            clamp(d.tokens_output),
            clamp(d.tokens_cache_read),
            clamp(d.tokens_cache_write),
        );
        let requests = clamp(d.requests);
        let brequests = clamp(d.billable_requests);
        self.lock()
            .execute(
                "INSERT INTO usage_metering (key_id, bucket, model, provider,
                     tokens_input, tokens_output, tokens_cache_read, tokens_cache_write,
                     requests, billable_requests, key_group_at_use, pricing_version)
                 VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12)
                 ON CONFLICT (key_id, bucket, model, provider) DO UPDATE SET
                     tokens_input       = usage_metering.tokens_input + EXCLUDED.tokens_input,
                     tokens_output      = usage_metering.tokens_output + EXCLUDED.tokens_output,
                     tokens_cache_read  = usage_metering.tokens_cache_read + EXCLUDED.tokens_cache_read,
                     tokens_cache_write = usage_metering.tokens_cache_write + EXCLUDED.tokens_cache_write,
                     requests           = usage_metering.requests + EXCLUDED.requests,
                     billable_requests  = usage_metering.billable_requests + EXCLUDED.billable_requests",
                &[
                    &d.key_id, &bucket, &d.model, &d.provider, &ti, &to, &tcr, &tcw, &requests,
                    &brequests, &d.key_group_at_use, &d.pricing_version,
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
                    tokens_input, tokens_output, tokens_cache_read, tokens_cache_write,
                    requests, billable_requests, key_group_at_use, pricing_version
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
                tokens_cache_write: read_u64(r.get::<_, i64>(6)),
                requests: read_u64(r.get::<_, i64>(7)),
                billable_requests: read_u64(r.get::<_, i64>(8)),
                key_group_at_use: r.get(9),
                pricing_version: r.get(10),
            })
            .collect())
    }

    fn purge_windows_before(&self, before: u64) -> StoreResult<u64> {
        let b = clamp(before);
        let mut client = self.lock();
        let mut tx = client.transaction().store()?;
        let n1 = tx
            .execute("DELETE FROM usage_windows WHERE window_start < $1", &[&b])
            .store()?;
        tx.execute("DELETE FROM usage_ledger WHERE window_start < $1", &[&b])
            .store()?;
        tx.commit().store()?;
        Ok(n1)
    }

    fn purge_metering_before(&self, bucket: &str) -> StoreResult<u64> {
        // The trait's purge_metering_before takes `bucket: &str` while list_metering/add_metering
        // use `bucket: u64` -- an inconsistency in the core trait itself, not introduced here.
        // usage_metering.bucket is genuinely BIGINT, so this parses the string form.
        let b: i64 = bucket.parse().map_err(|_| {
            StoreError(format!(
                "purge_metering_before: invalid bucket {bucket:?}, expected an integer"
            ))
        })?;
        let n = self
            .lock()
            .execute("DELETE FROM usage_metering WHERE bucket=$1", &[&b])
            .store()?;
        Ok(n)
    }

    fn put_credential(&self, secret: &CredentialSecret) -> StoreResult<()> {
        let mut client = self.lock();
        let mut tx = client.transaction().store()?;
        Self::put_credential_tx(&mut tx, secret)?;
        tx.commit().store()?;
        Ok(())
    }

    fn put_key_with_credential(
        &self,
        key: &VirtualKey,
        secret: &CredentialSecret,
    ) -> StoreResult<()> {
        // ATOMIC mint: the bearer key and its credential commit together or not at all.
        let pools = pools_to_storage(&key.allowed_scopes);
        let labels = labels_to_storage(&key.labels);
        let created = clamp(key.created_at);
        let expires = key.expires_at.map(clamp);
        let mut client = self.lock();
        let mut tx = client.transaction().store()?;
        let rev = Self::next_revision(&mut tx)?;
        tx.execute(
            "INSERT INTO keys
                (id,generation_hash,name,allowed_pools,enabled,created_at,key_group,labels,expires_at,deleted_at,revision)
             VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,NULL,$10)
             ON CONFLICT (id) DO UPDATE SET
                generation_hash=EXCLUDED.generation_hash, name=EXCLUDED.name,
                allowed_pools=EXCLUDED.allowed_pools, enabled=EXCLUDED.enabled,
                key_group=EXCLUDED.key_group, labels=EXCLUDED.labels,
                expires_at=EXCLUDED.expires_at, deleted_at=NULL, revision=EXCLUDED.revision",
            &[
                &key.id, &key.generation_hash, &key.name, &pools, &key.enabled, &created,
                &key.group, &labels, &expires, &rev,
            ],
        )
        .store()?;
        Self::put_credential_tx(&mut tx, secret)?;
        tx.commit().store()?;
        Ok(())
    }

    fn list_credentials(&self, key_id: &str) -> StoreResult<Vec<CredentialMeta>> {
        let sql = format!("SELECT {CRED_META_COLUMNS} FROM credentials WHERE key_id=$1");
        let rows = self.lock().query(&sql, &[&key_id]).store()?;
        Ok(rows.iter().map(row_to_cred_meta).collect())
    }

    fn lookup_credential_secret(
        &self,
        kind: &str,
        public_id: &str,
    ) -> StoreResult<Option<CredentialSecret>> {
        let sql = format!(
            "SELECT {CRED_META_COLUMNS},secret FROM credentials WHERE kind=$1 AND public_id=$2"
        );
        let row = self.lock().query_opt(&sql, &[&kind, &public_id]).store()?;
        Ok(row.map(|r| CredentialSecret {
            meta: row_to_cred_meta(&r),
            secret: r
                .get::<_, Option<String>>(CRED_SECRET_COLUMN_INDEX)
                .unwrap_or_default(),
        }))
    }

    fn revoke_credential(&self, id: &str, reason: &str) -> StoreResult<()> {
        let mut client = self.lock();
        let mut tx = client.transaction().store()?;
        let exists: bool = tx
            .query_one(
                "SELECT EXISTS(SELECT 1 FROM credentials WHERE id=$1)",
                &[&id],
            )
            .store()?
            .get(0);
        if !exists {
            // Idempotent per the trait doc.
            tx.commit().store()?;
            return Ok(());
        }
        let rev = Self::next_revision(&mut tx)?;
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        // `AND revoked_at IS NULL`: mirrors delete_key's `already_deleted` idempotency (see above) --
        // a repeat revoke_credential call on an already-revoked row must be a true no-op, not bump
        // the global revision / rewrite revoke_reason+updated_at every time it's called. Stated IN
        // the UPDATE's own WHERE clause (not just the `exists` SELECT above) so this is also
        // TOCTOU-safe: two concurrent revoke_credential calls on the same id now genuinely
        // serialize under Postgres' READ COMMITTED row-lock re-check, and only the first to commit
        // actually changes anything.
        // Return value intentionally unread: whether this call or a concurrent winner actually
        // changed the row, the outcome is the same idempotent success -- matching delete_key's
        // shape. `next_revision`'s bump above going unused in the losing case is acceptable per its
        // own doc (a monotonic counter with gaps).
        tx.execute(
            "UPDATE credentials SET revoked_at=$2, revoke_reason=$3, updated_at=$2, revision=$4
             WHERE id=$1 AND revoked_at IS NULL",
            &[&id, &clamp(now), &reason, &rev],
        )
        .store()?;
        tx.commit().store()?;
        Ok(())
    }

    fn list_credentials_since(&self, since: u64) -> StoreResult<Vec<CredentialSecret>> {
        let sql = format!(
            "SELECT {CRED_META_COLUMNS},secret FROM credentials WHERE revision > $1 ORDER BY revision"
        );
        let rows = self.lock().query(&sql, &[&clamp(since)]).store()?;
        Ok(rows
            .iter()
            .map(|r| CredentialSecret {
                meta: row_to_cred_meta(r),
                secret: r
                    .get::<_, Option<String>>(CRED_SECRET_COLUMN_INDEX)
                    .unwrap_or_default(),
            })
            .collect())
    }

    fn append_audit(&self, entry: &AuditRecord) -> StoreResult<()> {
        let (seq, ts) = (clamp(entry.seq), clamp(entry.ts));
        // ON CONFLICT DO NOTHING, not DO UPDATE: the trait's own contract is "append-only... a store
        // never rewrites or recomputes the digest" (busbar_api::Store::append_audit doc). `seq` is a
        // per-process counter (see the engine's own known caveat about clustered nodes), so a
        // collision here means either a real caller bug or two nodes racing on the same seq -- in
        // BOTH cases silently overwriting a prior entry's hash/prev_hash would corrupt the hash chain
        // without any trace. Failing loudly on a collision is strictly safer than the alternative:
        // the caller (or an operator) finds out immediately, instead of the audit log quietly losing
        // integrity guarantees it claims to hold.
        let inserted = self
            .lock()
            .execute(
                "INSERT INTO audit_log
                    (seq, ts, action, resource, outcome, principal, prev_hash, hash)
                 VALUES ($1,$2,$3,$4,$5,$6,$7,$8)
                 ON CONFLICT (seq) DO NOTHING",
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
        if inserted == 0 {
            return Err(StoreError(format!(
                "append_audit: seq {} already exists in audit_log; refusing to silently overwrite \
                 a durable audit entry (the append-only contract forbids rewriting a prior hash)",
                entry.seq
            )));
        }
        Ok(())
    }

    fn list_audit(&self) -> StoreResult<Vec<AuditRecord>> {
        let sql = format!("SELECT {AUDIT_COLUMNS} FROM audit_log ORDER BY seq");
        let rows = self.lock().query(&sql, &[]).store()?;
        Ok(rows.iter().map(row_to_audit).collect())
    }

    fn list_audit_tail(&self, limit: u64) -> StoreResult<Vec<AuditRecord>> {
        let sql = format!("SELECT {AUDIT_COLUMNS} FROM audit_log ORDER BY seq DESC LIMIT $1");
        let rows = self
            .lock()
            .query(&sql, &[&i64::try_from(limit).unwrap_or(i64::MAX)])
            .store()?;
        let mut out: Vec<AuditRecord> = rows.iter().map(row_to_audit).collect();
        out.reverse();
        Ok(out)
    }

    fn add_denylist(&self, sub: &str, reason: &str) -> StoreResult<()> {
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

const AUDIT_COLUMNS: &str = "seq, ts, action, resource, outcome, principal, prev_hash, hash";

fn row_to_audit(r: &Row) -> AuditRecord {
    AuditRecord {
        seq: read_u64(r.get::<_, i64>(0)),
        ts: read_u64(r.get::<_, i64>(1)),
        action: r.get(2),
        resource: r.get(3),
        outcome: r.get(4),
        principal: r.get(5),
        prev_hash: r.get(6),
        hash: r.get(7),
    }
}

impl PostgresStore {
    /// Shared body of `put_credential`/`put_key_with_credential`: upsert on `(key_id, kind, slot)`.
    /// Minting into an OCCUPIED LIVE slot (revoked_at IS NULL) MUST fail rather than silently
    /// destroy a working credential mid-overlap-window -- the `WHERE credentials.revoked_at IS NOT
    /// NULL` guard on the `DO UPDATE` makes that structural: the upsert simply does not apply if
    /// the existing row is live, and the subsequent `changed` check turns that into a real error
    /// instead of a silent no-op.
    fn put_credential_tx(tx: &mut Transaction<'_>, secret: &CredentialSecret) -> StoreResult<()> {
        let m = &secret.meta;
        let rev = Self::next_revision(tx)?;
        let form = secret_form_to_storage(m.secret_form);
        let secret_val = if m.secret_form == SecretForm::None {
            None
        } else {
            Some(secret.secret.as_str())
        };
        let expires = m.expires_at.map(clamp);
        let changed = tx
            .execute(
                "INSERT INTO credentials
                    (id,key_id,kind,slot,public_id,secret,secret_form,created_at,updated_at,expires_at,revoked_at,revoke_reason,revision)
                 VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,NULL,NULL,$11)
                 ON CONFLICT (key_id, kind, slot) DO UPDATE SET
                    id=EXCLUDED.id, public_id=EXCLUDED.public_id, secret=EXCLUDED.secret,
                    secret_form=EXCLUDED.secret_form, updated_at=EXCLUDED.updated_at,
                    expires_at=EXCLUDED.expires_at, revoked_at=NULL, revoke_reason=NULL,
                    revision=EXCLUDED.revision
                 WHERE credentials.revoked_at IS NOT NULL",
                &[
                    &m.id,
                    &m.key_id,
                    &m.kind,
                    &(m.slot as i16),
                    &m.public_id,
                    &secret_val,
                    &form,
                    &clamp(m.created_at),
                    &clamp(m.updated_at),
                    &expires,
                    &rev,
                ],
            )
            .store()?;
        if changed == 0 {
            // Either the slot is occupied by a LIVE credential (the WHERE guard blocked it), or this
            // is a genuine first insert into a free slot that the ON CONFLICT branch didn't need --
            // distinguish by checking existence.
            let exists: bool = tx
                .query_one(
                    "SELECT EXISTS(SELECT 1 FROM credentials WHERE key_id=$1 AND kind=$2 AND slot=$3)",
                    &[&m.key_id, &m.kind, &(m.slot as i16)],
                )
                .store()?
                .get(0);
            if exists {
                return Err(StoreError(format!(
                    "put_credential: slot {} for key {} kind {} holds a LIVE credential; revoke it first",
                    m.slot, m.key_id, m.kind
                )));
            }
            // Free slot, first insert -- the INSERT branch of the upsert should have applied. If we
            // get here with changed==0 and no existing row, something else rejected the write (e.g.
            // a UNIQUE(kind, public_id) violation on a DIFFERENT key/slot) -- surface plainly.
            return Err(StoreError(
                "put_credential: insert did not apply (public_id may already be in use by another credential)".to_string(),
            ));
        }
        Ok(())
    }
}

const _: fn() = || {
    fn assert_tosql<T: ToSql>() {}
    assert_tosql::<i64>();
    assert_tosql::<Option<i64>>();
    assert_tosql::<bool>();
};

#[cfg(test)]
mod tests;
