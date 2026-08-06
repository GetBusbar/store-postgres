// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Unit tests for the Postgres store (schema v5, generic credentials): DSN-password scrubbing plus
//! (gated on `BUSBAR_TEST_POSTGRES_URL`) real round-trip and invariant coverage against a live
//! `postgres:16`.

use super::*;
use busbar_api::{CredentialMeta, CredentialSecret, ModelTokensDelta, SecretForm, TierTokensDelta};

/// Drift guard, no live DB needed: `CRED_SECRET_COLUMN_INDEX` must stay in sync with
/// `CRED_META_COLUMNS`' own column count, since `str::split` isn't const-evaluable and the constant
/// is hand-maintained. Catches the class of bug where a column is added/removed from
/// CRED_META_COLUMNS without updating the index every `secret` read relies on.
#[test]
fn cred_secret_column_index_matches_cred_meta_columns_count() {
    assert_eq!(
        CRED_META_COLUMNS.split(',').count(),
        CRED_SECRET_COLUMN_INDEX,
        "CRED_SECRET_COLUMN_INDEX must equal CRED_META_COLUMNS' column count -- update it if you \
         changed CRED_META_COLUMNS"
    );
}

/// A connect-error string must never leak the DSN password.
#[test]
fn dsn_password_extraction_and_scrub() {
    assert_eq!(
        dsn_password("postgres://user:s3cr3t@host:5432/db").as_deref(),
        Some("s3cr3t")
    );
    assert_eq!(
        dsn_password("postgresql://u:p%40ss@host/db").as_deref(),
        Some("p%40ss")
    );
    assert_eq!(
        dsn_password("host=db user=u password=kwsecret dbname=x").as_deref(),
        Some("kwsecret")
    );
    assert_eq!(dsn_password("postgres://host:5432/db"), None);
    assert_eq!(dsn_password("host=db user=u"), None);

    let raw = dsn_password("postgresql://u:p%40ss@host/db").unwrap();
    let leak = "could not connect: postgresql://u:p%40ss@host/db (auth p@ss)".to_string();
    let s = scrub(leak, Some(&raw));
    assert!(
        !s.contains("p%40ss") && !s.contains("p@ss") && s.contains("<redacted>"),
        "both raw and decoded password forms must be scrubbed; got {s}"
    );
    assert_eq!(scrub("plain".into(), None), "plain");
    assert_eq!(percent_decode("p%40ss"), "p@ss");
    assert_eq!(percent_decode("bad%zz"), "bad%zz");
}

fn live_url() -> Option<String> {
    match std::env::var("BUSBAR_TEST_POSTGRES_URL") {
        Ok(url) => Some(url),
        Err(_) if std::env::var_os("CI").is_some() => {
            panic!(
                "BUSBAR_TEST_POSTGRES_URL is unset under CI: the Postgres service container must \
                 provision it. Refusing to silently skip the only live-DB coverage in CI."
            );
        }
        Err(_) => {
            eprintln!("skip: set BUSBAR_TEST_POSTGRES_URL to run the live Postgres tests");
            None
        }
    }
}

/// Open a raw `postgres::Client` with bounded retry-with-backoff. Used only where a test genuinely
/// needs a SECOND connection independent of the store's (e.g. holding a REPEATABLE READ snapshot
/// open on one connection while the store writes on its own) -- there the connection cannot be
/// reused away. Under the core gate's parallel-test load against a shared Postgres, a single
/// `Client::connect` can be transiently refused on connection pressure; retrying a handful of times
/// over a few seconds absorbs that transient without weakening any isolation assertion. ~10 tries
/// over ~2.5s total, then the last error surfaces as before.
fn connect_client_with_retry(url: &str) -> postgres::Client {
    let mut last_err = None;
    for attempt in 0..10u32 {
        match postgres::Client::connect(url, postgres::NoTls) {
            Ok(c) => return c,
            Err(e) => {
                last_err = Some(e);
                std::thread::sleep(std::time::Duration::from_millis(50 * (attempt as u64 + 1)));
            }
        }
    }
    panic!("connect (after retries): {:?}", last_err.unwrap());
}

/// `PostgresStore::connect` with bounded retry-with-backoff. Each connect opens a fresh connection
/// AND runs `migrate()`, so under the core gate's parallel-test load against a shared Postgres a
/// single connect can be TRANSIENTLY refused when the server is momentarily at its connection
/// ceiling (surfacing as `StoreError("db error")` / too-many-clients) -- the exact class of flake
/// the gate hit on the isolation test's connect. Every live-DB test needs at least this one store
/// connection, so footprint reduction alone can't harden the primary connect; retrying ~10 times
/// over a couple of seconds absorbs the transient. Returns the same `StoreResult` `connect` does, so
/// each caller keeps its own `.expect(...)` message. NOT used where a connect is EXPECTED to fail
/// (the permission test asserts `.is_err()` directly and must not spin on a genuine, persistent
/// error).
fn connect_store_with_retry(url: &str) -> StoreResult<PostgresStore> {
    let mut last_err = None;
    for attempt in 0..10u32 {
        if attempt > 0 {
            std::thread::sleep(std::time::Duration::from_millis(50 * attempt as u64));
        }
        match PostgresStore::connect(url) {
            Ok(store) => return Ok(store),
            Err(e) => last_err = Some(e),
        }
    }
    Err(last_err.expect("loop ran at least once"))
}

/// TRUE reset for test isolation -- unlike `delete_key` (a deliberate tombstone that can never fully
/// reset a row by design), this raw-SQL wipe gives each test a genuinely clean slate for its id, so
/// re-running the suite (or running it twice in a row) never sees stale state
/// from a prior run leaking into the CHECK constraints (e.g. re-minting into a row still marked
/// `deleted_at` from a previous run's tombstone would violate `keys_tombstone_disabled`).
fn hard_reset(store: &PostgresStore, id: &str) {
    let mut client = store.lock();
    let _ = client.execute("DELETE FROM credentials WHERE key_id=$1", &[&id]);
    let _ = client.execute("DELETE FROM keys WHERE id=$1", &[&id]);
    let _ = client.execute("DELETE FROM usage_metering WHERE key_id=$1", &[&id]);
    let _ = client.execute("DELETE FROM usage_windows WHERE bucket_id=$1", &[&id]);
    let _ = client.execute("DELETE FROM usage_ledger WHERE bucket_id=$1", &[&id]);
}

fn sample_key(id: &str) -> VirtualKey {
    VirtualKey {
        id: id.into(),
        generation_hash: "binding:x:g1".into(),
        name: "k".into(),
        allowed_scopes: None,
        enabled: true,
        created_at: 100,
        group: None,
        labels: Default::default(),
        expires_at: None,
        deleted_at: None,
        revision: 0,
    }
}

fn sample_cred(key_id: &str, slot: u8, public_id: &str) -> CredentialSecret {
    CredentialSecret {
        meta: CredentialMeta {
            id: format!("cred_{public_id}"),
            key_id: key_id.into(),
            kind: "sigv4".into(),
            slot,
            public_id: public_id.into(),
            secret_form: SecretForm::Recoverable,
            created_at: 100,
            updated_at: 100,
            expires_at: None,
            revoked_at: None,
            revoke_reason: None,
            revision: 0,
        },
        secret: "v1:plain:supersecret".into(),
    }
}

/// Basic key round-trip, including the new fields (generation_hash, expires_at, deleted_at,
/// revision) and the allowed_pools NULL-vs-'[]' distinction.
#[test]
fn key_roundtrip_new_fields() {
    let Some(url) = live_url() else { return };
    let store = connect_store_with_retry(&url).expect("connect");
    hard_reset(&store, "vk_rt1");
    hard_reset(&store, "vk_rt2");

    let mut k = sample_key("vk_rt1");
    k.expires_at = Some(999);
    k.allowed_scopes = Some(vec![]); // explicit empty grant, must NOT read back as None
    store.put_key(&k).unwrap();
    let back = store.get_key("vk_rt1").unwrap().unwrap();
    assert_eq!(back.generation_hash, "binding:x:g1");
    assert_eq!(back.expires_at, Some(999));
    assert_eq!(back.deleted_at, None);
    assert_eq!(
        back.allowed_scopes,
        Some(vec![]),
        "explicit empty grant must round-trip as Some([]), not None"
    );
    assert!(back.revision > 0, "put_key must stamp a nonzero revision");

    let mut k2 = sample_key("vk_rt2");
    k2.allowed_scopes = None; // omitted grant = all pools
    store.put_key(&k2).unwrap();
    let back2 = store.get_key("vk_rt2").unwrap().unwrap();
    assert_eq!(
        back2.allowed_scopes, None,
        "omitted grant must round-trip as None, not Some([])"
    );
}

/// THE core invariant: delete_key is a TOMBSTONE. The row survives (deleted_at set, enabled=false),
/// every credential is destroyed, and usage_metering (which FKs nothing here but conceptually
/// depends on key_id resolving) still finds the key by id afterward.
#[test]
fn delete_key_is_a_tombstone_not_a_hard_delete() {
    let Some(url) = live_url() else { return };
    let store = connect_store_with_retry(&url).expect("connect");
    let id = "vk_tombstone1";
    hard_reset(&store, id);

    let key = sample_key(id);
    let cred = sample_cred(id, 0, "AKIA_TOMBSTONE1");
    store.put_key_with_credential(&key, &cred).unwrap();
    assert_eq!(store.list_credentials(id).unwrap().len(), 1);

    store.delete_key(id).unwrap();

    // The assertions below only pass if delete_key genuinely tombstones rather than hard-deletes:
    // with delete_key reduced to `DELETE FROM keys WHERE id=$1`, get_key(id) returns None and the
    // very first assertion fails.
    let after = store.get_key(id).unwrap();
    assert!(
        after.is_some(),
        "the keys row must survive a delete_key call (tombstone, not hard delete)"
    );
    let after = after.unwrap();
    assert!(!after.is_live(), "is_live() must be false once tombstoned");
    assert!(!after.enabled, "enabled must be forced false");
    assert!(after.deleted_at.is_some(), "deleted_at must be set");

    let creds = store.list_credentials(id).unwrap();
    assert!(
        creds.is_empty(),
        "every credential row for the key must be destroyed on delete"
    );

    // Idempotent: deleting again is a no-op, not an error, and does not bump deleted_at.
    let deleted_at_first = after.deleted_at;
    store.delete_key(id).unwrap();
    let after2 = store.get_key(id).unwrap().unwrap();
    assert_eq!(
        after2.deleted_at, deleted_at_first,
        "a repeat delete must not change deleted_at"
    );
}

/// `delete_key` must stamp `deleted_at` with a WALL-CLOCK time, not with the store-global revision
/// counter. The two are both BIGINTs bound in the same statement, so binding the revision to both
/// `deleted_at` and `revision` type-checks, round-trips, and satisfies every "is the key
/// tombstoned" assertion elsewhere in this file -- while reporting that every key in the store was
/// deleted a few seconds after the epoch. Bracketing the call with real clock reads is the only
/// assertion that can tell the two apart: a revision counter is a small integer and can never fall
/// inside a window of the current Unix time.
#[test]
fn delete_key_stamps_deleted_at_with_a_wall_clock_time_not_the_revision() {
    let Some(url) = live_url() else { return };
    let store = connect_store_with_retry(&url).expect("connect");
    let id = "vk_deleted_at_clock1";
    hard_reset(&store, id);
    store.put_key(&sample_key(id)).unwrap();

    let before = now_secs();
    store.delete_key(id).unwrap();
    let after = now_secs();

    let deleted_at = store
        .get_key(id)
        .unwrap()
        .unwrap()
        .deleted_at
        .expect("delete_key must set deleted_at");
    assert!(
        deleted_at >= before && deleted_at <= after,
        "deleted_at must be the wall-clock second the delete landed (expected {before}..={after}), \
         got {deleted_at} -- a value far below the current Unix time means the revision counter was \
         bound to this column instead of a clock read"
    );
}

/// put_key_with_credential's ON CONFLICT path must clear a stale tombstone: re-minting over an id
/// that was previously deleted (deleted_at set, enabled=false by delete_key) must produce a fully
/// LIVE key, not one that is enabled=true while still marked deleted_at.
///
/// An ON CONFLICT UPDATE SET clause that omits `deleted_at=NULL` fails at the `deleted_at`
/// assertion below: `enabled` flips to `true` as the caller intended, but `deleted_at` is left at
/// whatever the tombstone set it to, so the row is simultaneously "enabled" and "deleted" -- exactly
/// the corrupt state this test guards against.
#[test]
fn put_key_with_credential_on_conflict_clears_a_stale_tombstone() {
    let Some(url) = live_url() else { return };
    let store = connect_store_with_retry(&url).expect("connect");
    let id = "vk_remint_over_tombstone1";
    hard_reset(&store, id);

    let key = sample_key(id);
    let cred = sample_cred(id, 0, "AKIA_REMINT1");
    store.put_key_with_credential(&key, &cred).unwrap();
    store.delete_key(id).unwrap();
    let tombstoned = store.get_key(id).unwrap().unwrap();
    assert!(tombstoned.deleted_at.is_some(), "precondition: tombstoned");
    assert!(!tombstoned.enabled, "precondition: disabled");

    // Re-mint over the same id: a fresh VirtualKey with enabled=true and no deleted_at, atomically
    // paired with a fresh credential, exactly like an operator re-issuing a revoked key.
    let mut remint = sample_key(id);
    remint.enabled = true;
    remint.deleted_at = None;
    let remint_cred = sample_cred(id, 0, "AKIA_REMINT1_NEW");
    store
        .put_key_with_credential(&remint, &remint_cred)
        .expect("re-mint over a tombstoned id must succeed, not violate keys_tombstone_disabled");

    let after = store.get_key(id).unwrap().unwrap();
    assert!(after.enabled, "the re-minted key must be enabled");
    assert!(
        after.deleted_at.is_none(),
        "the re-minted key must have its stale tombstone cleared, not be simultaneously enabled \
         and deleted: got deleted_at={:?}",
        after.deleted_at
    );
    assert_eq!(
        store.list_credentials(id).unwrap().len(),
        1,
        "the re-minted credential must be present"
    );
}

/// scrub_key: PII-erasure only, requires the key to already be tombstoned.
#[test]
fn scrub_key_requires_tombstone_first() {
    let Some(url) = live_url() else { return };
    let store = connect_store_with_retry(&url).expect("connect");
    let id = "vk_scrub1";
    hard_reset(&store, id);

    let mut key = sample_key(id);
    key.name = "Real Name".into();
    key.labels.insert("team".into(), "growth".into());
    store.put_key(&key).unwrap();

    // Scrubbing a LIVE key must fail.
    assert!(
        store.scrub_key(id).is_err(),
        "scrubbing a live key must be rejected"
    );

    store.delete_key(id).unwrap();
    store.scrub_key(id).unwrap();
    let scrubbed = store.get_key(id).unwrap().unwrap();
    assert_eq!(scrubbed.name, "");
    assert!(scrubbed.labels.is_empty());
    assert!(!scrubbed.is_live(), "scrub must not resurrect the key");
}

/// Credential minting is slot-safe: minting into a slot holding a LIVE credential must fail, not
/// silently clobber it. Minting into a REVOKED slot (or a free one) must succeed.
#[test]
fn credential_slot_guard_rejects_clobbering_a_live_credential() {
    let Some(url) = live_url() else { return };
    let store = connect_store_with_retry(&url).expect("connect");
    let id = "vk_slotguard1";
    hard_reset(&store, id);
    store.put_key(&sample_key(id)).unwrap();

    let c0 = sample_cred(id, 0, "AKIA_SLOT0_A");
    store.put_credential(&c0).unwrap();

    // Same slot, different public_id, while c0 is still LIVE -- must be rejected.
    let c0b = sample_cred(id, 0, "AKIA_SLOT0_B");
    let err = store.put_credential(&c0b);
    assert!(err.is_err(), "minting into an occupied LIVE slot must fail");
    // The original credential must be untouched.
    let live = store
        .lookup_credential_secret("sigv4", "AKIA_SLOT0_A")
        .unwrap();
    assert!(
        live.is_some(),
        "the original live credential must survive a rejected clobber attempt"
    );

    // Slot 1 is free -- overlap-window rotation must succeed.
    let c1 = sample_cred(id, 1, "AKIA_SLOT1_A");
    store.put_credential(&c1).unwrap();
    assert_eq!(store.list_credentials(id).unwrap().len(), 2);

    // Revoke slot 0, then re-minting into it must succeed (revoked slots are reusable).
    let cred0_id = c0.meta.id.clone();
    store.revoke_credential(&cred0_id, "rotated").unwrap();
    let c0c = sample_cred(id, 0, "AKIA_SLOT0_C");
    store.put_credential(&c0c).unwrap();
    let resolved = store
        .lookup_credential_secret("sigv4", "AKIA_SLOT0_C")
        .unwrap()
        .expect("re-mint into a revoked slot must succeed");
    assert_eq!(resolved.meta.slot, 0);
}

/// put_credential_tx must bind CredentialMeta::updated_at to its own column, not silently reuse
/// created_at's parameter for both.
///
/// A `VALUES ...,$8,$8,$9,...` binding -- created_at's placeholder used twice, with `updated_at`
/// never bound at all -- fails here: the round-tripped `updated_at` comes back equal to `created_at`
/// (100) instead of the distinct value (200) this test mints with.
#[test]
fn put_credential_binds_updated_at_to_its_own_column_not_created_at() {
    let Some(url) = live_url() else { return };
    let store = connect_store_with_retry(&url).expect("connect");
    let id = "vk_updated_at1";
    hard_reset(&store, id);
    store.put_key(&sample_key(id)).unwrap();

    let mut cred = sample_cred(id, 0, "AKIA_UPDATEDAT1");
    cred.meta.created_at = 100;
    cred.meta.updated_at = 200;
    store.put_credential(&cred).unwrap();

    let got = store
        .list_credentials(id)
        .unwrap()
        .into_iter()
        .find(|m| m.public_id == "AKIA_UPDATEDAT1")
        .expect("the minted credential must be listed");
    assert_eq!(got.created_at, 100, "created_at must round-trip untouched");
    assert_eq!(
        got.updated_at, 200,
        "updated_at must round-trip as its own distinct value, not be silently overwritten by \
         created_at's"
    );
}

/// revoke_credential kills ONE credential independent of the key: the key stays enabled, the OTHER
/// slot's credential stays live, only the targeted one is revoked. This is the plugin-level half of
/// the fan-out fix the core redesign exists for (the orchestration itself lives in GovState::revoke,
/// but it depends on this method actually working).
#[test]
fn revoke_credential_is_independent_of_the_key_and_other_slots() {
    let Some(url) = live_url() else { return };
    let store = connect_store_with_retry(&url).expect("connect");
    let id = "vk_revoke1";
    hard_reset(&store, id);
    store.put_key(&sample_key(id)).unwrap();
    let c0 = sample_cred(id, 0, "AKIA_REVOKE1_A");
    let c1 = sample_cred(id, 1, "AKIA_REVOKE1_B");
    store.put_credential(&c0).unwrap();
    store.put_credential(&c1).unwrap();

    store.revoke_credential(&c0.meta.id, "leaked").unwrap();

    let key = store.get_key(id).unwrap().unwrap();
    assert!(
        key.enabled,
        "revoking a credential must not touch the key's enabled flag"
    );
    assert!(key.is_live());

    let creds = store.list_credentials(id).unwrap();
    let meta0 = creds.iter().find(|c| c.id == c0.meta.id).unwrap();
    let meta1 = creds.iter().find(|c| c.id == c1.meta.id).unwrap();
    assert!(
        meta0.revoked_at.is_some(),
        "the targeted credential must be revoked"
    );
    assert!(
        meta1.revoked_at.is_none(),
        "the OTHER slot's credential must be untouched"
    );

    // The VERIFY path, not just the admin listing: `lookup_credential_secret` still resolves the
    // row (the trait reserves `None` for an unknown `(kind, public_id)` pair, so hiding a revoked
    // row here would make a revoked secret indistinguishable from a typo'd one), which is exactly
    // why the revocation has to be visible ON the row it returns. Asserted as a positive fact about
    // what the verify path hands back: an `is_none() || !is_live()` disjunction cannot fail once
    // `revoked_at.is_some()` has been asserted above, so it would pass no matter what this lookup
    // returned.
    let resolved = store
        .lookup_credential_secret("sigv4", "AKIA_REVOKE1_A")
        .unwrap()
        .expect("the verify path must still resolve a revoked credential, not report it unknown");
    assert!(
        resolved.meta.revoked_at.is_some(),
        "the credential the verify path resolves must carry the revocation, or every caller's \
         liveness check admits a revoked secret"
    );
    assert!(
        !resolved.meta.is_live(0),
        "a revoked credential must never read as live on the verify path"
    );

    // Idempotent.
    store
        .revoke_credential(&c0.meta.id, "leaked again")
        .unwrap();
}

/// `revoke_credential` must FAIL LOUD on a credential id that does not exist, rather than reporting
/// a successful revocation of nothing. The trait's own doc defaults this method to a loud error
/// precisely because "a silent no-op here would let an operator believe a leaked SigV4 secret was
/// killed when it was not"; the idempotency it also promises is about an ALREADY-REVOKED row, which
/// the second half of this test pins as still being a no-op success.
///
/// The unknown-id case is reachable in ordinary operation, not just from a typo: minting into a
/// revoked slot rewrites that row's primary key (`id=EXCLUDED.id`), so an id handed out by an
/// earlier `list_credentials` can stop naming any row while a caller is still working through the
/// list.
#[test]
fn revoke_credential_errors_on_an_unknown_id_but_stays_idempotent_on_a_revoked_one() {
    let Some(url) = live_url() else { return };
    let store = connect_store_with_retry(&url).expect("connect");
    let id = "vk_revoke_unknown1";
    hard_reset(&store, id);
    store.put_key(&sample_key(id)).unwrap();

    let err = store
        .revoke_credential("cred_this_id_was_never_minted", "leaked")
        .expect_err("revoking an id that names no row must be an error, not a reported success");
    assert!(
        err.0.contains("cred_this_id_was_never_minted"),
        "the error should name the id that could not be revoked: {}",
        err.0
    );

    // The idempotent half: a real credential revoked twice succeeds both times.
    let cred = sample_cred(id, 0, "AKIA_REVOKE_UNKNOWN1");
    store.put_credential(&cred).unwrap();
    store.revoke_credential(&cred.meta.id, "leaked").unwrap();
    store
        .revoke_credential(&cred.meta.id, "leaked again")
        .expect("re-revoking an already-revoked credential must stay a no-op success");
}

/// HYDRATION-DELTA SOUNDNESS, the same invariant the SQLite and MySQL schemas have to hold. A
/// revision-based delta
/// consumer polling list_keys_since/list_credentials_since must be able to observe a delete_key
/// tombstone AND infer the credential deletion from it, because the credential rows are hard-deleted
/// and produce no delta of their own.
#[test]
fn hydration_delta_makes_credential_deletion_observable_via_the_key_tombstone() {
    let Some(url) = live_url() else { return };
    let store = connect_store_with_retry(&url).expect("connect");
    let id = "vk_hydrate1";
    hard_reset(&store, id);

    let key = sample_key(id);
    let cred = sample_cred(id, 0, "AKIA_HYDRATE1");
    store.put_key_with_credential(&key, &cred).unwrap();

    // Establish a watermark AFTER the mint (so the delete is the only thing after it).
    let watermark = store.get_key(id).unwrap().unwrap().revision;

    store.delete_key(id).unwrap();

    let key_deltas = store.list_keys_since(watermark).unwrap();
    let tombstoned = key_deltas
        .iter()
        .find(|k| k.id == id)
        .expect("the tombstoned key MUST appear in the delta since the pre-delete watermark");
    assert!(
        !tombstoned.is_live(),
        "the delta must show the key as tombstoned"
    );

    // First confirm the credential is ACTUALLY gone -- without this, the "no delta" check below is
    // tautological: a credential that was simply left untouched by a broken delete_key would ALSO
    // produce zero deltas past the watermark (nothing ever wrote a new revision for it), making the
    // two cases indistinguishable to that assertion alone.
    assert!(
        store.list_credentials(id).unwrap().is_empty(),
        "delete_key must have hard-deleted the credential row for a correct baseline to compare \
         the delta behavior below against"
    );

    // The credential delta, by contrast, is NOT required to (and structurally cannot) show the
    // deletion -- this is the exact gap. A correct hydrator must react to the KEY delta's
    // deleted_at, not wait for a credential delta that will never come.
    let cred_deltas = store.list_credentials_since(watermark).unwrap();
    assert!(
        cred_deltas.iter().all(|c| c.meta.key_id != id),
        "a hard-deleted credential produces no further delta -- this is the documented gap the \
         consumer-side contract (see Store::list_credentials_since's doc) exists to close"
    );
}

/// A concurrent-instance race: two independent connections both try to delete the same key. Exactly
/// one does the real work; both must return Ok (idempotent), and the final state must be a single,
/// consistent tombstone -- not a partial/interleaved one.
#[test]
fn concurrent_delete_of_the_same_key_is_safe_and_idempotent() {
    let Some(url) = live_url() else { return };
    let store_a = connect_store_with_retry(&url).expect("connect a");
    let store_b = connect_store_with_retry(&url).expect("connect b");
    let id = "vk_concurrent_del1";
    hard_reset(&store_a, id);
    store_a.put_key(&sample_key(id)).unwrap();
    let cred = sample_cred(id, 0, "AKIA_CONCURRENT1");
    store_a.put_credential(&cred).unwrap();

    let url_b = url.clone();
    let id_b = id.to_string();
    let handle = std::thread::spawn(move || {
        let store_b2 = connect_store_with_retry(&url_b).expect("connect b2");
        store_b2.delete_key(&id_b)
    });
    let r1 = store_b.delete_key(id);
    let r2 = handle.join().unwrap();
    assert!(
        r1.is_ok() && r2.is_ok(),
        "both concurrent deletes must succeed (idempotent), got {r1:?} / {r2:?}"
    );

    let after = store_a.get_key(id).unwrap().unwrap();
    assert!(!after.is_live());
    assert!(store_a.list_credentials(id).unwrap().is_empty());
}

/// get_usage's REPEATABLE READ helper must actually open that isolation level.
#[test]
fn get_usage_transaction_is_actually_repeatable_read() {
    let Some(url) = live_url() else { return };
    let store = connect_store_with_retry(&url).expect("connect");
    // Drive the isolation check through the store's OWN connection -- the exact same client
    // get_usage uses -- rather than opening a second raw `postgres::Client`. That extra, uncounted
    // connection was pure connection-footprint overhead here (this assertion never needed a
    // *separate* connection, only a real one), and under the core gate's parallel-test load against
    // a shared Postgres its `.connect()` transiently failed on connection pressure -- the observed
    // flake panicked at this test's connect path (`connect: StoreError("db error")`), never on the
    // isolation assertion below. Reusing the store's client (extending what b2f3804 did for the
    // sibling torn-read test) halves this test's connection count and removes the refuse-able
    // connect, while testing the real helper against a real client just as faithfully. The scope
    // guard releases the store lock before `get_usage` (which re-locks the same mutex) is called.
    let level: String = {
        let mut client = store.lock();
        let mut tx = PostgresStore::snapshot_consistent_tx(&mut client).unwrap();
        let level: String = tx
            .query_one("SHOW transaction_isolation", &[])
            .unwrap()
            .get(0);
        tx.commit().unwrap();
        level
    };
    assert_eq!(
        level, "repeatable read",
        "get_usage's helper must actually open REPEATABLE READ"
    );
    let got = store.get_usage("nonexistent_bucket", 0);
    assert!(got.is_ok(), "get_usage must still be callable: {got:?}");
}

/// THE actual torn-read proof the previous test's docstring used to promise but never ran: a
/// concurrent add_usage landing between get_usage's requests-row read and its model-rows read must
/// not be half-visible. Drives get_usage's own two-step read manually (its real SQL, via the same
/// `snapshot_consistent_tx` helper it uses internally) so a write can be deliberately interleaved
/// between the two steps on a SEPARATE connection, then asserts REPEATABLE READ's snapshot held: the
/// second read still sees the pre-interleave state, not the concurrent writer's new model row.
///
/// Non-vacuous: downgrading `snapshot_consistent_tx`'s isolation level to READ COMMITTED makes the
/// `model_count` assertion below fail, because the second read then observes the interleaved
/// writer's new model row.
#[test]
fn get_usage_snapshot_does_not_observe_a_concurrent_add_usage_between_its_two_reads() {
    let Some(url) = live_url() else { return };
    let store = connect_store_with_retry(&url).expect("connect");
    let bucket = "vk_torn_read1";
    let ws = 20_270_301u64;
    hard_reset(&store, bucket);
    let _ = store
        .lock()
        .execute("DELETE FROM usage_windows WHERE bucket_id=$1", &[&bucket]);
    let _ = store
        .lock()
        .execute("DELETE FROM usage_ledger WHERE bucket_id=$1", &[&bucket]);

    // Seed one model row so the "before" state is non-empty and distinguishable from "after".
    store
        .put_usage(
            bucket,
            ws,
            &UsageLedger {
                requests: 10,
                billable_requests: 10,
                models: vec![ModelTokens {
                    model: "seed-model".into(),
                    tokens: TierTokens {
                        input: 1,
                        output: 1,
                        cache_read: 0,
                        cache_write: 0,
                    },
                }],
            },
        )
        .unwrap();

    // Open the snapshot and take the FIRST of get_usage's two reads (the requests row) manually.
    // This SECOND connection is genuinely required (the snapshot must stay open here while `store`
    // writes on its own connection below), so it can't be reused away like the sibling isolation
    // test's -- instead its connect is bounded-retried to absorb transient connection-pressure
    // refusals under the gate's parallel load.
    let mut client = connect_client_with_retry(&url);
    let mut tx = PostgresStore::snapshot_consistent_tx(&mut client).unwrap();
    let _requests_row = tx
        .query_one(
            "SELECT requests, billable_requests FROM usage_windows WHERE bucket_id=$1 AND window_start=$2",
            &[&bucket, &clamp(ws)],
        )
        .unwrap();

    // Interleave: a SEPARATE connection commits an add_usage that adds a brand-new model row and
    // bumps requests, fully committed before this transaction's second read runs. `store` is already
    // an independent connection from the snapshot's `client` (a distinct `Client::connect` above) and
    // is idle here, so it IS the required separate writer -- reusing it (rather than opening a third
    // connection) keeps the interleave semantics identical while removing a connect()/migrate() that
    // could fail under a shared CI Postgres's connection pressure (the observed gate flake: the third
    // connect's `.expect` panicked, never the isolation assertion below).
    store
        .add_usage(
            bucket,
            ws,
            &UsageDelta {
                requests: 5,
                billable_requests: 5,
                models: vec![ModelTokensDelta {
                    model: "concurrent-writer-model".into(),
                    tokens: TierTokensDelta {
                        input: 1,
                        output: 1,
                        cache_read: 0,
                        cache_write: 0,
                    },
                }],
            },
        )
        .unwrap();

    // The SECOND read, same transaction/snapshot: under REPEATABLE READ this must still see only
    // the pre-interleave model row, not the concurrent writer's new one.
    let model_rows = tx
        .query(
            "SELECT model FROM usage_ledger WHERE bucket_id=$1 AND window_start=$2",
            &[&bucket, &clamp(ws)],
        )
        .unwrap();
    tx.commit().unwrap();

    let models: Vec<String> = model_rows.iter().map(|r| r.get(0)).collect();
    assert_eq!(
        models,
        vec!["seed-model".to_string()],
        "a REPEATABLE READ snapshot must not observe a model row committed by a concurrent \
         add_usage after this transaction began; observed: {models:?}"
    );

    // Sanity: the interleaved write DID land for a fresh read (proves it wasn't silently a no-op).
    let after = store.get_usage(bucket, ws).unwrap();
    assert_eq!(
        after.requests, 15,
        "the concurrent add_usage must have applied for a fresh read"
    );
    assert_eq!(
        after.models.len(),
        2,
        "both models must be present for a fresh read"
    );
}

/// usage_metering round-trip including the new fields (billable_requests, key_group_at_use,
/// pricing_version) and the renamed tokens_cache_write (was tokens_cache_creation).
#[test]
fn metering_roundtrip_new_fields() {
    let Some(url) = live_url() else { return };
    let store = connect_store_with_retry(&url).expect("connect");
    let bucket = 20_270_101u64;
    hard_reset(&store, "vk_meter_new1");
    store
        .add_metering(&busbar_api::MeteringDelta {
            key_id: "vk_meter_new1".into(),
            bucket,
            model: "m".into(),
            provider: "p".into(),
            tokens_input: 10,
            tokens_output: 20,
            tokens_cache_read: 1,
            tokens_cache_write: 2,
            requests: 3,
            billable_requests: 2,
            key_group_at_use: "growth".into(),
            pricing_version: "2026-07".into(),
        })
        .unwrap();
    let rows = store.list_metering(bucket).unwrap();
    let row = rows.iter().find(|r| r.key_id == "vk_meter_new1").unwrap();
    assert_eq!(row.tokens_cache_write, 2);
    assert_eq!(row.billable_requests, 2);
    assert_eq!(row.key_group_at_use, "growth");
    assert_eq!(row.pricing_version, "2026-07");
}

// ---------------------------------------------------------------------------------------------
// Targeted coverage for arithmetic, boundary and guard conditions the broader tests above exercise
// only incidentally. Each test below pins one specific operator or bound.
// ---------------------------------------------------------------------------------------------

/// `percent_decode`'s length guard and hi/lo-nibble arithmetic, pinned with cases the existing
/// `p%40ss`/`bad%zz` coverage doesn't reach: a `lo` of 0 (as in `%40`) makes `hi*16+lo` and
/// `hi*16-lo` compute the same value, so a nonzero `lo` is needed to distinguish `+` from `-`; and
/// neither existing case puts a bare `%` within 2 bytes of the end of the string, so the `i + 2 <
/// len` guard's `+` was never distinguished from `*` (which, at `i=1` on a 3-byte string, would
/// wrongly pass the guard and index one byte past the end).
#[test]
fn percent_decode_edge_cases() {
    assert_eq!(
        percent_decode("%41"),
        "A",
        "a nonzero low nibble must be added, not subtracted"
    );
    assert_eq!(
        percent_decode("a%1"),
        "a%1",
        "a '%' with only one trailing hex digit must be left completely literal, never panic"
    );
    assert_eq!(
        percent_decode("abc%"),
        "abc%",
        "a trailing bare '%' with no hex digits must be left literal, never panic"
    );
}

/// `is_undefined_table` must discriminate the ONE SQLSTATE (`42P01`/undefined_table) it exists to
/// recognize from every other error class -- pinned against two REAL postgres errors (never a
/// hand-built one, since `postgres::Error` has no public constructor), so neither an inverted
/// comparison nor an unconditional true/false would pass.
#[test]
fn is_undefined_table_matches_only_the_real_sqlstate() {
    let Some(url) = live_url() else { return };
    let mut client = postgres::Client::connect(&url, postgres::NoTls).unwrap();

    let missing = client
        .query_opt(
            "SELECT 1 FROM spg_this_table_definitely_does_not_exist_xyz",
            &[],
        )
        .unwrap_err();
    assert!(
        is_undefined_table(&missing),
        "a query against a genuinely missing table must be classified as undefined_table: {missing}"
    );

    let syntax_err = client.query_opt("SELEC 1", &[]).unwrap_err();
    assert!(
        !is_undefined_table(&syntax_err),
        "a syntax error must NOT be misclassified as undefined_table: {syntax_err}"
    );
}

/// `labels_to_storage`'s serialization -- not just the empty-map default -- must round-trip a
/// non-empty label set. `sample_key`'s `Default::default()` labels are empty, and `serde_json` of
/// an empty `BTreeMap` is `"{}"`, the SAME string `labels_to_storage`'s own error fallback returns,
/// so a `labels_to_storage` that returned `String::new()` unconditionally would still round-trip an
/// empty map back to an empty map. Only a NON-empty label set can tell `"{}"` (correct) apart from
/// `""`, since `labels_from_storage("")` also defaults to an empty map.
#[test]
fn labels_round_trip_non_empty_map() {
    let Some(url) = live_url() else { return };
    let store = connect_store_with_retry(&url).expect("connect");
    hard_reset(&store, "vk_labels_rt");

    let mut k = sample_key("vk_labels_rt");
    k.labels = std::collections::BTreeMap::from([
        ("team".to_string(), "growth".to_string()),
        ("env".to_string(), "prod".to_string()),
    ]);
    store.put_key(&k).unwrap();
    let back = store.get_key("vk_labels_rt").unwrap().unwrap();
    assert_eq!(back.labels.get("team").map(String::as_str), Some("growth"));
    assert_eq!(back.labels.get("env").map(String::as_str), Some("prod"));
    assert_eq!(back.labels.len(), 2);
}

/// `secret_form_to_storage`/`secret_form_from_storage` for all three `SecretForm` variants, pure
/// (no DB needed) and independent of which credential fixtures happen to default to `Recoverable`
/// elsewhere -- catches a deleted `"recoverable"` or `"digest"` match arm silently falling through
/// to the `_ => SecretForm::None` catch-all.
#[test]
fn secret_form_storage_round_trip_all_variants() {
    assert_eq!(secret_form_to_storage(SecretForm::None), "none");
    assert_eq!(
        secret_form_to_storage(SecretForm::Recoverable),
        "recoverable"
    );
    assert_eq!(secret_form_to_storage(SecretForm::Digest), "digest");

    assert_eq!(secret_form_from_storage("none"), SecretForm::None);
    assert_eq!(
        secret_form_from_storage("recoverable"),
        SecretForm::Recoverable
    );
    assert_eq!(secret_form_from_storage("digest"), SecretForm::Digest);
    assert_eq!(
        secret_form_from_storage("garbage"),
        SecretForm::None,
        "an unrecognized stored value must fail safe to None, not panic"
    );
}

/// `put_usage`/`add_usage`'s multi-row `VALUES (...)` batching (comma insertion gated on `i > 0`,
/// and each row's placeholder `base = 3 + i * 5`) is only exercised by a call with 2+ models -- every
/// existing test used exactly one model, so `i > 0` vs `i < 0`, and `+`/`*` in the offset arithmetic,
/// were never distinguished (with one model, `i` is always 0, and both branches degenerate to the
/// same single-row SQL).
#[test]
fn put_usage_and_add_usage_batch_multiple_models_correctly() {
    let Some(url) = live_url() else { return };
    let store = connect_store_with_retry(&url).expect("connect");
    let bucket = "vk_multi_model_batch";
    let ws = 20_270_401u64;
    let ws2 = ws + 1;
    for w in [ws, ws2] {
        let _ = store.lock().execute(
            "DELETE FROM usage_windows WHERE bucket_id=$1 AND window_start=$2",
            &[&bucket, &clamp(w)],
        );
        let _ = store.lock().execute(
            "DELETE FROM usage_ledger WHERE bucket_id=$1 AND window_start=$2",
            &[&bucket, &clamp(w)],
        );
    }

    store
        .put_usage(
            bucket,
            ws,
            &UsageLedger {
                requests: 3,
                billable_requests: 2,
                models: vec![
                    ModelTokens {
                        model: "model-a".into(),
                        tokens: TierTokens {
                            input: 10,
                            output: 20,
                            cache_read: 1,
                            cache_write: 2,
                        },
                    },
                    ModelTokens {
                        model: "model-b".into(),
                        tokens: TierTokens {
                            input: 30,
                            output: 40,
                            cache_read: 3,
                            cache_write: 4,
                        },
                    },
                    ModelTokens {
                        model: "model-c".into(),
                        tokens: TierTokens {
                            input: 50,
                            output: 60,
                            cache_read: 5,
                            cache_write: 6,
                        },
                    },
                ],
            },
        )
        .unwrap();

    let got = store.get_usage(bucket, ws).unwrap();
    let mut models = got.models;
    models.sort_by(|a, b| a.model.cmp(&b.model));
    assert_eq!(
        models.len(),
        3,
        "all three model rows must land as three distinct, correctly delimited rows"
    );
    assert_eq!(models[0].model, "model-a");
    assert_eq!(models[0].tokens.input, 10);
    assert_eq!(models[0].tokens.output, 20);
    assert_eq!(models[1].model, "model-b");
    assert_eq!(models[1].tokens.input, 30);
    assert_eq!(models[1].tokens.cache_write, 4);
    assert_eq!(models[2].model, "model-c");
    assert_eq!(models[2].tokens.cache_read, 5);
    assert_eq!(models[2].tokens.cache_write, 6);

    store
        .add_usage(
            bucket,
            ws2,
            &UsageDelta {
                requests: 1,
                billable_requests: 1,
                models: vec![
                    ModelTokensDelta {
                        model: "model-x".into(),
                        tokens: TierTokensDelta {
                            input: 7,
                            output: 8,
                            cache_read: 0,
                            cache_write: 0,
                        },
                    },
                    ModelTokensDelta {
                        model: "model-y".into(),
                        tokens: TierTokensDelta {
                            input: 9,
                            output: 11,
                            cache_read: 0,
                            cache_write: 0,
                        },
                    },
                ],
            },
        )
        .unwrap();
    let got2 = store.get_usage(bucket, ws2).unwrap();
    let mut models2 = got2.models;
    models2.sort_by(|a, b| a.model.cmp(&b.model));
    assert_eq!(
        models2.len(),
        2,
        "both delta model rows must land distinctly"
    );
    assert_eq!(models2[0].model, "model-x");
    assert_eq!(models2[0].tokens.input, 7);
    assert_eq!(models2[1].model, "model-y");
    assert_eq!(models2[1].tokens.output, 11);
}

/// `append_audit`'s append-only contract: a seq collision must be rejected, never silently
/// overwritten (the trait's own doc: "a store never rewrites or recomputes the digest"). Previously
/// entirely untested -- `append_audit`/`AuditRecord` didn't appear anywhere in this file.
#[test]
fn append_audit_is_append_only_and_rejects_a_seq_collision() {
    let Some(url) = live_url() else { return };
    let store = connect_store_with_retry(&url).expect("connect");
    let seq = 900_000_001u64;
    let _ = store
        .lock()
        .execute("DELETE FROM audit_log WHERE seq=$1", &[&clamp(seq)]);

    let entry = AuditRecord {
        seq,
        ts: 1_700_000_000,
        action: "hook.register".into(),
        resource: "hook:compress".into(),
        outcome: "applied".into(),
        principal: "vk_audit_test".into(),
        prev_hash: String::new(),
        hash: "hash-1".into(),
    };
    store.append_audit(&entry).unwrap();

    let mut colliding = entry.clone();
    colliding.hash = "hash-2-different".into();
    colliding.outcome = "rejected".into();
    let err = store
        .append_audit(&colliding)
        .expect_err("a seq collision must be rejected, never silently accepted as an overwrite");
    assert!(
        err.0.contains(&seq.to_string()),
        "the collision error should name the colliding seq: {}",
        err.0
    );

    // The original entry must survive UNCHANGED -- proof this was truly rejected, not partially
    // applied. Queried directly by seq (never list_audit_tail), so this can't race a concurrent
    // test's own unrelated audit_log rows.
    let mut client = postgres::Client::connect(&url, postgres::NoTls).unwrap();
    let row = client
        .query_one(
            "SELECT hash, outcome FROM audit_log WHERE seq=$1",
            &[&clamp(seq)],
        )
        .unwrap();
    let hash: String = row.get(0);
    let outcome: String = row.get(1);
    assert_eq!(
        hash, "hash-1",
        "the original entry's hash must not have been overwritten"
    );
    assert_eq!(outcome, "applied");

    let _ = store
        .lock()
        .execute("DELETE FROM audit_log WHERE seq=$1", &[&clamp(seq)]);
}

/// The denylist pair, previously untested in either direction. `add_denylist` is an UPSERT whose
/// `DO UPDATE SET reason` half is the part that can silently rot: downgrading it to `DO NOTHING`
/// keeps every "is this subject denied" check passing while quietly pinning the reason to whatever
/// the first call said, so a re-denylist with a corrected reason reports success and changes
/// nothing.
#[test]
fn denylist_add_is_listed_and_a_repeat_add_updates_the_reason() {
    let Some(url) = live_url() else { return };
    let store = connect_store_with_retry(&url).expect("connect");
    let sub = format!("sub_denylist_{}", unique_suffix());
    let _ = store
        .lock()
        .execute("DELETE FROM denylist WHERE sub=$1", &[&sub]);

    store.add_denylist(&sub, "first reason").unwrap();
    assert!(
        store.list_denylist().unwrap().contains(&sub),
        "an added subject must appear in list_denylist"
    );

    store.add_denylist(&sub, "corrected reason").unwrap();
    let stored_reason: String = store
        .lock()
        .query_one("SELECT reason FROM denylist WHERE sub=$1", &[&sub])
        .unwrap()
        .get(0);
    assert_eq!(
        stored_reason, "corrected reason",
        "re-denylisting a subject must update the recorded reason, not silently keep the old one"
    );
    let occurrences = store
        .list_denylist()
        .unwrap()
        .iter()
        .filter(|s| *s == &sub)
        .count();
    assert_eq!(
        occurrences, 1,
        "a repeat add must not duplicate the subject"
    );

    let _ = store
        .lock()
        .execute("DELETE FROM denylist WHERE sub=$1", &[&sub]);
}

/// `list_audit_tail` must return the tail OLDEST FIRST. It queries `ORDER BY seq DESC LIMIT n` and
/// reverses in Rust, so dropping the reverse still returns the right n entries, still passes any
/// set-membership assertion, and hands every hash-chain verifier the chain backwards. Ordering is
/// the only assertion that can see it.
#[test]
fn list_audit_tail_returns_the_newest_entries_oldest_first() {
    let Some(url) = live_url() else { return };
    let store = connect_store_with_retry(&url).expect("connect");
    // A high, unique seq block so this cannot collide with a concurrently running test's entries.
    let base = 800_000_000u64 + (std::process::id() as u64 % 100_000) * 1_000;
    for offset in 0..4u64 {
        let _ = store.lock().execute(
            "DELETE FROM audit_log WHERE seq=$1",
            &[&clamp(base + offset)],
        );
    }
    for offset in 0..4u64 {
        store
            .append_audit(&AuditRecord {
                seq: base + offset,
                ts: 1_700_000_000 + offset,
                action: "key.mint".into(),
                resource: format!("key:{offset}"),
                outcome: "applied".into(),
                principal: "vk_tail_test".into(),
                prev_hash: format!("h{}", offset.saturating_sub(1)),
                hash: format!("h{offset}"),
            })
            .unwrap();
    }

    let tail = store.list_audit_tail(3).unwrap();
    let ours: Vec<u64> = tail
        .iter()
        .map(|r| r.seq)
        .filter(|s| *s >= base && *s < base + 4)
        .collect();
    assert_eq!(
        ours,
        vec![base + 1, base + 2, base + 3],
        "list_audit_tail must return the NEWEST entries in OLDEST-FIRST order, so a hash-chain \
         verifier reads prev_hash -> hash forwards"
    );

    for offset in 0..4u64 {
        let _ = store.lock().execute(
            "DELETE FROM audit_log WHERE seq=$1",
            &[&clamp(base + offset)],
        );
    }
}

/// The two purge methods, previously untested. Both are named "before" and both must delete
/// STRICTLY older rows while leaving the boundary row itself alone, and `purge_windows_before` must
/// purge the ledger alongside the windows: purging only `usage_windows` would leave orphaned
/// per-model token rows that no window row accounts for, growing forever.
#[test]
fn purge_windows_and_metering_delete_only_what_is_older_than_the_boundary() {
    let Some(url) = live_url() else { return };
    let store = connect_store_with_retry(&url).expect("connect");
    let bucket = format!("vk_purge_{}", unique_suffix());
    let old_ws = 1_000u64;
    let boundary = 2_000u64;

    let ledger = |model: &str| UsageLedger {
        requests: 1,
        billable_requests: 1,
        models: vec![ModelTokens {
            model: model.into(),
            tokens: TierTokens {
                input: 1,
                output: 1,
                cache_read: 0,
                cache_write: 0,
            },
        }],
    };
    store
        .put_usage(&bucket, old_ws, &ledger("old-model"))
        .unwrap();
    store
        .put_usage(&bucket, boundary, &ledger("boundary-model"))
        .unwrap();

    let purged = store.purge_windows_before(boundary).unwrap();
    assert!(
        purged >= 1,
        "the strictly-older window must be reported as purged, got {purged}"
    );
    assert_eq!(
        store.get_usage(&bucket, old_ws).unwrap().requests,
        0,
        "a window older than the boundary must be gone"
    );
    let kept = store.get_usage(&bucket, boundary).unwrap();
    assert_eq!(
        kept.requests, 1,
        "the boundary window itself must survive: the contract is strictly-before, not at-or-before"
    );
    assert_eq!(
        kept.models.len(),
        1,
        "the boundary window's ledger rows must survive alongside it"
    );
    let orphaned: i64 = store
        .lock()
        .query_one(
            "SELECT COUNT(*) FROM usage_ledger WHERE bucket_id=$1 AND window_start=$2",
            &[&bucket, &clamp(old_ws)],
        )
        .unwrap()
        .get(0);
    assert_eq!(
        orphaned, 0,
        "purging a window must purge its per-model ledger rows too, or they orphan and grow forever"
    );

    // usage_metering, whose boundary parameter is a STRING on this trait method while every other
    // metering method takes it as u64. The parse is the only caller-supplied parse in the crate.
    let key_id = format!("vk_purge_meter_{}", unique_suffix());
    let meter = |bucket: u64| busbar_api::MeteringDelta {
        key_id: key_id.clone(),
        bucket,
        model: "m".into(),
        provider: "p".into(),
        tokens_input: 1,
        tokens_output: 1,
        tokens_cache_read: 0,
        tokens_cache_write: 0,
        requests: 1,
        billable_requests: 1,
        key_group_at_use: String::new(),
        pricing_version: String::new(),
    };
    let meter_bucket = 20_270_601u64;
    store.add_metering(&meter(meter_bucket)).unwrap();
    assert!(
        store
            .list_metering(meter_bucket)
            .unwrap()
            .iter()
            .any(|r| r.key_id == key_id),
        "precondition: the metering row must exist before purging it"
    );

    let bad = store.purge_metering_before("not-a-number");
    assert!(
        bad.is_err(),
        "a non-integer bucket must be a loud error, never a silent no-op reported as a purge"
    );
    assert!(
        store
            .list_metering(meter_bucket)
            .unwrap()
            .iter()
            .any(|r| r.key_id == key_id),
        "a rejected purge must not have deleted anything"
    );

    store
        .purge_metering_before(&meter_bucket.to_string())
        .unwrap();
    assert!(
        !store
            .list_metering(meter_bucket)
            .unwrap()
            .iter()
            .any(|r| r.key_id == key_id),
        "the named metering bucket must be purged"
    );

    let _ = store
        .lock()
        .execute("DELETE FROM usage_windows WHERE bucket_id=$1", &[&bucket]);
    let _ = store
        .lock()
        .execute("DELETE FROM usage_ledger WHERE bucket_id=$1", &[&bucket]);
}

/// `list_keys` is deliberately UNFILTERED: it must include tombstoned rows, because
/// `list_keys_since`'s fallback consumers need the tombstone visible to drive credential eviction.
/// Adding the intuitively-correct-looking `WHERE deleted_at IS NULL` would silently break that, and
/// nothing else in this suite would notice.
#[test]
fn list_keys_includes_tombstoned_rows() {
    let Some(url) = live_url() else { return };
    let store = connect_store_with_retry(&url).expect("connect");
    let id = format!("vk_list_tombstoned_{}", unique_suffix());
    hard_reset(&store, &id);
    store.put_key(&sample_key(&id)).unwrap();
    store.delete_key(&id).unwrap();

    let listed = store.list_keys().unwrap();
    let found = listed
        .iter()
        .find(|k| k.id == id)
        .expect("list_keys must include a tombstoned key, not filter it out");
    assert!(
        !found.is_live(),
        "the listed row must be the tombstone itself"
    );

    hard_reset(&store, &id);
}

/// A unique-enough suffix (pid + nanos) for names that must not collide across concurrently
/// running test binaries against the SAME shared Postgres instance (this repo's own `e2e.rs` uses
/// the identical pattern for its temp work directory).
fn unique_suffix() -> String {
    format!(
        "{}_{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    )
}

/// Split a `postgres://user:pass@host:port/db` URL into its `(userinfo, host:port, db)` parts.
/// This crate's own test fixtures (and `dsn_password`'s own parsing) already assume this exact
/// shape, so no more general a parser is needed here.
fn split_url(url: &str) -> (&str, &str, &str) {
    let rest = url.split("://").nth(1).expect("url must have a scheme");
    let (userinfo, host_and_db) = rest.rsplit_once('@').expect("url must have userinfo");
    let (host_port, db) = host_and_db
        .split_once('/')
        .expect("url must have a db path");
    (userinfo, host_port, db)
}

fn isolated_db_url(url: &str, db_name: &str) -> String {
    let (userinfo, host_port, _) = split_url(url);
    format!("postgres://{userinfo}@{host_port}/{db_name}")
}

fn role_url(url: &str, db_name: &str, user: &str, pass: &str) -> String {
    let (_, host_port, _) = split_url(url);
    format!("postgres://{user}:{pass}@{host_port}/{db_name}")
}

fn create_fresh_database(url: &str, db_name: &str) {
    let mut maint = postgres::Client::connect(url, postgres::NoTls).unwrap();
    let _ = maint.execute(&format!("DROP DATABASE IF EXISTS {db_name}"), &[]);
    maint
        .execute(&format!("CREATE DATABASE {db_name}"), &[])
        .unwrap();
}

fn drop_database(url: &str, db_name: &str) {
    if let Ok(mut maint) = postgres::Client::connect(url, postgres::NoTls) {
        let _ = maint.execute(
            &format!("DROP DATABASE IF EXISTS {db_name} WITH (FORCE)"),
            &[],
        );
    }
}

/// `migrate_locked`'s undefined-table bootstrap path AND its legacy-table drop, together, on a
/// genuinely fresh (separate, disposable) database rather than the shared test database -- which,
/// once any test has run against it, never again presents an undefined `busbar_schema` or a
/// version < `SCHEMA_VERSION`, so this code was structurally unreachable from every other test in
/// this file.
#[test]
fn migrate_bootstraps_fresh_database_and_drops_legacy_tables() {
    let Some(url) = live_url() else { return };
    let db = format!("spg_fresh_{}", unique_suffix());
    create_fresh_database(&url, &db);
    let iso_url = isolated_db_url(&url, &db);

    {
        let mut c = postgres::Client::connect(&iso_url, postgres::NoTls).unwrap();
        c.batch_execute("CREATE TABLE virtual_keys (id TEXT PRIMARY KEY)")
            .unwrap();
    }

    let store =
        connect_store_with_retry(&iso_url).expect("connect must bootstrap a fresh database");

    let mut check = postgres::Client::connect(&iso_url, postgres::NoTls).unwrap();
    let legacy_gone: bool = check
        .query_one("SELECT to_regclass('virtual_keys') IS NULL", &[])
        .unwrap()
        .get(0);
    assert!(
        legacy_gone,
        "a fresh database's pre-existing legacy virtual_keys table must be dropped on bootstrap"
    );
    let version: i64 = check
        .query_one("SELECT COALESCE(MAX(version), 0) FROM busbar_schema", &[])
        .unwrap()
        .get(0);
    assert_eq!(
        version, SCHEMA_VERSION,
        "a fresh database must land on the current schema version"
    );

    drop(store);
    drop(check);
    drop_database(&url, &db);
}

/// The mirror image of the test above: a database ALREADY at `SCHEMA_VERSION` must skip the
/// legacy-table check entirely, never touching a table that merely happens to share a legacy name.
/// Distinguishes `<` from `==`/`<=` at the exact boundary (`version == SCHEMA_VERSION`), which the
/// fresh-database test (`version` starts at 0) cannot: at 0, `<`, `<=`, and (against a nonzero
/// SCHEMA_VERSION) `==`'s complement all happen to agree closely enough that only the equality
/// boundary itself tells them apart.
#[test]
fn migrate_already_at_current_version_skips_the_legacy_check() {
    let Some(url) = live_url() else { return };
    let db = format!("spg_atver_{}", unique_suffix());
    create_fresh_database(&url, &db);
    let iso_url = isolated_db_url(&url, &db);

    {
        let mut c = postgres::Client::connect(&iso_url, postgres::NoTls).unwrap();
        c.batch_execute(&format!(
            "CREATE TABLE busbar_schema (version BIGINT PRIMARY KEY);
             INSERT INTO busbar_schema (version) VALUES ({SCHEMA_VERSION});
             CREATE TABLE virtual_keys (id TEXT PRIMARY KEY);"
        ))
        .unwrap();
    }

    let store = connect_store_with_retry(&iso_url).expect("connect");

    let mut check = postgres::Client::connect(&iso_url, postgres::NoTls).unwrap();
    let legacy_still_there: bool = check
        .query_one("SELECT to_regclass('virtual_keys') IS NOT NULL", &[])
        .unwrap()
        .get(0);
    assert!(
        legacy_still_there,
        "a database already at SCHEMA_VERSION must not run the legacy-table-drop check at all"
    );

    drop(store);
    drop(check);
    drop_database(&url, &db);
}

/// The v6 one-time backfill: a database sitting at v5 with a `usage_windows` row shaped
/// `billable_requests=0, requests>0` (indistinguishable, by counter value alone, from a
/// legitimately fully-refunded window OR a genuine pre-split legacy row) gets `billable_requests`
/// backfilled to `requests` when `connect()` migrates it across the v5->v6 boundary.
#[test]
fn migrate_v6_backfills_billable_requests_for_a_pre_migration_row() {
    let Some(url) = live_url() else { return };
    let db = format!("spg_v6backfill_{}", unique_suffix());
    create_fresh_database(&url, &db);
    let iso_url = isolated_db_url(&url, &db);

    {
        let mut c = postgres::Client::connect(&iso_url, postgres::NoTls).unwrap();
        c.batch_execute(
            "CREATE TABLE busbar_schema (version BIGINT PRIMARY KEY);
             INSERT INTO busbar_schema (version) VALUES (5);
             CREATE TABLE usage_windows (
                 bucket_id TEXT NOT NULL,
                 window_start BIGINT NOT NULL,
                 requests BIGINT NOT NULL DEFAULT 0,
                 billable_requests BIGINT NOT NULL DEFAULT 0,
                 PRIMARY KEY (bucket_id, window_start)
             );
             INSERT INTO usage_windows (bucket_id, window_start, requests, billable_requests)
                 VALUES ('vk_test', 0, 7, 0);",
        )
        .unwrap();
    }

    let store = connect_store_with_retry(&iso_url).expect("connect must run the v6 migration");

    let mut check = postgres::Client::connect(&iso_url, postgres::NoTls).unwrap();
    let billable: i64 = check
        .query_one(
            "SELECT billable_requests FROM usage_windows WHERE bucket_id='vk_test' AND window_start=0",
            &[],
        )
        .unwrap()
        .get(0);
    assert_eq!(
        billable, 7,
        "a pre-v6 row with billable_requests=0, requests>0 must be backfilled to requests"
    );
    let version: i64 = check
        .query_one("SELECT COALESCE(MAX(version), 0) FROM busbar_schema", &[])
        .unwrap()
        .get(0);
    assert_eq!(version, SCHEMA_VERSION);

    drop(store);
    drop(check);
    drop_database(&url, &db);
}

/// The other half: a database ALREADY at v6+ must NOT have this backfill re-applied — a row
/// shaped `billable_requests=0, requests>0` there is either a genuinely fully-refunded window
/// (must stay 0) or freshly written data, never something to re-bill. This is what makes the v6
/// migration safe as a ONE-TIME event rather than the exact per-boot heuristic bug it replaces.
#[test]
fn migrate_v6_does_not_rerun_the_backfill_on_an_already_migrated_database() {
    let Some(url) = live_url() else { return };
    let db = format!("spg_v6norerun_{}", unique_suffix());
    create_fresh_database(&url, &db);
    let iso_url = isolated_db_url(&url, &db);

    {
        let mut c = postgres::Client::connect(&iso_url, postgres::NoTls).unwrap();
        c.batch_execute(&format!(
            "CREATE TABLE busbar_schema (version BIGINT PRIMARY KEY);
             INSERT INTO busbar_schema (version) VALUES ({SCHEMA_VERSION});
             CREATE TABLE usage_windows (
                 bucket_id TEXT NOT NULL,
                 window_start BIGINT NOT NULL,
                 requests BIGINT NOT NULL DEFAULT 0,
                 billable_requests BIGINT NOT NULL DEFAULT 0,
                 PRIMARY KEY (bucket_id, window_start)
             );
             INSERT INTO usage_windows (bucket_id, window_start, requests, billable_requests)
                 VALUES ('vk_refunded', 0, 7, 0);"
        ))
        .unwrap();
    }

    let store = connect_store_with_retry(&iso_url).expect("connect");

    let mut check = postgres::Client::connect(&iso_url, postgres::NoTls).unwrap();
    let billable: i64 = check
        .query_one(
            "SELECT billable_requests FROM usage_windows WHERE bucket_id='vk_refunded' AND window_start=0",
            &[],
        )
        .unwrap()
        .get(0);
    assert_eq!(
        billable, 0,
        "a database already at SCHEMA_VERSION must never re-run the v6 backfill — a \
         legitimately-refunded-to-zero row on an already-migrated store must stay 0"
    );

    drop(store);
    drop(check);
    drop_database(&url, &db);
}

/// `migrate`/`migrate_locked` must never silently succeed against a role that lacks real read
/// access to its own bookkeeping table -- built with a role granted CREATE/INSERT but deliberately
/// NEVER SELECT on `busbar_schema`, so a genuine SQLSTATE 42501 (insufficient_privilege) surfaces
/// somewhere in `migrate_locked`'s statement sequence (Postgres requires SELECT on the target table
/// for `INSERT ... ON CONFLICT`, even `DO NOTHING`, confirmed empirically against this exact
/// fixture -- not just for the version-probe `SELECT` itself), and `connect()` must propagate that
/// as an `Err`, never proceed as if the database were merely fresh.
///
/// NOTE on `is_undefined_table(&e)` at the `migrate_locked` match guard (line ~324): that specific
/// branch is unreachable via ANY fixture reachable from this test file, confirmed by hand-patching
/// it to hardcoded `true` and to hardcoded `false` and observing `connect()`'s behavior is
/// unchanged in both cases -- `migrate_locked` unconditionally runs `CREATE TABLE IF NOT EXISTS
/// busbar_schema` as its very first statement, so by the time the guarded `SELECT` runs, the table
/// either already exists (guard never fires) or the preceding `CREATE TABLE` itself already
/// propagated the error several lines earlier (guard never reached). The branch is therefore
/// unreachable given the current code structure rather than merely untested: no test can
/// distinguish the two behaviours without changing the source.
#[test]
fn migrate_propagates_a_non_undefined_table_error_and_never_silently_succeeds() {
    let Some(url) = live_url() else { return };
    let db = format!("spg_perm_{}", unique_suffix());
    create_fresh_database(&url, &db);
    let iso_url = isolated_db_url(&url, &db);
    let role = format!("spg_limited_{}", unique_suffix());

    {
        let mut c = postgres::Client::connect(&iso_url, postgres::NoTls).unwrap();
        c.batch_execute(&format!(
            "CREATE ROLE {role} LOGIN PASSWORD 'limited';
             GRANT CREATE, USAGE ON SCHEMA public TO {role};
             CREATE TABLE busbar_schema (version BIGINT PRIMARY KEY);
             GRANT INSERT ON busbar_schema TO {role};"
        ))
        .unwrap();
        // Deliberately NO SELECT grant on busbar_schema.
    }

    let limited_url = role_url(&url, &db, &role, "limited");

    // Sanity-check the fixture itself, independently (raw client, never through the store): the
    // probe query must fail with insufficient_privilege, never undefined_table, or this test would
    // prove nothing.
    {
        let mut raw = postgres::Client::connect(&limited_url, postgres::NoTls).unwrap();
        let probe_err = raw
            .query_opt("SELECT COALESCE(MAX(version), 0) FROM busbar_schema", &[])
            .unwrap_err();
        assert_eq!(
            probe_err.code(),
            Some(&postgres::error::SqlState::INSUFFICIENT_PRIVILEGE),
            "test setup sanity: the probe query must fail with insufficient_privilege, not \
             undefined_table, for this test to mean anything: {probe_err}"
        );
        assert!(!is_undefined_table(&probe_err));
    }

    assert!(
        PostgresStore::connect(&limited_url).is_err(),
        "migrate must never silently succeed against a role that can't actually read its own \
         bookkeeping table"
    );

    let mut cleanup = postgres::Client::connect(&iso_url, postgres::NoTls).unwrap();
    let _ = cleanup.batch_execute(&format!(
        "DROP OWNED BY {role}; DROP ROLE IF EXISTS {role};"
    ));
    drop(cleanup);
    drop_database(&url, &db);
}
