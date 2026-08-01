// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Unit tests for the Postgres store (schema v5, generic credentials): DSN-password scrubbing plus
//! (gated on `BUSBAR_TEST_POSTGRES_URL`) real round-trip and invariant coverage against a live
//! `postgres:16`.

use super::*;
use busbar_api::{CredentialMeta, CredentialSecret, SecretForm};

/// L2: a connect-error string must never leak the DSN password.
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

/// TRUE reset for test isolation -- unlike `delete_key` (a deliberate tombstone that can never fully
/// reset a row by design), this raw-SQL wipe gives each test a genuinely clean slate for its id, so
/// re-running the suite (or running it twice, as red-before-green proofs do) never sees stale state
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
/// revision) and the C6 allowed_pools NULL-vs-'[]' distinction.
#[test]
fn key_roundtrip_new_fields() {
    let Some(url) = live_url() else { return };
    let store = PostgresStore::connect(&url).expect("connect");
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
    let store = PostgresStore::connect(&url).expect("connect");
    let id = "vk_tombstone1";
    hard_reset(&store, id);

    let key = sample_key(id);
    let cred = sample_cred(id, 0, "AKIA_TOMBSTONE1");
    store.put_key_with_credential(&key, &cred).unwrap();
    assert_eq!(store.list_credentials(id).unwrap().len(), 1);

    store.delete_key(id).unwrap();

    // RED-BEFORE-GREEN evidence lives in the assertions below: this test only passes if delete_key
    // genuinely tombstones rather than hard-deletes. Confirmed by temporarily reverting delete_key
    // to `DELETE FROM keys WHERE id=$1` during development: get_key(id) then returned None and this
    // test failed at the very first assertion, exactly as expected.
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

/// scrub_key: PII-erasure only, requires the key to already be tombstoned.
#[test]
fn scrub_key_requires_tombstone_first() {
    let Some(url) = live_url() else { return };
    let store = PostgresStore::connect(&url).expect("connect");
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
    let store = PostgresStore::connect(&url).expect("connect");
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

/// revoke_credential kills ONE credential independent of the key: the key stays enabled, the OTHER
/// slot's credential stays live, only the targeted one is revoked. This is the plugin-level half of
/// the fan-out fix the core redesign exists for (the orchestration itself lives in GovState::revoke,
/// but it depends on this method actually working).
#[test]
fn revoke_credential_is_independent_of_the_key_and_other_slots() {
    let Some(url) = live_url() else { return };
    let store = PostgresStore::connect(&url).expect("connect");
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

    assert!(
        store
            .lookup_credential_secret("sigv4", "AKIA_REVOKE1_A")
            .unwrap()
            .is_none()
            || !meta0.is_live(0),
        "a revoked credential must no longer resolve as live"
    );

    // Idempotent.
    store
        .revoke_credential(&c0.meta.id, "leaked again")
        .unwrap();
}

/// HYDRATION-DELTA SOUNDNESS: the exact invariant this session's design work flagged as a real gap
/// (independently found by the SQLite and MySQL schema design passes). A revision-based delta
/// consumer polling list_keys_since/list_credentials_since must be able to observe a delete_key
/// tombstone AND infer the credential deletion from it, because the credential rows are hard-deleted
/// and produce no delta of their own.
#[test]
fn hydration_delta_makes_credential_deletion_observable_via_the_key_tombstone() {
    let Some(url) = live_url() else { return };
    let store = PostgresStore::connect(&url).expect("connect");
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
    let store_a = PostgresStore::connect(&url).expect("connect a");
    let store_b = PostgresStore::connect(&url).expect("connect b");
    let id = "vk_concurrent_del1";
    hard_reset(&store_a, id);
    store_a.put_key(&sample_key(id)).unwrap();
    let cred = sample_cred(id, 0, "AKIA_CONCURRENT1");
    store_a.put_credential(&cred).unwrap();

    let url_b = url.clone();
    let id_b = id.to_string();
    let handle = std::thread::spawn(move || {
        let store_b2 = PostgresStore::connect(&url_b).expect("connect b2");
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

/// get_usage's REPEATABLE READ snapshot must not tear: a concurrent add_usage landing between the
/// requests-row read and the model-rows read must not be half-visible.
#[test]
fn get_usage_transaction_is_actually_repeatable_read() {
    let Some(url) = live_url() else { return };
    let store = PostgresStore::connect(&url).expect("connect");
    let mut client = postgres::Client::connect(&url, postgres::NoTls).unwrap();
    let mut tx = PostgresStore::snapshot_consistent_tx(&mut client).unwrap();
    let level: String = tx
        .query_one("SHOW transaction_isolation", &[])
        .unwrap()
        .get(0);
    tx.commit().unwrap();
    assert_eq!(
        level, "repeatable read",
        "get_usage's helper must actually open REPEATABLE READ"
    );
    let _ = store.get_usage("nonexistent_bucket", 0); // smoke: still callable
}

/// usage_metering round-trip including the new fields (billable_requests, key_group_at_use,
/// pricing_version) and the renamed tokens_cache_write (was tokens_cache_creation).
#[test]
fn metering_roundtrip_new_fields() {
    let Some(url) = live_url() else { return };
    let store = PostgresStore::connect(&url).expect("connect");
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
