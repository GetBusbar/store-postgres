// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! End-to-end coverage of the `busbar-store-postgres-plugin` cdylib loaded over the REAL loader
//! `load_store` seam (the exact seam the engine uses for `governance.store: postgres`) against a REAL
//! `postgres:16` — not a mock, not `:memory:`. This is the seam-plus-database proof the sqlite plugin
//! gets for free from a real on-disk file (see busbarAI's
//! `crates/plugin-loader/src/lib.rs::load_and_exercise_sqlite_plugin_persists_to_real_file_across_reopen`,
//! which this file is modeled on) — Postgres needs a live server instead of a temp file, so these tests
//! are gated on `BUSBAR_TEST_POSTGRES_URL` exactly like the underlying `busbar-store-postgres` crate's
//! own `roundtrip_against_live_postgres` test.
//!
//! Persistence is proven TWO independent ways, mirroring the sqlite reopen test:
//!   1. dlopen the SAME cdylib again (a fresh `busbar_open`, fresh in-plugin connection) against the
//!      SAME database — proves the plugin isn't just caching in-process.
//!   2. connect with the plain `busbar_store_postgres::PostgresStore` directly — a code path that never
//!      goes through the cdylib, the C ABI, or the loader at all — proving the plugin actually wrote
//!      real Postgres rows, not just satisfying its own in-process round-trip.

use busbar_api::{ModelTokens, Store, TierTokens, UsageLedger, VirtualKey};
use busbar_plugin_loader::load_store;
use busbar_store_postgres::PostgresStore;

/// Resolve `BUSBAR_TEST_POSTGRES_URL`. Skips cleanly when unset locally so a bare `cargo test` needs
/// no database; HARD-FAILS when `CI` is set (the workflow's `postgres:16` service container must have
/// provisioned it — see `.github/workflows/ci.yml`), so this coverage can never silently vanish.
/// Mirrors the identical guard in busbar-store-postgres's own `roundtrip_against_live_postgres` test.
fn postgres_url() -> Option<String> {
    match std::env::var("BUSBAR_TEST_POSTGRES_URL") {
        Ok(url) => Some(url),
        Err(_) if std::env::var_os("CI").is_some() => {
            panic!(
                "BUSBAR_TEST_POSTGRES_URL is unset under CI: the postgres:16 service container must \
                 provision it (see .github/workflows/ci.yml). Refusing to silently skip the only \
                 real-ABI-against-real-Postgres coverage in CI."
            );
        }
        Err(_) => {
            eprintln!("skip: set BUSBAR_TEST_POSTGRES_URL to run the live-Postgres ABI test");
            None
        }
    }
}

/// Locate the built plugin cdylib in the target dir (mirrors the loader's own `sqlite_plugin_path`).
/// CI-hardened the same way: `cargo test` builds the cdylib as part of the test run (this crate is a
/// `cdylib`-only lib), so its absence under `CI` is a broken build, not something to skip past.
fn plugin_path() -> Option<std::path::PathBuf> {
    let candidate = (|| {
        let exe = std::env::current_exe().ok()?; // .../target/<profile>/deps/e2e-<hash>
        let profile_dir = exe.parent()?.parent()?; // .../target/<profile>
        let name = busbar_plugin_loader::plugin_library_filename("busbar_store_postgres_plugin");
        let candidate = profile_dir.join(&name);
        candidate.exists().then_some(candidate)
    })();
    if candidate.is_none() && std::env::var_os("CI").is_some() {
        panic!(
            "the store-postgres-plugin cdylib is not built under CI: `cargo test` must build it. \
             Refusing to silently skip the only over-the-ABI coverage of the durable Postgres store path."
        );
    }
    candidate
}

fn cfg(url: &str) -> String {
    serde_json::json!({ "url": url }).to_string()
}

/// A distinct per-test key id/hash so two tests sharing one live database never collide (and each test
/// cleans up after itself with `delete_key`, mirroring `busbar-store-postgres`'s own live-DB test).
fn cleanup(url: &str, id: &str) {
    if let Ok(store) = PostgresStore::connect(url) {
        let _ = store.delete_key(id);
    }
}

/// END-TO-END + REAL PERSISTENCE: dlopen the real plugin, write a key + usage ledger over the C ABI,
/// drop the plugin (running `busbar_close` via `RawPlugin`'s `Drop`), then verify the data genuinely
/// persisted in Postgres — not just cached in-process — two independent ways (see module doc).
#[test]
fn load_and_exercise_postgres_plugin_persists_across_reopen_and_independent_connection() {
    let Some(url) = postgres_url() else { return };
    let Some(path) = plugin_path() else {
        eprintln!(
            "skip: store-postgres-plugin cdylib not built (run under --workspace/normal build)"
        );
        return;
    };

    let key_id = "vk_pg_abi_e2e";
    cleanup(&url, key_id);

    let key = VirtualKey {
        id: key_id.into(),
        key_hash: "abi-hash".into(),
        name: "abi-e2e".into(),
        allowed_pools: Some(vec!["prod".into()]),
        enabled: true,
        created_at: 55,
        group: Some("infra".into()),
        labels: std::collections::BTreeMap::from([("env".into(), "prod".into())]),
    };
    let ledger = UsageLedger {
        requests: 4,
        billable_requests: 3,
        models: vec![ModelTokens {
            model: "gpt-5".into(),
            tokens: TierTokens {
                input: 12,
                output: 6,
                cache_read: 1,
                cache_write: 0,
            },
        }],
    };

    {
        let store = load_store(&path, &cfg(&url)).expect("load the postgres plugin over the C ABI");
        store.put_key(&key).expect("put_key over the ABI");
        store
            .put_usage(key_id, 300, &ledger)
            .expect("put_usage over the ABI");
        assert_eq!(
            store
                .get_key(key_id)
                .expect("get_key")
                .expect("present in the same session")
                .id,
            key_id
        );
        // `store` (the `DynStore`/`RawPlugin` it wraps) drops here, running `busbar_close` and
        // dropping the plugin's `PostgresStore`/connection — the database must hold the committed
        // data after this, not just an in-process cache.
    }

    // (1) Re-dlopen the SAME cdylib against the SAME database: a fresh plugin instance, fresh
    // `busbar_open`, fresh connection inside the plugin — proves the round-trip isn't relying on the
    // first instance still being alive.
    let reopened = load_store(&path, &cfg(&url))
        .expect("re-load the postgres plugin against the same database");
    let got = reopened
        .get_key(key_id)
        .expect("get_key after reopen")
        .expect("the key must survive a full plugin close + reopen against the same database");
    assert_eq!(got.group.as_deref(), Some("infra"));
    assert_eq!(got.labels.get("env").map(String::as_str), Some("prod"));
    let usage = reopened
        .get_usage(key_id, 300)
        .expect("get_usage after reopen");
    assert_eq!(usage.requests, 4, "usage ledger must survive the reopen");
    assert_eq!(usage.billable_requests, 3);
    let t = usage
        .tokens_for("gpt-5")
        .expect("model row survives reopen");
    assert_eq!((t.input, t.output, t.cache_read), (12, 6, 1));
    drop(reopened);

    // (2) Connect with the plain `PostgresStore` directly — a code path that never touches the cdylib,
    // the C ABI, or `plugin-loader` at all. If the plugin's `put_key`/`put_usage` over the ABI were
    // silent no-ops (or wrote to a different database than the configured `url`), this independent
    // reader would come back empty even though the reopen-via-plugin check above passed.
    let direct = PostgresStore::connect(&url)
        .expect("connect directly with the plain PostgresStore, bypassing the plugin entirely");
    let direct_key = Store::get_key(&direct, key_id)
        .expect("get_key via the direct connection")
        .expect("the row must be physically present in Postgres");
    assert_eq!(direct_key.name, "abi-e2e");
    assert_eq!(direct_key.allowed_pools, Some(vec!["prod".to_string()]));
    let direct_usage =
        Store::get_usage(&direct, key_id, 300).expect("get_usage via the direct connection");
    assert_eq!(
        direct_usage.requests, 4,
        "usage must be physically present in Postgres, not just cached in-process"
    );

    direct.delete_key(key_id).expect("cleanup");
}

/// END-TO-END FAILURE: an `open()` config that cannot produce a usable store (malformed JSON, a
/// missing `url`, or a URL Postgres itself refuses) surfaces back across the C ABI as a clean `Err`,
/// never a panic or a silently-succeeded load. Mirrors the sqlite plugin's own
/// `load_and_exercise_sqlite_plugin_bad_config_fails_over_abi`.
#[test]
fn load_and_exercise_postgres_plugin_bad_config_fails_over_abi() {
    let Some(path) = plugin_path() else {
        eprintln!(
            "skip: store-postgres-plugin cdylib not built (run under --workspace/normal build)"
        );
        return;
    };

    let err = load_store(&path, "{ not json")
        .err()
        .expect("malformed config JSON must fail to load, not silently succeed");
    assert!(
        err.contains("invalid postgres plugin config"),
        "the plugin's own error message should survive the ABI crossing intact: {err}"
    );

    let err = load_store(&path, "{}")
        .err()
        .expect("a config missing url must fail to load");
    assert!(
        err.contains("requires a \"url\""),
        "expected the plugin's own missing-url message, got: {err}"
    );

    // A syntactically-valid but unroutable/unreachable target: the underlying `postgres::Client`
    // connect must fail, and that failure must surface as a load error across the ABI, never a panic.
    let err = load_store(
        &path,
        &cfg("postgres://u:p@127.0.0.1:1/definitely_not_a_real_db"),
    )
    .err()
    .expect("an unreachable postgres target must fail to load");
    assert!(
        err.contains("error connecting to server"),
        "expected tokio-postgres's own connect-failure message to survive the ABI crossing, got: {err}"
    );
}

/// A non-plugin library (or a missing file) is refused with a clear error, never a crash. Mirrors
/// the sqlite plugin's own `refuses_non_plugin`.
#[test]
fn refuses_non_plugin() {
    let err = match load_store(std::path::Path::new("/definitely/not/a/plugin.so"), "{}") {
        Err(e) => e,
        Ok(_) => panic!("a missing library must not load"),
    };
    assert!(err.contains("failed to load plugin"), "got: {err}");
}
