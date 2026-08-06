// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! End-to-end coverage of the `busbar-store-postgres-plugin` cdylib, loaded the way a REAL operator
//! actually loads a plugin — not via a direct in-process `busbar_plugin_loader::load_store()` call
//! (flagged, correctly, as testing a mechanism no end user ever uses: nobody imports
//! `busbar-plugin-loader` and calls its internal function).
//!
//! `load_and_exercise_postgres_plugin_via_file_drop` instead: packs the built cdylib into a real
//! tarball (the same `busbar-plugin-pack` tool CI's own SIGNOFF step uses), drops it into a real
//! `plugins.dir`, and boots a REAL `busbar` process (no `--validate`) against a config naming
//! `store: { module: postgres }` — the documented file-drop install path (see
//! `crates/plugin-loader/src/lib.rs::list_plugin_files`/boot-time discovery).
//!
//! `--validate` is DELIBERATELY not used for the load-proof itself: it is manifest-only by design
//! ("no server, no network, no state, no dlopen" — `crates/busbar/src/main.rs`'s own `--help` text)
//! and never opens the store, so checking the schema after `--validate` alone would prove nothing
//! about the real boot path. A clean `--validate` run first proves the file-dropped plugin passes
//! the trust/manifest gate; then a REAL BOOT (no `--validate` flag) is the only thing that actually
//! `dlopen`s the plugin and runs `Store::connect`/migration (busbar's own gate-assembly code calls
//! `plugin_registry.open_store` synchronously during construction, before the listener ever binds —
//! see `crates/busbar/src/main.rs`), so that's what proves the persistence claim.
//!
//! Persistence is then proven the same two independent ways the prior direct-call test used (kept —
//! this part was always sound, only the LOADING mechanism was wrong):
//!   1. The boot runs against a DISPOSABLE, freshly created, genuinely empty database, and is polled
//!      via a RAW independent `postgres::Client` connection (never `PostgresStore::connect`, so this
//!      check can't create the schema itself) for the `keys` table to appear within a timeout. The
//!      empty database is what makes this a proof rather than a formality: against the shared test
//!      database, every live unit test in this workspace has already migrated a `keys` table into
//!      existence, so the same poll would break true on its first iteration even if `busbar` had
//!      failed to load the plugin and exited immediately. Then the schema VERSION the boot wrote is
//!      read back, and the child is confirmed still running rather than having died after migrating.
//!   2. Only AFTER those proofs, a second, independent `PostgresStore::connect` (bypassing the
//!      plugin/ABI/loader entirely) confirms the store type itself can talk to the same schema.
//!
//! The two ABI-contract error-path tests below (`bad_config_fails_over_abi`, `refuses_non_plugin`)
//! are DELIBERATELY left calling `load_store()` directly — they test the loader's own error-surface
//! contract in isolation (a legitimate internal unit-test target: "does a bad config produce a clean
//! Err across the ABI, never a panic"), which is a different question from "does a real end-user
//! install work," and converting them to a full process-boot-and-capture-stderr harness for each
//! error shape is a much larger, lower-value lift than the persistence test's conversion.

use busbar_store_postgres::PostgresStore;
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

/// RAII guard for a spawned child process: kills and reaps it on drop, including when a panic
/// unwinds partway through the test (unlike a manual `child.kill()` call placed after the code that
/// might panic, which never runs if an earlier assertion fails first).
struct ChildGuard(Child);

impl Drop for ChildGuard {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

fn postgres_url() -> Option<String> {
    match std::env::var("BUSBAR_TEST_POSTGRES_URL") {
        Ok(url) => Some(url),
        Err(_) if std::env::var_os("CI").is_some() => {
            panic!(
                "BUSBAR_TEST_POSTGRES_URL is unset under CI: the postgres:16 service container must \
                 provision it. Refusing to silently skip the only real-install-path coverage in CI."
            );
        }
        Err(_) => {
            eprintln!("skip: set BUSBAR_TEST_POSTGRES_URL to run the live-Postgres e2e tests");
            None
        }
    }
}

/// Checks BOTH the "uplifted" `<profile_dir>/<name>` copy (only refreshed when `[lib]` is a ROOT
/// build target of the invocation, e.g. `cargo build --all-targets`) and the raw
/// `<profile_dir>/deps/<name>` compiler output (refreshed on every build that recompiles the lib,
/// uplifted or not). A bare `cargo test --release` does NOT uplift the cdylib to the top-level
/// profile dir, only to `target/deps`, so checking only `profile_dir` silently finds nothing.
fn plugin_path() -> Option<PathBuf> {
    let candidate = (|| {
        let exe = std::env::current_exe().ok()?;
        let profile_dir = exe.parent()?.parent()?;
        let name = busbar_plugin_loader::plugin_library_filename("busbar_store_postgres_plugin");
        let uplifted = profile_dir.join(&name);
        let raw = profile_dir.join("deps").join(&name);
        [uplifted, raw]
            .into_iter()
            .filter_map(|p| {
                std::fs::metadata(&p)
                    .and_then(|m| m.modified())
                    .ok()
                    .map(|mtime| (p, mtime))
            })
            .max_by_key(|(_, mtime)| *mtime)
            .map(|(p, _)| p)
    })();
    if candidate.is_none() && std::env::var_os("CI").is_some() {
        panic!(
            "the store-postgres-plugin cdylib is not built under CI: `cargo test` must build it \
             (checked both the uplifted target dir and target/deps). Refusing to silently skip the \
             only over-the-ABI coverage of the durable Postgres store path."
        );
    }
    candidate
}

fn cfg(url: &str) -> String {
    serde_json::json!({ "url": url }).to_string()
}

/// A suffix unique across concurrently running test binaries against the SAME Postgres instance.
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

/// Rewrite a `postgres://user:pass@host:port/db` URL to name a different database on the same
/// server, keeping the credentials. The shape is the one this crate's own fixtures and
/// `dsn_password` already assume.
fn isolated_db_url(url: &str, db_name: &str) -> String {
    let rest = url.split("://").nth(1).expect("url must have a scheme");
    let (userinfo, host_and_db) = rest.rsplit_once('@').expect("url must have userinfo");
    let (host_port, _) = host_and_db
        .split_once('/')
        .expect("url must have a db path");
    format!("postgres://{userinfo}@{host_port}/{db_name}")
}

/// Create a genuinely empty database. The boot proof below rests entirely on this: the shared CI
/// database already carries a `keys` table by the time this binary runs (every live unit test opens
/// a `PostgresStore`, and `connect` migrates), so polling it for that table cannot distinguish "this
/// boot created the schema" from "it was already there" -- the poll would break true on its first
/// iteration even if `busbar` had failed to load the plugin and exited immediately.
fn create_fresh_database(url: &str, db_name: &str) -> bool {
    let Ok(mut maint) = postgres::Client::connect(url, postgres::NoTls) else {
        return false;
    };
    let _ = maint.execute(&format!("DROP DATABASE IF EXISTS {db_name}"), &[]);
    maint
        .execute(&format!("CREATE DATABASE {db_name}"), &[])
        .is_ok()
}

fn drop_database(url: &str, db_name: &str) {
    if let Ok(mut maint) = postgres::Client::connect(url, postgres::NoTls) {
        let _ = maint.execute(
            &format!("DROP DATABASE IF EXISTS {db_name} WITH (FORCE)"),
            &[],
        );
    }
}

/// The sibling busbarAI checkout's root (same convention this repo already uses for its path deps).
fn busbarai_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../busbarAI")
        .canonicalize()
        .expect("sibling busbarAI checkout must exist (see Cargo.toml path deps)")
}

/// Build (once, cached by cargo) and return the path to the real `busbar` binary and the real
/// `busbar-plugin-pack` binary, both from the sibling busbarAI checkout — never a fixture, never a
/// stub, the exact binaries a real release ships.
fn build_real_binaries() -> (PathBuf, PathBuf) {
    let root = busbarai_root();
    let status = Command::new("cargo")
        .args([
            "build",
            "--release",
            "-p",
            "busbar",
            "-p",
            "busbar-plugin-pack",
        ])
        .current_dir(&root)
        .status()
        .expect("run cargo build for busbar + busbar-plugin-pack");
    assert!(
        status.success(),
        "building the real busbar + busbar-plugin-pack binaries must succeed"
    );
    (
        root.join("target/release/busbar"),
        root.join("target/release/busbar-plugin-pack"),
    )
}

/// THE REAL END-TO-END INSTALL PROOF: pack the plugin, drop it in a real `plugins.dir`, run the real
/// `busbar --validate` against a config naming `store: { module: postgres }` (trust/manifest gate
/// proof), then boot a REAL `busbar` process (no `--validate`) and poll for real Postgres to
/// actually be touched — via the documented file-drop mechanism, never a direct `load_store()` call.
#[test]
fn load_and_exercise_postgres_plugin_via_file_drop() {
    let Some(admin_url) = postgres_url() else {
        return;
    };
    let Some(so_path) = plugin_path() else {
        eprintln!("skip: store-postgres-plugin cdylib not built");
        return;
    };

    // A DISPOSABLE, genuinely empty database, created before the boot and dropped after it. The
    // schema this test polls for can then only have come from the boot under test.
    let db = format!("spg_filedrop_{}", unique_suffix());
    assert!(
        create_fresh_database(&admin_url, &db),
        "the file-drop boot proof needs its own empty database; creating {db} failed"
    );
    let url = isolated_db_url(&admin_url, &db);

    let (busbar_bin, pack_bin) = build_real_binaries();

    let work = std::env::temp_dir().join(format!(
        "busbar-pg-filedrop-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    let plugins_dir = work.join("plugins");
    std::fs::create_dir_all(&plugins_dir).unwrap();

    // Pack the real cdylib into a real signed-shape tarball via the same tool CI's SIGNOFF step
    // uses, --allow-unsigned locally exactly like CI's own unsigned-key fallback.
    let tarball = work.join("store-postgres.tar.gz");
    let status = Command::new(&pack_bin)
        .args([
            "pack",
            "--lib",
            so_path.to_str().unwrap(),
            "--name",
            "busbar-store-postgres-plugin",
            "--alias",
            "postgres",
            "--kind",
            "store",
            "--version",
            "0.0.0-e2e",
            "--publisher",
            "busbar",
            "--description",
            "e2e file-drop proof",
            "--license",
            "Apache-2.0",
            "--out",
            tarball.to_str().unwrap(),
            "--allow-unsigned",
        ])
        .status()
        .expect("run busbar-plugin-pack");
    assert!(status.success(), "packing the plugin must succeed");

    // FILE-DROP: the real boot-time discovery mechanism extracts/reads whatever is in plugins.dir --
    // dropping the packed tarball here, uninstalled via any admin call, is the documented mechanism.
    std::fs::copy(&tarball, plugins_dir.join("store-postgres.tar.gz")).unwrap();

    let config = work.join("config.yaml");
    let providers = work.join("providers.yaml");
    // providers.yaml is the flat CATALOG (provider name at the document root, no wrapping key) --
    // config.yaml separately has its OWN `providers:`/`models:` blocks naming which catalog
    // entries are enabled. Mirrors the known-good fixture in
    // crates/busbar/tests/cli_validate.rs::write_configs, not invented here.
    std::fs::write(
        &providers,
        "mock:\n  protocol: anthropic\n  base_url: \"http://127.0.0.1:9\"\n  api_key_env: MOCK_KEY\n",
    )
    .unwrap();
    std::fs::write(
        &config,
        format!(
            "listen: \"127.0.0.1:0\"\n\
             store:\n  module: postgres\n  settings: {{ url: \"{url}\" }}\n\
             plugins:\n  enabled: true\n  dir: {}\n  trust:\n    allow_unsigned: true\n\
             auth:\n  chain: []\n\
             providers:\n  mock:\n    api_key: {{ env: MOCK_KEY }}\n\
             models:\n  test-model:\n    provider: mock\n",
            plugins_dir.display()
        ),
    )
    .unwrap();

    // `--validate` is DELIBERATELY not used for the load-proof itself: it is manifest-only by
    // design ("no server, no network, no state, no dlopen" -- crates/busbar/src/main.rs's own
    // `--help` text) and never opens the store. A clean `--validate` run first proves the
    // file-dropped plugin passes the trust/manifest gate; then a REAL BOOT (no `--validate` flag,
    // below) is the only thing that actually `dlopen`s the plugin and runs
    // `Store::connect`/migration.
    let out = Command::new(&busbar_bin)
        .arg("--validate")
        .env("BUSBAR_CONFIG", &config)
        .env("BUSBAR_PROVIDERS", &providers)
        .output()
        .expect("run busbar --validate");
    assert!(
        out.status.success(),
        "busbar --validate must succeed with the file-dropped postgres plugin: stdout={} stderr={}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );

    // REAL BOOT: run the actual gateway process (no --validate) against the same file-dropped
    // plugin + config, and poll -- via a RAW independent postgres::Client connection, never
    // PostgresStore::connect, so this check can't accidentally create the schema itself -- for the
    // `keys` table to appear. This is the only genuine proof that boot actually dlopened the plugin
    // and called Store::connect (which runs migrate()) before ever handling a request, and it is a
    // proof only because the database above was created empty for this test alone: against the
    // shared database every other test in this workspace migrates, `keys` already exists and the
    // poll would succeed on its first iteration no matter what the child process did.
    let child = Command::new(&busbar_bin)
        .env("BUSBAR_CONFIG", &config)
        .env("BUSBAR_PROVIDERS", &providers)
        .env("BUSBAR_STATE_FILE", "") // disable the state-snapshot file; not under test here
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("spawn a real busbar boot");
    let mut guard = ChildGuard(child);

    let deadline = Instant::now() + Duration::from_secs(15);
    let booted = loop {
        if let Ok(mut raw) = postgres::Client::connect(&url, postgres::NoTls) {
            if let Ok(row) = raw.query_one(
                "SELECT EXISTS (SELECT 1 FROM information_schema.tables WHERE table_name='keys')",
                &[],
            ) {
                let exists: bool = row.get(0);
                if exists {
                    break true;
                }
            }
        }
        if let Ok(Some(status)) = guard.0.try_wait() {
            panic!("busbar exited before creating the postgres schema (status: {status})");
        }
        if Instant::now() >= deadline {
            break false;
        }
        std::thread::sleep(Duration::from_millis(50));
    };
    assert!(
        booted,
        "a real busbar boot with the file-dropped postgres plugin must create the `keys` table \
         (via Store::connect/migrate) within 15s -- proof the real dlopen+connect path executed \
         during boot, not a no-op"
    );

    // The boot did not just create a table, it landed the CURRENT schema: read the version the
    // plugin-loaded migrate() wrote, over a raw client. Checked before the direct connect below,
    // because `PostgresStore::connect` runs migrate() itself and would write this row if the boot
    // had not.
    let mut raw = postgres::Client::connect(&url, postgres::NoTls)
        .expect("raw connect to the fresh database");
    let version: i64 = raw
        .query_one("SELECT COALESCE(MAX(version), 0) FROM busbar_schema", &[])
        .expect("the boot must have created busbar_schema")
        .get(0);
    assert!(
        version > 0,
        "the plugin-loaded boot must have written a schema version, got {version}"
    );
    // And the process is still alive, serving on that store, rather than having created the schema
    // and died: a crashed child is exactly what the poll above cannot distinguish on its own.
    assert!(
        matches!(guard.0.try_wait(), Ok(None)),
        "the real busbar boot must still be running on the file-dropped postgres store, not have \
         exited after creating the schema"
    );

    // Only AFTER those proofs: a second, independent PostgresStore::connect (bypassing the
    // plugin/ABI/loader entirely) confirms the store type itself can talk to the same schema the
    // real boot process just created.
    let _direct = PostgresStore::connect(&url).expect(
        "connect directly, bypassing the plugin entirely, to confirm the schema the real boot \
         created is usable",
    );

    drop(_direct);
    drop(raw);
    drop(guard); // explicit: stop the real busbar process before dropping its database
    let _ = std::fs::remove_dir_all(&work);
    drop_database(&admin_url, &db);
}

/// END-TO-END FAILURE (ABI-contract unit test, see module doc for why this stays a direct
/// `load_store()` call): an `open()` config that cannot produce a usable store surfaces back across
/// the C ABI as a clean `Err`, never a panic or a silently-succeeded load.
#[test]
fn load_and_exercise_postgres_plugin_bad_config_fails_over_abi() {
    let Some(path) = plugin_path() else {
        eprintln!("skip: store-postgres-plugin cdylib not built");
        return;
    };

    let err = busbar_plugin_loader::load_store(&path, "{ not json")
        .err()
        .expect("malformed config JSON must fail to load, not silently succeed");
    assert!(
        err.contains("invalid postgres plugin config"),
        "the plugin's own error message should survive the ABI crossing intact: {err}"
    );

    let err = busbar_plugin_loader::load_store(&path, "{}")
        .err()
        .expect("a config missing url must fail to load");
    assert!(
        err.contains("requires a \"url\""),
        "expected the plugin's own missing-url message, got: {err}"
    );

    let err = busbar_plugin_loader::load_store(
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

/// A non-plugin library (or a missing file) is refused with a clear error, never a crash. Same
/// ABI-contract-unit-test rationale as above.
#[test]
fn refuses_non_plugin() {
    let err = match busbar_plugin_loader::load_store(
        std::path::Path::new("/definitely/not/a/plugin.so"),
        "{}",
    ) {
        Err(e) => e,
        Ok(_) => panic!("a missing library must not load"),
    };
    assert!(err.contains("failed to load plugin"), "got: {err}");
}
