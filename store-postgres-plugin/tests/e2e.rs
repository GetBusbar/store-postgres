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
///
/// It also owns the file this child's stdout+stderr were redirected to, and that is load-bearing
/// rather than bookkeeping. This boot used to run with `.stderr(Stdio::null())`, so a failed boot
/// could only ever report an exit code while busbar's own explanation was discarded at the point it
/// was produced. That cost `admin_api_e2e.rs` a qa-gate leg once already, and it matters more here:
/// this test boots against a database that has never existed before, so a first-run-only failure
/// has no other trace anywhere.
///
/// A FILE, not `Stdio::piped()`: nothing reads the pipe while the child runs, so a child that
/// out-talked the pipe buffer would block forever on write and turn a clean failure into a hang.
struct ChildGuard(Child, PathBuf);

impl ChildGuard {
    fn output(&self) -> String {
        std::fs::read_to_string(&self.1).unwrap_or_else(|e| format!("<log unreadable: {e}>"))
    }
}

impl Drop for ChildGuard {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

/// A disposable database that drops itself on drop, panic path included. Written as a trailing
/// statement, the cleanup only ran when the test passed, so every red run leaked a fully migrated
/// database under a pid+nanos name that nothing would ever reclaim.
struct TempDb {
    admin_url: String,
    name: String,
}

impl TempDb {
    fn create(admin_url: &str, prefix: &str) -> Self {
        let name = format!(
            "{prefix}_{}_{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        );
        let mut maint = postgres::Client::connect(admin_url, postgres::NoTls)
            .expect("connect to create the disposable database");
        let _ = maint.execute(&format!("DROP DATABASE IF EXISTS {name}"), &[]);
        maint
            .execute(&format!("CREATE DATABASE {name}"), &[])
            .expect("the boot proof needs its own empty database");
        Self {
            admin_url: admin_url.to_string(),
            name,
        }
    }

    /// Rewrite the admin DSN to name this database, keeping the credentials. The shape is the one
    /// this crate's own fixtures and `dsn_password` already assume.
    fn url(&self) -> String {
        let rest = self
            .admin_url
            .split("://")
            .nth(1)
            .expect("url must have a scheme");
        let (userinfo, host_and_db) = rest.rsplit_once('@').expect("url must have userinfo");
        let (host_port, _) = host_and_db
            .split_once('/')
            .expect("url must have a db path");
        format!("postgres://{userinfo}@{host_port}/{}", self.name)
    }
}

impl Drop for TempDb {
    fn drop(&mut self) {
        if let Ok(mut maint) = postgres::Client::connect(&self.admin_url, postgres::NoTls) {
            let _ = maint.execute(
                &format!("DROP DATABASE IF EXISTS {} WITH (FORCE)", self.name),
                &[],
            );
        }
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

/// Locate the cdylib THIS `cargo test` invocation just built — never a leftover artifact.
///
/// This looks ONLY in `target/<profile>/deps/`, never `target/<profile>/`, and that distinction is
/// the whole point of this function.
///
/// `cargo` emits the lib target's cdylib into `deps/` as part of the very build graph that produces
/// this test binary (this package's lib unit is compiled with BOTH declared crate-types — see
/// `[lib] crate-type = ["cdylib", "rlib"]` in Cargo.toml), so `deps/libbusbar_store_postgres_plugin.dylib` is by construction up to
/// date with the source tree under test. Cargo only *uplifts* a copy to `target/<profile>/` for
/// `cargo build`, NEVER for `cargo test`. A lookup in `target/<profile>/` therefore reads an
/// artifact that nothing in this test's dependency graph refreshes: whatever some earlier `cargo
/// build` left there, from any commit — or nothing at all.
///
/// Both outcomes of that are lies about durability, and the second is the dangerous one:
///   * NOTHING there  -> the old code `return`ed with a "skip:" line and reported GREEN. That is how
///     `cargo test` can pass with ZERO over-the-ABI coverage of the durable store path.
///   * STALE artifact -> a cdylib built before an ABI change answers every write `Ok(())` and every
///     read empty, which is BYTE-FOR-BYTE the signature of the unrelayed-seam defect this file
///     exists to catch (that defect was real: `DynStore`'s `impl Store` overrode 24 methods, none of
///     them the task/call-log methods, so `put_task` took the accept-and-keep-nothing trait
///     default). RED on a stale artifact is indistinguishable from RED on the real bug — and an
///     artifact NEWER than a regression reports GREEN while the shipped ABI is broken. Proven, not
///     theorised: with a regressed plugin in the tree and a good cdylib in `target/debug/`, the old
///     lookup passed and this one fails.
///
/// Same hazard, and the same reasoning, as the engine's `crates/busbar/Cargo.toml` dev-dependency on
/// `busbar-store-example-plugin`: keep the cdylib in the build graph so no test can judge a stale
/// one. Here the plugin's lib IS this package, so that graph edge already exists — what was missing
/// was reading the artifact that edge actually produces.
///
/// Panics rather than skipping: a missing cdylib under `cargo test` means the build graph changed
/// shape, and the only honest report of that is a failure, not a silent pass.
/// The newest mtime across every workspace crate's `src/` — "how fresh must a cdylib be to be the
/// one this source tree describes".
///
/// Deliberately ONLY `src/**/*.rs` of each workspace member: editing a `tests/` file or a
/// `[dev-dependencies]` line recompiles the test binary but NOT the lib, so including those would
/// fail a perfectly current cdylib.
fn newest_source_mtime() -> std::time::SystemTime {
    fn walk(dir: &std::path::Path, newest: &mut std::time::SystemTime) {
        let Ok(rd) = std::fs::read_dir(dir) else {
            return;
        };
        for e in rd.flatten() {
            let p = e.path();
            if p.is_dir() {
                walk(&p, newest);
            } else if p.extension().is_some_and(|x| x == "rs") {
                if let Ok(m) = e.metadata().and_then(|m| m.modified()) {
                    if m > *newest {
                        *newest = m;
                    }
                }
            }
        }
    }
    let ws_root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("the plugin crate always sits under the workspace root");
    let mut newest = std::time::SystemTime::UNIX_EPOCH;
    for e in std::fs::read_dir(ws_root).into_iter().flatten().flatten() {
        let src = e.path().join("src");
        if src.is_dir() {
            walk(&src, &mut newest);
        }
    }
    newest
}

fn plugin_path() -> PathBuf {
    let exe = std::env::current_exe().expect("current_exe"); // .../target/<profile>/deps/<test>-<hash>
    let deps_dir = exe.parent().expect("the test binary always lives in deps/");
    let name = busbar_plugin_loader::plugin_library_filename("busbar_store_postgres_plugin");
    let fresh = deps_dir.join(&name);
    assert!(
        fresh.exists(),
        "the store-postgres-plugin cdylib is not at {}, where cargo emits it for the same build that produced \
         this test binary. Refusing to fall back to target/<profile>/ (an artifact only `cargo \
         build` refreshes) or to skip: judging a stale cdylib is exactly how an unrelayed plugin \
         ABI reads as green.",
        fresh.display()
    );
    // FRESHNESS, ASSERTED — not assumed. Under `cargo test` the artifact above is rebuilt by the
    // same graph that built this binary (proven: delete it, re-run, cargo re-emits it). But this
    // test binary can also be executed DIRECTLY out of `deps/`, where nothing rebuilds anything,
    // and a stale cdylib there produces empty reads — indistinguishable from the unrelayed-ABI
    // defect. So compare it against the sources and fail with a message that says STALE ARTIFACT,
    // explicitly NOT a durability verdict.
    let built = std::fs::metadata(&fresh)
        .and_then(|m| m.modified())
        .expect("cdylib mtime");
    let newest_src = newest_source_mtime();
    assert!(
        built >= newest_src,
        "STALE ARTIFACT — THIS IS NOT A DURABILITY FAILURE. {} predates this workspace's sources, \
         so it cannot answer for the code in the tree; a pre-change cdylib returns empty for every \
         read, which reads exactly like an unrelayed plugin ABI. Run `cargo build -p {}` (or just \
         `cargo test`, which rebuilds it) and re-run.",
        fresh.display(),
        "busbar-store-postgres-plugin"
    );
    fresh
}

fn cfg(url: &str) -> String {
    serde_json::json!({ "url": url }).to_string()
}

/// Every `env:` secret-ref name a config text references, in first-seen order, de-duplicated.
///
/// busbar 1.5.3 made `--validate` RESOLVE built-in (`env`/`file`) secret references and exit 1 when
/// one cannot resolve, rather than only checking the reference's SHAPE. The fixture below names a
/// real-looking env var (`MOCK_KEY`), so `--validate` failed on any machine that does not happen to
/// have it set -- which is every CI runner and most dev machines:
///
///   [error] providers.mock.api_key: secret env:MOCK_KEY cannot resolve: environment variable
///   'MOCK_KEY' is unset
///
/// Hardcoding `MOCK_KEY` here would fix today's failure but rot the moment this fixture, or a future
/// one, names a different variable. Extracting the names generically is the approach the sibling
/// `GetBusbar/store-sqlite` and `GetBusbar/store-mysql` plugin e2e tests already took for this exact
/// break (and the core repo's `crates/busbar/tests/docs_examples.rs`), so the harness keeps working
/// no matter what the fixture references.
fn referenced_env_vars(text: &str) -> Vec<String> {
    let mut v: Vec<String> = Vec::new();
    for (i, _) in text.match_indices("env:") {
        let rest = &text[i + 4..];
        let name: String = rest
            .chars()
            .skip_while(|c| c.is_whitespace())
            .take_while(|c| c.is_ascii_alphanumeric() || *c == '_')
            .collect();
        if !name.is_empty() && !v.contains(&name) {
            v.push(name);
        }
    }
    v
}

/// Set a harmless placeholder for every `{ env: NAME }` `config_text` references, so `--validate`
/// (which now resolves built-in secrets, see `referenced_env_vars`) has something to resolve.
/// 64 hex chars: valid for `auth.signing_key`, and harmless as any other secret's value.
fn set_referenced_secret_envs(cmd: &mut Command, config_text: &str) {
    for name in referenced_env_vars(config_text) {
        cmd.env(
            name,
            "0000000000000000000000000000000000000000000000000000000000000001",
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
    // `plugin_path()` panics on a missing-or-stale cdylib rather than returning None and skipping:
    // a skip here reports green with zero over-the-ABI coverage, which is the failure mode the
    // freshness guard exists to make impossible.
    let so_path = plugin_path();

    // A DISPOSABLE, genuinely empty database. The schema this test polls for can then only have
    // come from the boot under test. The guard drops it on the panic path too, so a red run does
    // not leave a migrated database behind on the shared server forever.
    let tmp = TempDb::create(&admin_url, "spg_filedrop");
    let url = tmp.url();

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
    let config_text = format!(
        "listen: \"127.0.0.1:0\"\n\
         store:\n  module: postgres\n  settings: {{ url: \"{url}\" }}\n\
         plugins:\n  enabled: true\n  dir: {}\n  trust:\n    allow_unsigned: true\n\
         auth:\n  chain: []\n\
         providers:\n  mock:\n    api_key: {{ env: MOCK_KEY }}\n\
         models:\n  test-model:\n    provider: mock\n",
        plugins_dir.display()
    );
    std::fs::write(&config, &config_text).unwrap();

    // `--validate` is DELIBERATELY not used for the load-proof itself: it is manifest-only by
    // design ("no server, no network, no state, no dlopen" -- crates/busbar/src/main.rs's own
    // `--help` text) and never opens the store. A clean `--validate` run first proves the
    // file-dropped plugin passes the trust/manifest gate; then a REAL BOOT (no `--validate` flag,
    // below) is the only thing that actually `dlopen`s the plugin and runs
    // `Store::connect`/migration.
    //
    // Busbar 1.5.3 made `--validate` RESOLVE built-in (`env`/`file`) secret references and fail
    // when one cannot, instead of only checking the reference's shape -- so `providers.mock.
    // api_key: { env: MOCK_KEY }` above now needs MOCK_KEY set, or this call fails on THIS
    // MACHINE's environment rather than on anything about the plugin under test. Extracted
    // generically (`set_referenced_secret_envs`) rather than hardcoded, so this fixture gaining or
    // renaming a variable does not rot the harness.
    let mut validate_cmd = Command::new(&busbar_bin);
    validate_cmd
        .arg("--validate")
        .env("BUSBAR_CONFIG", &config)
        .env("BUSBAR_PROVIDERS", &providers);
    set_referenced_secret_envs(&mut validate_cmd, &config_text);
    let out = validate_cmd.output().expect("run busbar --validate");
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
    let boot_log = work.join("boot.log");
    let boot_log_out = std::fs::File::create(&boot_log).expect("create the boot log");
    let boot_log_err = boot_log_out.try_clone().expect("dup the boot log handle");
    let mut boot_cmd = Command::new(&busbar_bin);
    boot_cmd
        .env("BUSBAR_CONFIG", &config)
        .env("BUSBAR_PROVIDERS", &providers)
        .env("BUSBAR_STATE_FILE", "") // disable the state-snapshot file; not under test here
        .stdout(Stdio::from(boot_log_out))
        .stderr(Stdio::from(boot_log_err));
    // The REAL BOOT resolves `env:` secret references too, not just `--validate`, so it needs the
    // same placeholders the validate run above got.
    set_referenced_secret_envs(&mut boot_cmd, &config_text);
    let child = boot_cmd.spawn().expect("spawn a real busbar boot");
    let mut guard = ChildGuard(child, boot_log);

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
            panic!(
                "busbar exited before creating the postgres schema (status: {status})\n\
                 --- boot output ---\n{}",
                guard.output()
            );
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
         during boot, not a no-op\n--- boot output ---\n{}",
        guard.output()
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
         exited after creating the schema\n--- boot output ---\n{}",
        guard.output()
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
}

/// END-TO-END FAILURE (ABI-contract unit test, see module doc for why this stays a direct
/// `load_store()` call): an `open()` config that cannot produce a usable store surfaces back across
/// the C ABI as a clean `Err`, never a panic or a silently-succeeded load.
#[test]
fn load_and_exercise_postgres_plugin_bad_config_fails_over_abi() {
    let path = plugin_path();

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

/// THE DURABILITY PROOF FOR THE FOUR MCP CALL-LOG METHODS, OVER THE REAL PLUGIN PATH.
///
/// This repo ships `feat/durable-mcp-call-log` — `append_mcp_call`/`list_mcp_calls`/
/// `list_mcp_call_principals`/`purge_mcp_calls_before` against a real Postgres. Every existing test
/// of those four calls `PostgresStore` DIRECTLY, in-process, and NONE of them can see the failure
/// that actually matters in production, because in production this backend is ONLY ever reached as a
/// plugin: conformance boots the in-process RAM store, so the plugin seam is the only path a real
/// deployment takes and was, until this test, the one path with zero coverage of these methods.
///
/// `busbar_api::Store` DEFAULTS all ten task/call-log methods to accept-and-keep-nothing. A plugin
/// seam that does not RELAY them silently substitutes those defaults: every `append_mcp_call`
/// returns `Ok`, every `list_mcp_calls` answers empty, and a deployment loses every tool-call record
/// while reporting success. That is not hypothetical — the ABI once carried four store methods while
/// the trait carried ten, so exactly this happened. A unit test passing while the ABI drops every
/// write is the precise shape this test exists to make impossible.
///
/// So it goes through `busbar_plugin_loader::load_store`: a REAL `dlopen` of the built cdylib, the
/// real C ABI, the real `DynStore`. It writes AT ARITY > 1 (three chained records for one principal
/// and one for a second), DROPS the handle — which runs `busbar_close` and UNLOADS the library, so
/// nothing this process still holds can answer the reads — then `dlopen`s AGAIN over the same file
/// and reads everything back. A restart is what proves durability; a single-row same-session round
/// trip would not distinguish a relayed method from a lucky trait default, and a multi-row one
/// across an unload/reload cannot be faked by either.
///
/// A third leg reads the same rows through the plain `PostgresStore`, never touching the cdylib, the
/// C ABI or the loader — so a plugin that answered from its own in-process cache still fails here.
#[test]
fn mcp_call_log_survives_an_unload_and_reload_over_the_real_plugin_abi() {
    use busbar_api::{McpCallRecord, Store};

    let path = plugin_path();
    let Some(url) = postgres_url() else {
        return;
    };
    let cfg = cfg(&url);

    // Start from an EMPTY call log. `list_mcp_call_principals` and `purge_mcp_calls_before` are
    // GLOBAL, not per-principal, so against a re-used database a leftover chain from an earlier run
    // would make both of their exact assertions below meaningless. `purge_mcp_calls_before(MAX)` is
    // the store's own contract-level wipe, so this needs no raw-SQL knowledge of the schema. No
    // other test in this file touches `mcp_calls`.
    let direct = PostgresStore::connect(&url).expect("connect directly to clean up and verify");
    Store::purge_mcp_calls_before(&direct, u64::MAX).expect("wipe the call log before this run");

    // Per-run principal ids: a read that only THIS run's writes can answer. Two of them, because one
    // principal's chain leaking into another's is a real defect class and a single-principal test is
    // blind to it.
    let stamp = format!(
        "{}_{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    );
    let p_main = format!("vk_abi_main_{stamp}");
    let p_other = format!("vk_abi_other_{stamp}");

    let call = |principal: &str, seq: u64, prev: &str, hash: &str| McpCallRecord {
        principal: principal.to_string(),
        seq,
        ts: 2_000 + seq,
        server: "srv".to_string(),
        tool: "srv_read_file".to_string(),
        outcome: "dispatched".to_string(),
        reason: String::new(),
        tool_digest: format!("sha256:tool{seq}"),
        pin_generation: 3,
        request_id: format!("req-{seq}"),
        prev_hash: prev.to_string(),
        hash: hash.to_string(),
    };

    {
        // BOOT 1 — a real dlopen of the cdylib; every call below crosses the C ABI.
        let store = busbar_plugin_loader::load_store(&path, &cfg)
            .expect("the postgres plugin must load over the real ABI");
        for (seq, prev, hash) in [(1_u64, "", "h1"), (2, "h1", "h2"), (3, "h2", "h3")] {
            store
                .append_mcp_call(&call(&p_main, seq, prev, hash))
                .expect("append_mcp_call over the ABI");
        }
        store
            .append_mcp_call(&call(&p_other, 1, "", "o1"))
            .expect("append_mcp_call over the ABI");
        // Dropping the boxed store drops the loader's `Library` handle: `busbar_close` runs and the
        // dylib is UNLOADED. Nothing this process still holds can be answering the reads below.
        drop(store);
    }

    // BOOT 2 — a second, independent dlopen over the same file, a fresh `busbar_open`, a fresh
    // connection inside the plugin.
    let store = busbar_plugin_loader::load_store(&path, &cfg)
        .expect("the postgres plugin must load again over the real ABI");

    let calls = store.list_mcp_calls(&p_main).expect("list_mcp_calls");
    assert_eq!(
        calls.iter().map(|c| c.seq).collect::<Vec<_>>(),
        vec![1, 2, 3],
        "the per-principal call chain must survive the unload/reload over the plugin ABI in chain \
         order; got {} record(s) back, which is the accept-and-keep-nothing shape of the trait \
         default an unrelayed seam substitutes",
        calls.len()
    );
    for w in calls.windows(2) {
        assert_eq!(
            w[1].prev_hash, w[0].hash,
            "the chain must still link after the reload: seq {} carries prev_hash {:?} but seq {} \
             persisted hash {:?}",
            w[1].seq, w[1].prev_hash, w[0].seq, w[0].hash
        );
    }
    // Every non-indexed field rides the `body` column; a relay that dropped it would still satisfy a
    // seq-only check.
    assert_eq!(calls[2].tool_digest, "sha256:tool3");
    assert_eq!(calls[2].request_id, "req-3");
    assert_eq!(calls[2].tool, "srv_read_file");
    assert_eq!(calls[2].outcome, "dispatched");
    assert_eq!(calls[1].pin_generation, 3);
    assert_eq!(
        store
            .list_mcp_calls(&p_other)
            .expect("list_mcp_calls")
            .len(),
        1,
        "one principal's chain must not carry another's records"
    );

    let principals = store
        .list_mcp_call_principals()
        .expect("list_mcp_call_principals");
    assert_eq!(
        principals,
        vec![p_main.clone(), p_other.clone()],
        "the boot enumeration must name every principal holding records, exactly once each"
    );

    // Retention crosses the ABI too, COUNT AND ALL — checked for the number it ACTUALLY removed,
    // because a relay that dropped the return value would read as 0 and look like a no-op sweep.
    assert_eq!(
        store.purge_mcp_calls_before(2_002).expect("purge"),
        2,
        "both records at ts 2001 go (one per principal); the one sitting exactly at the cutoff stays"
    );
    assert_eq!(
        store.list_mcp_calls(&p_main).expect("list_mcp_calls").len(),
        2
    );
    assert!(store
        .list_mcp_calls(&p_other)
        .expect("list_mcp_calls")
        .is_empty());
    assert_eq!(
        store
            .list_mcp_call_principals()
            .expect("list_mcp_call_principals"),
        vec![p_main.clone()],
        "a principal whose chain the sweep emptied must leave the enumeration, or a boot keeps \
         resuming a chain with nothing in it"
    );
    drop(store);

    // LEG 3 — read the surviving rows through the plain `PostgresStore`, a code path that never
    // touches the cdylib, the C ABI or the loader. A plugin answering the reads above out of its own
    // in-process state (rather than Postgres) passes both boots and fails here.
    let direct_calls =
        Store::list_mcp_calls(&direct, &p_main).expect("list_mcp_calls via the direct connection");
    assert_eq!(
        direct_calls.iter().map(|c| c.seq).collect::<Vec<_>>(),
        vec![2, 3],
        "the records must be physically present in Postgres, not just cached in-process by the plugin"
    );
    assert_eq!(direct_calls[1].hash, "h3");

    Store::purge_mcp_calls_before(&direct, u64::MAX).expect("clean up this run's records");
}

/// THE DURABILITY PROOF FOR THE SIX A2A TASK-STORE METHODS, OVER THE REAL PLUGIN PATH.
///
/// The sibling proof above does this for the MCP call log; this one exists because the task methods
/// are a SEPARATE half of the same defaulted seam and half the fleet used to be missing them.
/// `busbar_api::Store` defaults `put_task` to `Ok(())`, `get_task` to `Ok(None)` and `list_tasks` to
/// `Ok(vec![])`: a backend that does not override them ACCEPTS EVERY WRITE AND REPORTS SUCCESS while
/// keeping nothing. An operator would find "task state survives a restart" false on their own
/// deployment, which is the worst place to discover it.
///
/// The conformance suite cannot see this: it boots the in-process RAM store, where those defaults
/// ARE the honest answer and nothing looks wrong. The plugin seam is the ONLY path a real Postgres
/// deployment takes, so it is the only path worth proving on. A unit test against `PostgresStore`
/// proves the function compiles and works in-process; it does not prove the plugin path reaches it.
///
/// So: a REAL `dlopen` of the built cdylib, the real C ABI, the real `DynStore`. Write at arity > 1
/// (two tasks, one of them UPSERTED a second time, plus two independent provenance chains), DROP the
/// handle — `busbar_close` runs and the library is unloaded, so nothing this process still holds can
/// answer the reads — then `dlopen` again and read everything back. A third leg reads the same rows
/// through the plain `PostgresStore`, never touching the cdylib, so a plugin answering out of its own
/// in-process cache still fails.
#[test]
fn task_store_survives_an_unload_and_reload_over_the_real_plugin_abi() {
    use busbar_api::{Store, TaskEventRow, TaskRow};

    let path = plugin_path();
    let Some(url) = postgres_url() else {
        return;
    };
    let cfg = cfg(&url);

    // Start from an EMPTY task table. `purge_tasks_before` is GLOBAL and terminal-only, and the
    // count it returns is asserted exactly below, so a leftover terminal row from an earlier run
    // would make that assertion meaningless. `purge_tasks_before(MAX)` is the store's own
    // contract-level wipe of exactly that population, so this needs no raw-SQL knowledge.
    let direct = PostgresStore::connect(&url).expect("connect directly to clean up and verify");
    Store::purge_tasks_before(&direct, u64::MAX).expect("wipe terminal tasks before this run");

    let stamp = format!(
        "{}_{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    );
    // Per-run ids, so every read below can only be answered by THIS run's writes.
    let t_live = format!("task_abi_live_{stamp}");
    let t_done = format!("task_abi_done_{stamp}");

    // A timestamp BAND well above any plausible leftover, so the purge cutoff picked below names
    // this run's rows and nothing else.
    const BASE_TS: u64 = 4_000_000_000;

    let task = |id: &str, state: &str, updated_at: u64, cursor: u64| TaskRow {
        task_id: id.to_string(),
        context_id: format!("ctx-{id}"),
        principal: "vk_task_abi".to_string(),
        direction: "inbound".to_string(),
        state: state.to_string(),
        agent_id: "agent-7".to_string(),
        artifact_cursor: cursor,
        push_callback: "https://callback.example/hook".to_string(),
        created_at: BASE_TS,
        updated_at,
    };
    let event = |id: &str, seq: u64, kind: &str, prev: &str, hash: &str| TaskEventRow {
        task_id: id.to_string(),
        seq,
        ts: BASE_TS + seq,
        kind: kind.to_string(),
        context_id: format!("ctx-{id}"),
        principal: "vk_task_abi".to_string(),
        agent_id: "agent-7".to_string(),
        state: "working".to_string(),
        request_id: format!("req-{seq}"),
        prev_hash: prev.to_string(),
        hash: hash.to_string(),
    };

    {
        // BOOT 1 — a real dlopen of the cdylib; every call below crosses the C ABI.
        let store = busbar_plugin_loader::load_store(&path, &cfg)
            .expect("the postgres plugin must load over the real ABI");
        store
            .put_task(&task(&t_live, "working", BASE_TS + 100, 3))
            .expect("put_task over the ABI");
        // The SECOND write for the same id: the engine writes through on every state transition, so
        // this must REPLACE the row, never append a second one. An interrupted task waiting on a
        // human is exactly what a restart has to find.
        store
            .put_task(&task(&t_live, "input-required", BASE_TS + 200, 9))
            .expect("put_task over the ABI");
        store
            .put_task(&task(&t_done, "completed", BASE_TS + 50, 1))
            .expect("put_task over the ABI");
        // Two INDEPENDENT chains: per-task provenance that leaked across tasks is a real defect
        // class, and a single-chain test is blind to it.
        for (seq, prev, hash) in [(1_u64, "", "h1"), (2, "h1", "h2"), (3, "h2", "h3")] {
            store
                .append_task_event(&event(&t_live, seq, "task.working", prev, hash))
                .expect("append_task_event over the ABI");
        }
        store
            .append_task_event(&event(&t_done, 1, "task.completed", "", "d1"))
            .expect("append_task_event over the ABI");
        // Dropping the boxed store drops the loader's `Library` handle: `busbar_close` runs and the
        // dylib is UNLOADED. Nothing this process still holds can be answering the reads below.
        drop(store);
    }

    // BOOT 2 — a second, independent dlopen over the same file, a fresh `busbar_open`, a fresh
    // connection inside the plugin.
    let store = busbar_plugin_loader::load_store(&path, &cfg)
        .expect("the postgres plugin must load again over the real ABI");

    let got = store.get_task(&t_live).expect("get_task").expect(
        "an in-flight task must survive the unload/reload over the plugin ABI; got None back, \
         which is exactly the accept-and-keep-nothing shape of the trait default an unimplemented \
         backend (or an unrelayed seam) substitutes",
    );
    assert_eq!(
        got,
        task(&t_live, "input-required", BASE_TS + 200, 9),
        "every field must round-trip, and the row read back must be the SECOND write: put_task \
         upserts by task_id"
    );
    assert!(
        store
            .get_task(&format!("task_abi_nonexistent_{stamp}"))
            .expect("get_task on an unknown id is not an error")
            .is_none(),
        "an unknown task id reads back None, not an error"
    );

    let listed = store.list_tasks().expect("list_tasks");
    let mine = listed
        .iter()
        .filter(|t| t.task_id == t_live || t.task_id == t_done)
        .map(|t| t.task_id.clone())
        .collect::<Vec<_>>();
    assert_eq!(
        mine,
        vec![t_done.clone(), t_live.clone()],
        "list_tasks is UNFILTERED — the terminal row is returned too — and the upserted task \
         appears exactly ONCE; got {} of this run's rows back",
        mine.len()
    );

    let events = store.list_task_events(&t_live).expect("list_task_events");
    assert_eq!(
        events.iter().map(|e| e.seq).collect::<Vec<_>>(),
        vec![1, 2, 3],
        "the per-task provenance chain must survive the reload, oldest-first by seq; got {} \
         event(s), the empty shape of the trait default",
        events.len()
    );
    for w in events.windows(2) {
        assert_eq!(
            w[1].prev_hash, w[0].hash,
            "the chain must still link after the reload: seq {} carries prev_hash {:?} but seq {} \
             persisted hash {:?}",
            w[1].seq, w[1].prev_hash, w[0].seq, w[0].hash
        );
    }
    assert_eq!(events[2].kind, "task.working");
    assert_eq!(events[2].request_id, "req-3");
    assert_eq!(
        store
            .list_task_events(&t_done)
            .expect("list_task_events")
            .len(),
        1,
        "one task's chain must not carry another's events"
    );

    // The task-event contract UPSERTS on (task_id, seq) — the engine's write-through is idempotent
    // on replay, and rejecting or duplicating a replayed seq breaks the chain it will verify.
    let mut replayed = event(&t_live, 3, "task.working", "h2", "h3");
    replayed.state = "input-required".to_string();
    store
        .append_task_event(&replayed)
        .expect("a replayed (task_id, seq) upserts rather than erroring");
    let events = store.list_task_events(&t_live).expect("list_task_events");
    assert_eq!(
        events.len(),
        3,
        "a replayed seq must not append a 4th event"
    );
    assert_eq!(events[2].state, "input-required");

    // Retention crosses the ABI too, COUNT AND ALL — checked for the number it ACTUALLY removed,
    // because a relay that dropped the return value would read as 0 and look like a no-op sweep.
    assert_eq!(
        store
            .purge_tasks_before(BASE_TS + 100)
            .expect("purge_tasks_before"),
        1,
        "only the TERMINAL row older than the cutoff goes; the interrupted task is never swept no \
         matter how old, because an interrupt waiting on a human is exactly the row that \
         legitimately sits still"
    );
    assert!(
        store.get_task(&t_done).expect("get_task").is_none(),
        "the purged task is gone"
    );
    assert!(
        store.get_task(&t_live).expect("get_task").is_some(),
        "a non-terminal task is never purged"
    );
    assert!(
        store
            .list_task_events(&t_done)
            .expect("list_task_events")
            .is_empty(),
        "the purge is the ONLY retention method the contract gives task_events, so a swept task's \
         chain must go with it or it is unbounded forever"
    );
    drop(store);

    // LEG 3 — read the surviving row through the plain `PostgresStore`, a code path that never
    // touches the cdylib, the C ABI or the loader. A plugin answering the reads above out of its own
    // in-process state (rather than Postgres) passes both boots and fails here.
    let direct_task = Store::get_task(&direct, &t_live)
        .expect("get_task via the direct connection")
        .expect("the task must be physically present in Postgres, not just cached in-process");
    assert_eq!(direct_task.artifact_cursor, 9);
    assert_eq!(direct_task.state, "input-required");
    assert_eq!(
        Store::list_task_events(&direct, &t_live)
            .expect("list_task_events via the direct connection")
            .len(),
        3
    );

    // Clean up this run's rows through the contract: mark the survivor terminal, then sweep.
    Store::put_task(&direct, &task(&t_live, "canceled", BASE_TS + 200, 9))
        .expect("clean up this run's task");
    Store::purge_tasks_before(&direct, u64::MAX).expect("clean up this run's rows");
}

/// THE DURABILITY PROOF FOR THE FOUR TRUST-STATE METHODS, OVER THE REAL PLUGIN PATH.
///
/// Same reasoning as the task-store test above, and a sharper cost. `busbar_api::Store` defaults
/// `put_mcp_demotion`/`list_mcp_demotions`/`clear_mcp_demotion` to accept-and-keep-nothing and
/// `redeem_ask_state` to `Ok(true)` — "yes, this call is the first redemption" — so a seam that does
/// not RELAY them substitutes two security failures, both silent and both green:
///
///   * a demotion is written, reported successful and DISCARDED, so a restart hands a quarantined
///     upstream the operator's approval back; and
///   * every redeemer of one single-use approval is told it is the first, so a confirm-once tool an
///     operator gated because it moves money executes once per node and once per restart.
///
/// A real Postgres deployment reaches this backend ONLY over the plugin seam, so that is the path
/// worth proving on: a real `dlopen`, the real C ABI, the real `DynStore`. Two simultaneous loads
/// are the fleet; a drop and a reload is the restart; and a third leg reads through the plain
/// `PostgresStore`, never touching the cdylib, so a plugin answering out of its own in-process state
/// still fails.
///
/// PANICS rather than skipping when no Postgres is configured. These are the only over-the-ABI
/// coverage of two properties whose unimplemented form is silently green, and a case that can skip
/// is a case that will skip on the day it matters.
#[test]
fn trust_state_survives_an_unload_and_reload_over_the_real_plugin_abi() {
    use busbar_api::{McpDemotionRow, Store};

    let path = plugin_path();
    let url = std::env::var("BUSBAR_TEST_POSTGRES_URL").unwrap_or_else(|_| {
        panic!(
            "BUSBAR_TEST_POSTGRES_URL is unset, and this case must not skip: it is the only \
             over-the-ABI proof that a demotion and a spent approval survive a restart on this \
             backend, and both fail SILENTLY when unrelayed — the trait defaults answer `Ok(())` to \
             a demotion and `true` to every redemption"
        )
    });
    let cfg = cfg(&url);

    let stamp = format!(
        "{}_{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    );
    // Per-run ids, so every read below can only be answered by THIS run's writes, and so two runs
    // against one shared Postgres cannot redeem each other's approvals.
    let srv_demoted = format!("srv_abi_demoted_{stamp}");
    let srv_cleared = format!("srv_abi_cleared_{stamp}");
    let nonce_restart = format!("nonce_abi_restart_{stamp}");
    let nonce_fleet = format!("nonce_abi_fleet_{stamp}");
    let nonce_fresh = format!("nonce_abi_fresh_{stamp}");
    const NOW: u64 = 4_000_000_000;

    let demotion = |server: &str, reason: &str, at: u64| McpDemotionRow {
        server: server.to_string(),
        reason: reason.to_string(),
        recorded_at: at,
    };

    {
        // BOOT 1 — a real dlopen of the cdylib; every call below crosses the C ABI.
        let store = busbar_plugin_loader::load_store(&path, &cfg)
            .expect("the postgres plugin must load over the real ABI");
        store
            .put_mcp_demotion(&demotion(&srv_demoted, "tool-drift", NOW))
            .expect("put_mcp_demotion");
        // The UPSERT path crosses the ABI too: a second demotion of one upstream replaces the row.
        store
            .put_mcp_demotion(&demotion(&srv_demoted, "digest-mismatch", NOW + 10))
            .expect("put_mcp_demotion");
        store
            .put_mcp_demotion(&demotion(&srv_cleared, "tool-drift", NOW + 20))
            .expect("put_mcp_demotion");
        store
            .clear_mcp_demotion(&srv_cleared)
            .expect("a later agreeing observation clears the quarantine");
        assert!(
            store
                .redeem_ask_state(&nonce_restart, NOW + 900, NOW)
                .expect("redeem_ask_state"),
            "the FIRST redemption must be answered `true`, or nothing below is about single use"
        );
        // Dropping the boxed store runs `busbar_close` and unloads the library, so nothing this
        // process still holds can be answering the reads below.
        drop(store);
    }

    // BOOT 2 — a second, independent dlopen against the same database.
    let store = busbar_plugin_loader::load_store(&path, &cfg)
        .expect("the postgres plugin must load again over the real ABI");

    let rows = store.list_mcp_demotions().expect("list_mcp_demotions");
    let mine = rows
        .iter()
        .filter(|r| r.server == srv_demoted || r.server == srv_cleared)
        .cloned()
        .collect::<Vec<_>>();
    assert_eq!(
        mine,
        vec![demotion(&srv_demoted, "digest-mismatch", NOW + 10)],
        "the boot read must put the recorded quarantine back in force — at its LATEST reason, and \
         without the one a later agreeing observation cleared. An empty answer here is the \
         accept-and-keep-nothing trait default an unrelayed seam substitutes, and it means a \
         restart hands a demoted upstream the operator's approval back"
    );

    assert!(
        !store
            .redeem_ask_state(&nonce_restart, NOW + 900, NOW + 1)
            .expect("redeem_ask_state"),
        "a restart handed a spent approval back over the plugin ABI. The approval has not lapsed — \
         outliving a restart is the point of it — so the only thing that changed is that the \
         process which recorded the redemption is gone"
    );

    // THE FLEET. A second, simultaneous dlopen against the same database is what a second node of
    // one deployment is: it shares the signing key, so it shares the seal, and every check but this
    // one passes on both.
    let node_b = busbar_plugin_loader::load_store(&path, &cfg)
        .expect("a second node loads the same plugin against the same database");
    assert!(store
        .redeem_ask_state(&nonce_fleet, NOW + 900, NOW + 2)
        .expect("redeem_ask_state"));
    assert!(
        !node_b
            .redeem_ask_state(&nonce_fleet, NOW + 900, NOW + 3)
            .expect("redeem_ask_state"),
        "a second node redeemed an approval the first already spent, which is one operator \
         confirmation executing once per node"
    );
    // THE CONTROL: a ledger that refused everything would satisfy both cases above and would have
    // deleted the feature.
    assert!(
        node_b
            .redeem_ask_state(&nonce_fresh, NOW + 900, NOW + 4)
            .expect("redeem_ask_state"),
        "a freshly minted approval is not the one that was spent; refusing it would make the shared \
         ledger a blanket refusal of every confirmation after the first"
    );

    // LEG 3 — the same rows through the plain `PostgresStore`, a path that never touches the cdylib,
    // the C ABI or the loader. A plugin answering the reads above out of its own in-process state
    // passes both boots and fails here.
    let direct = PostgresStore::connect(&url).expect("connect directly to verify and clean up");
    assert!(
        Store::list_mcp_demotions(&direct)
            .expect("list_mcp_demotions via the direct connection")
            .iter()
            .any(|r| r.server == srv_demoted && r.reason == "digest-mismatch"),
        "the demotion must be physically present in Postgres, not merely cached in the plugin"
    );
    assert!(
        !Store::redeem_ask_state(&direct, &nonce_restart, NOW + 900, NOW + 5)
            .expect("redeem_ask_state via the direct connection"),
        "the spent-approval row must be physically present in Postgres: a direct connection that \
         never loaded the plugin has to see the redemption the plugin recorded"
    );

    // Clean up this run's demotion through the contract. The three ledger entries are left where
    // they are ON PURPOSE: the contract gives the ledger no delete, only the expiry sweep that a
    // redemption carries, and firing that sweep here with a far-future `now` would evict every row
    // any CONCURRENT test process is relying on — which is exactly the "one node's cleanup breaks
    // another node's ledger" failure this table exists to prevent. The ids are per-run unique, so
    // they cannot affect a later run, and a real deployment's own sweep bounds them.
    Store::clear_mcp_demotion(&direct, &srv_demoted).expect("clean up this run's demotion");
}
