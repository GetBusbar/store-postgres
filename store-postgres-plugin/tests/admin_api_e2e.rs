// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE prod-ready end-to-end bar for this plugin, driven the way a real OPERATOR installs and uses
//! it in production — never a file dropped onto disk before boot (see `e2e.rs` for that path, still
//! real and still kept as its own proof), but the REAL admin HTTP API:
//!
//!   1. Boot a real `busbar` process (no `--validate`) with its admin listener up and the compiled-in
//!      `memory` store active (`store:` block absent — see `busbar`'s own `StoreCfg` doc: "Absent
//!      block = the compiled-in ephemeral RAM store").
//!   2. `POST /api/v1/admin/plugins` with the REAL built cdylib, base64-encoded, guarded by a real
//!      `x-admin-token` — the exact wire shape `crates/busbar/src/admin/v1/json/handlers.rs`'s
//!      `install_plugin` and its own admin test (`test_admin_v1_plugin_install_list_reload_remove`
//!      in `crates/busbar/src/admin/tests/tests.rs`) use, mirrored here against a REAL cdylib rather
//!      than that in-process test's own never-dlopened junk bytes.
//!   3. `GET /api/v1/admin/plugins?type=store` confirms the install landed in the real catalog.
//!
//! Installing over the admin API does NOT hot-swap the ACTIVE store — confirmed against
//! `crates/busbar/src/admin/v1/json/handlers.rs`'s own `reload_plugins` doc comment ("the
//! governance/store instance is REUSED across the swap") and `PUT /config/settings`'s handler,
//! which puts `store` on its own `restart_required` list. There is no admin endpoint that hot-swaps
//! the active store; a fresh process boot is the only real mechanism, so this test uses one — same
//! as a real operator editing `store: module: postgres` into `config.yaml` and restarting after an
//! admin-API install:
//!
//!   4. Stop that process. Rewrite `config.yaml` on disk (same `plugins.dir`, now containing the
//!      tarball the ADMIN API itself wrote there in step 2 — never touched directly by this test) to
//!      point `store: module: postgres` at the real Postgres.
//!   5. Boot a SECOND real `busbar` process against that config. Busbar's own first-boot store
//!      resolution (`plugin_registry.open_store`, called synchronously during construction, before
//!      the listener ever binds) dlopens the plugin that landed on disk via the admin API in step 2.
//!      Poll — via a RAW independent `postgres::Client`, never `PostgresStore::connect` — for the
//!      `keys` table to appear, proving the real dlopen + `Store::connect`/`migrate()` path executed.
//!   6. `POST /api/v1/admin/keys` (with `issue_aws_credential: true`) against this SECOND process —
//!      REAL WORK: mint a virtual key AND a credential through the running instance, over the same
//!      real admin API.
//!   7. Independently verify — a fresh RAW `postgres::Client`, bypassing the plugin/ABI/admin-API
//!      entirely — that both the `keys` row and the `credentials` row actually landed.
//!
//! Together: real admin-API install -> real (admin-API-driven) plugin load -> real admin-API write
//! -> real, independently-verified Postgres persistence.

use base64::Engine as _;
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

/// Fixed ed25519 signing secret (64 hex = 32 bytes) for this e2e test. 1.5.1 requires an
/// explicit signing key to mint virtual keys; busbar no longer auto-generates one.
const TEST_SIGNING_KEY: &str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

/// RAII guard for a spawned child process: kills and reaps it on drop, including when a panic
/// unwinds partway through the test. Same pattern as `e2e.rs`'s own `ChildGuard`.
///
/// It also owns the path this child's stdout+stderr were redirected to. THAT IS LOAD-BEARING, not
/// bookkeeping. This test used to spawn busbar with `.stderr(Stdio::null())`, so when a boot failed
/// the only thing anyone ever saw was
///
///     boot #1 exited before its admin listener came up (status: exit status: 1)
///
/// -- an exit code and nothing else, with busbar's own diagnosis of WHY thrown away at the point it
/// was produced. qa-gate run 31059945604 lost this leg to a fail-closed config refusal that busbar
/// printed in full and this harness deleted; the actual cause had to be recovered from a DIFFERENT
/// job's logs. A test that can only report "it exited" cannot be debugged from its own output, so
/// every boot now logs to a file and every failure path prints that file.
///
/// A FILE, not `Stdio::piped()`: nothing here reads the pipe while the child runs, so a child that
/// out-talked the pipe buffer would block forever on write and turn a clean failure into a hang.
struct ChildGuard(Child, PathBuf);

impl ChildGuard {
    /// The child's captured output, formatted for a panic message. Never panics itself: this runs
    /// on the failure path, where a second, unrelated panic would bury the first.
    fn output(&self) -> String {
        match std::fs::read_to_string(&self.1) {
            Ok(s) if s.trim().is_empty() => "  (the child produced no output)".to_string(),
            Ok(s) => s
                .lines()
                .map(|l| format!("  | {l}"))
                .collect::<Vec<_>>()
                .join("\n"),
            Err(e) => format!("  (could not read {}: {e})", self.1.display()),
        }
    }
}

impl Drop for ChildGuard {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

/// Spawn `busbar` with its stdout+stderr captured to `log`, and wrap it in a `ChildGuard` that
/// knows where to find them. Every boot in this test goes through here, so the capture cannot be
/// forgotten on a boot added later.
fn spawn_busbar(cmd: &mut Command, log: PathBuf, what: &str) -> ChildGuard {
    let out = std::fs::File::create(&log)
        .unwrap_or_else(|e| panic!("create the {what} log at {}: {e}", log.display()));
    let err = out
        .try_clone()
        .unwrap_or_else(|e| panic!("dup the {what} log handle: {e}"));
    let child = cmd
        .stdout(Stdio::from(out))
        .stderr(Stdio::from(err))
        .spawn()
        .unwrap_or_else(|e| panic!("spawn the real busbar for {what}: {e}"));
    ChildGuard(child, log)
}

fn postgres_url() -> Option<String> {
    match std::env::var("BUSBAR_TEST_POSTGRES_URL") {
        Ok(url) => Some(url),
        Err(_) if std::env::var_os("CI").is_some() => {
            panic!(
                "BUSBAR_TEST_POSTGRES_URL is unset under CI: the postgres:16 service container must \
                 provision it. Refusing to silently skip the only real-admin-API-install coverage \
                 in CI."
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
/// profile dir, only to `target/deps`, so checking only `profile_dir` silently finds nothing and
/// this test's CI hard-panic fires even though the cdylib really was built.
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

/// The sibling busbarAI checkout's root (same convention `e2e.rs` already uses for its path deps).
fn busbarai_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../busbarAI")
        .canonicalize()
        .expect("sibling busbarAI checkout must exist (see Cargo.toml path deps)")
}

/// Build (once, cached by cargo) and return the real `busbar` and `busbar-plugin-pack` binaries,
/// both from the sibling busbarAI checkout — never a fixture, never a stub.
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

/// Reserve a free loopback port for the admin listener (bind-then-drop; the standard, small-TOCTOU
/// pattern for handing a port to a spawned external process — the same trade-off `listen:
/// "127.0.0.1:0"` in `e2e.rs` accepts for the data-plane listener, except busbar itself doesn't
/// report back which port it took for `:0`, so the admin listener needs a port this test can name
/// in the config file up front).
fn free_port() -> u16 {
    std::net::TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

fn cleanup(url: &str, id: &str) {
    if let Ok(mut client) = postgres::Client::connect(url, postgres::NoTls) {
        let _ = client.execute("DELETE FROM credentials WHERE key_id=$1", &[&id]);
        let _ = client.execute("DELETE FROM keys WHERE id=$1", &[&id]);
    }
}

/// Poll `http://127.0.0.1:{port}/api/v1/admin/plugins` (any admin GET works — we just need a TCP
/// accept + HTTP response) until the admin listener is up, or the child has already exited.
fn wait_for_admin_listener(
    client: &reqwest::blocking::Client,
    admin_base: &str,
    token: &str,
    guard: &mut ChildGuard,
    what: &str,
) {
    let deadline = Instant::now() + Duration::from_secs(15);
    loop {
        if client
            .get(format!("{admin_base}/plugins"))
            .header("x-admin-token", token)
            .send()
            .is_ok()
        {
            return;
        }
        if let Ok(Some(status)) = guard.0.try_wait() {
            panic!(
                "{what} exited before its admin listener came up (status: {status})\n\
                 --- {what} output ---\n{}",
                guard.output()
            );
        }
        if Instant::now() >= deadline {
            panic!(
                "{what}'s admin listener never came up within 15s\n\
                 --- {what} output ---\n{}",
                guard.output()
            );
        }
        std::thread::sleep(Duration::from_millis(50));
    }
}

/// THE REAL END-TO-END PROOF: install the real cdylib over the real admin API, restart onto it
/// (the only real activation mechanism busbar exposes for a store-kind plugin), mint a virtual key
/// and AWS credential through the running instance over the same admin API, and independently
/// confirm both rows landed in real Postgres.
#[test]
fn install_over_admin_api_then_mint_a_key_and_verify_postgres_directly() {
    let Some(url) = postgres_url() else { return };
    let Some(so_path) = plugin_path() else {
        eprintln!("skip: store-postgres-plugin cdylib not built");
        return;
    };
    let key_id = "vk_pg_adminapi_e2e";
    cleanup(&url, key_id);

    let (busbar_bin, pack_bin) = build_real_binaries();

    let work = std::env::temp_dir().join(format!(
        "busbar-pg-adminapi-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    let plugins_dir = work.join("plugins");
    std::fs::create_dir_all(&plugins_dir).unwrap();

    // Pack the REAL cdylib (never junk bytes) into a real signed-shape tarball, same tool + flags
    // as `e2e.rs` and CI's own SIGNOFF step use. Read back the bytes here -- this test uploads them
    // itself over HTTP, never by copying the file into `plugins_dir` directly.
    let tarball_path = work.join("store-postgres.tar.gz");
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
            "admin-api e2e proof",
            "--license",
            "Apache-2.0",
            "--out",
            tarball_path.to_str().unwrap(),
            "--allow-unsigned",
        ])
        .status()
        .expect("run busbar-plugin-pack");
    assert!(status.success(), "packing the plugin must succeed");
    let tarball_bytes = std::fs::read(&tarball_path).unwrap();
    let file = "store-postgres.tar.gz";

    let admin_port = free_port();
    let admin_token = "spg-adminapi-e2e-token";
    let admin_base = format!("http://127.0.0.1:{admin_port}/api/v1/admin");
    let client = reqwest::blocking::Client::new();

    let providers = work.join("providers.yaml");
    std::fs::write(
        &providers,
        "mock:\n  protocol: anthropic\n  base_url: \"http://127.0.0.1:9\"\n  api_key_env: MOCK_KEY\n",
    )
    .unwrap();
    let providers_and_common = format!(
        "listen: \"127.0.0.1:0\"\n\
         admin_listen: \"127.0.0.1:{admin_port}\"\n\
         plugins:\n  enabled: true\n  dir: {}\n  trust:\n    allow_unsigned: true\n\
         identity-providers:\n  admin-tokens: {{ module: admin-tokens, token: {{ env: BUSBAR_ADMIN_TOKEN }} }}\n\
         auth:\n  chain: []\n  signing_key: {{ env: BUSBAR_SIGNING_KEY }}\n  admin_auth: [admin-tokens]\n\
         providers:\n  mock:\n    api_key: {{ env: MOCK_KEY }}\n\
         models:\n  test-model:\n    provider: mock\n",
        plugins_dir.display()
    );

    // BOOT #1: no `store:` block at all -- the compiled-in `memory` store, per StoreCfg's own doc
    // ("Absent block = the compiled-in ephemeral RAM store"). The postgres plugin is NOT on disk
    // yet: this process only exists to serve the admin API that installs it.
    let config1 = work.join("config1.yaml");
    std::fs::write(&config1, &providers_and_common).unwrap();

    let mut guard1 = spawn_busbar(
        Command::new(&busbar_bin)
            .env("BUSBAR_CONFIG", &config1)
            .env("BUSBAR_PROVIDERS", &providers)
            .env("BUSBAR_ADMIN_TOKEN", admin_token)
            .env("BUSBAR_SIGNING_KEY", TEST_SIGNING_KEY)
            .env("BUSBAR_STATE_FILE", ""),
        work.join("boot1.log"),
        "boot #1 (memory store, admin listener up)",
    );
    wait_for_admin_listener(&client, &admin_base, admin_token, &mut guard1, "boot #1");

    // REAL ADMIN-API INSTALL: POST the real cdylib tarball, base64, exactly the wire shape
    // `install_plugin`/its own admin test use -- never a file-drop.
    let install_body = serde_json::json!({
        "file": file,
        "tarball_b64": base64::engine::general_purpose::STANDARD.encode(&tarball_bytes),
    });
    let install_resp = client
        .post(format!("{admin_base}/plugins"))
        .header("x-admin-token", admin_token)
        .json(&install_body)
        .send()
        .unwrap();
    let install_status = install_resp.status();
    let install_body_text = install_resp.text().unwrap_or_default();
    assert_eq!(
        install_status.as_u16(),
        201,
        "plugin install must succeed over the real admin API: {install_body_text}"
    );
    assert!(
        plugins_dir.join(file).exists(),
        "the admin API's own install handler must have written the tarball to plugins.dir \
         (this test never writes it there itself)"
    );

    // A mutation WITHOUT the admin token must be rejected -- the surface really is guarded, not
    // open, mirroring the exact assertion busbarAI core's own
    // `test_admin_v1_plugin_install_list_reload_remove` makes. Over a REAL out-of-process TCP
    // connection (unlike that in-process axum test), a server that rejects before reading the
    // full request body can legitimately close the connection rather than complete a clean 401
    // response -- so either outcome (a 401 status, or the connection itself being refused/reset)
    // counts as proof the write was rejected; only a 2xx success would mean the guard is missing.
    match client
        .post(format!("{admin_base}/plugins"))
        .json(&install_body)
        .send()
    {
        Ok(unauth) => assert_eq!(
            unauth.status().as_u16(),
            401,
            "plugin install without x-admin-token must be rejected with 401, not accepted"
        ),
        Err(e) => {
            // A transport error is only acceptable as "the server closed on us mid-reject". It is
            // NOT acceptable as "the server was gone", which is what an unqualified `!e.is_status()`
            // check admits: this call never runs `error_for_status`, so `is_status()` is false for
            // EVERY error it can produce, including connection-refused because the process had
            // already died -- a dead server would have read as proof the guard held. Prove the
            // server is still there and still serving, so the only surviving explanation is a
            // deliberate reject.
            assert!(
                !e.is_status(),
                "an unauthenticated install must never be accepted: {e}"
            );
            let alive = client
                .get(format!("{admin_base}/plugins?type=store"))
                .header("x-admin-token", admin_token)
                .send()
                .expect("the admin surface must still answer after rejecting the unauthenticated install; a dead server is not evidence that the token guard held");
            assert_eq!(
                alive.status().as_u16(),
                200,
                "an authenticated read must still succeed after the rejected unauthenticated write"
            );
        }
    }

    // Confirm the real catalog reports it (not just a 201 with no lasting effect).
    let list: serde_json::Value = client
        .get(format!("{admin_base}/plugins?type=store"))
        .header("x-admin-token", admin_token)
        .send()
        .unwrap()
        .json()
        .unwrap();
    let items = list["items"].as_array().expect("plugins list has items");
    assert!(
        items
            .iter()
            .any(|p| p["target"] == file && p["name"] == "busbar-store-postgres-plugin"),
        "the installed postgres plugin must be listed in the real catalog: {items:?}"
    );

    // Install alone does NOT hot-swap the active store (confirmed against busbarAI core's own
    // `reload_plugins`/`PUT /config/settings` doc comments -- `store` is on the restart_required
    // list, and there is no live-swap endpoint for it). A real restart is the only real activation
    // path, so this test uses one, same as a real operator would.
    drop(guard1);

    // BOOT #2: same plugins.dir (now containing the tarball the ADMIN API itself wrote in the
    // install call above), config now naming `store: module: postgres` against the real Postgres.
    let config2 = work.join("config2.yaml");
    std::fs::write(
        &config2,
        format!(
            "{providers_and_common}store:\n  module: postgres\n  settings: {{ url: \"{url}\" }}\n"
        ),
    )
    .unwrap();

    let mut guard2 = spawn_busbar(
        Command::new(&busbar_bin)
            .env("BUSBAR_CONFIG", &config2)
            .env("BUSBAR_PROVIDERS", &providers)
            .env("BUSBAR_ADMIN_TOKEN", admin_token)
            .env("BUSBAR_SIGNING_KEY", TEST_SIGNING_KEY)
            .env("BUSBAR_STATE_FILE", ""),
        work.join("boot2.log"),
        "boot #2 (postgres store, the admin-installed plugin)",
    );

    // Wait for boot #2 to make progress, and fail fast (with its log) if it exits instead. This is
    // a PROGRESS WAIT, not the load proof: this test shares the CI database with every other live
    // test in the workspace, so the `keys` table it polls for is already there and the loop breaks
    // true on its first iteration regardless of what this child did. The actual proof that boot #2
    // dlopened the admin-installed plugin and is serving on the Postgres store is the admin-API
    // mint further down, verified by reading the minted key and credential back over a raw client
    // -- rows that cannot exist unless this process loaded the plugin and wrote them. (e2e.rs's
    // file-drop test carries the from-empty version of this check, on its own disposable database.)
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
        if let Ok(Some(status)) = guard2.0.try_wait() {
            panic!(
                "boot #2 exited before creating the postgres schema (status: {status})\n\
                 --- boot #2 output ---\n{}",
                guard2.output()
            );
        }
        if Instant::now() >= deadline {
            break false;
        }
        std::thread::sleep(Duration::from_millis(50));
    };
    assert!(
        booted,
        "boot #2, restarted onto the admin-installed postgres plugin, must reach a migrated \
         `keys` table within 15s\n\
         --- boot #2 output ---\n{}",
        guard2.output()
    );
    wait_for_admin_listener(&client, &admin_base, admin_token, &mut guard2, "boot #2");

    // REAL WORK, over the real admin API: mint a virtual key WITH an AWS-shaped credential.
    let mint_body = serde_json::json!({
        "name": "spg-adminapi-e2e-key",
        "labels": {},
        "issue_aws_credential": true,
    });
    let mint_resp = client
        .post(format!("{admin_base}/keys"))
        .header("x-admin-token", admin_token)
        .json(&mint_body)
        .send()
        .unwrap();
    let mint_status = mint_resp.status();
    let mint_json: serde_json::Value = mint_resp.json().unwrap();
    assert_eq!(
        mint_status.as_u16(),
        201,
        "minting a key over the real admin API must succeed: {mint_json}"
    );
    let minted_id = mint_json["id"]
        .as_str()
        .expect("minted key response has an id")
        .to_string();
    let access_key_id = mint_json["aws_access_key_id"]
        .as_str()
        .expect("issue_aws_credential:true must return an aws_access_key_id")
        .to_string();
    assert!(
        mint_json["aws_secret_access_key"].is_string(),
        "issue_aws_credential:true must also return an aws_secret_access_key: {mint_json}"
    );

    // INDEPENDENT VERIFICATION: a fresh RAW postgres::Client, bypassing the plugin/ABI/admin-API
    // entirely, confirms the key AND its credential actually landed in real Postgres.
    let mut raw = postgres::Client::connect(&url, postgres::NoTls)
        .expect("connect directly to confirm persistence, bypassing the plugin entirely");
    let key_row = raw
        .query_opt("SELECT name, enabled FROM keys WHERE id=$1", &[&minted_id])
        .unwrap();
    let key_row = key_row.expect("the minted key must be a real row in the real keys table");
    let stored_name: String = key_row.get(0);
    let stored_enabled: bool = key_row.get(1);
    assert_eq!(stored_name, "spg-adminapi-e2e-key");
    assert!(stored_enabled);

    let cred_row = raw
        .query_opt(
            "SELECT kind, public_id FROM credentials WHERE key_id=$1",
            &[&minted_id],
        )
        .unwrap();
    let cred_row = cred_row
        .expect("the minted AWS credential must be a real row in the real credentials table");
    let stored_kind: String = cred_row.get(0);
    let stored_public_id: String = cred_row.get(1);
    assert_eq!(stored_kind, "sigv4");
    assert_eq!(
        stored_public_id, access_key_id,
        "the credential row's public_id must be the SAME access key id the admin API returned"
    );

    drop(guard2);
    drop(raw);
    let _ = std::fs::remove_dir_all(&work);
    cleanup(&url, &minted_id);
}
