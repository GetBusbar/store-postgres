# store-postgres

**This plugin's version: v1.0.0.** (Independently versioned from busbar
itself — see [Versioning](#versioning) below.)

[![CI](https://github.com/GetBusbar/store-postgres/actions/workflows/ci.yml/badge.svg)](https://github.com/GetBusbar/store-postgres/actions/workflows/ci.yml)
[![Release](https://img.shields.io/github/v/release/GetBusbar/store-postgres)](https://github.com/GetBusbar/store-postgres/releases)
[![License: Apache 2.0](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)

The first-party, signed `kind: store` plugin for
[busbar](https://getbusbar.com): the Postgres backend for busbar's
durable governance store, exported over the store C ABI. Drop the built
`.so`/`.dylib`/`.dll` into the engine's plugins folder and set
`store: { module: postgres, settings: { url: "postgres://..." } }`; the
engine loads it in-process at boot.
One Postgres behind a fleet of busbar nodes means virtual keys,
budgets, and usage are shared across the cluster instead of siloed per
node.

## Versioning

This plugin is versioned **independently of busbar** — `v1.0.0` here says
nothing about which busbar release it is. Compatibility with busbar is
stated separately: **requires busbar 1.5.0+** (the release that ships the
signed hybrid plugin ABI this crate loads over). Pin both versions
explicitly in production; do not assume they move together.

It is a `cdylib` that implements busbar's `Store` trait (via
[`busbar-plugin-sdk`](https://github.com/GetBusbar/busbar/tree/main/crates/plugin-sdk))
and is loaded in-process by busbar over the signed hybrid plugin ABI —
`dlopen`'d, not spawned as a separate process.

This repo is a same-repo, 2-crate Cargo workspace: it brings 100% of
what it needs. All the SQL and schema logic lives in the
`busbar-store-postgres` crate (`store-postgres/`, a same-repo sibling
this plugin wraps — a custom build can also link it statically instead
of loading this cdylib); `store-postgres-plugin/src/lib.rs` only adapts
the engine's JSON config (`{"url": "postgres://..."}`) into a
`PostgresStore`.

## What it is for

- **A shared, multi-node governance store.** `store: sqlite` is
  per-node; `store: postgres` puts virtual keys, budgets, and usage
  behind one database so a fleet of busbar nodes agrees on state.
- **Drop-in interchangeable with the SQLite backend at the `Store`
  trait**, which is the boundary busbar actually depends on: the same
  keys, credentials, tombstone and revision semantics, and the same
  JSON encoding of `allowed_pools`. The physical tables are NOT
  identical: Postgres keeps per-model token counters in their own
  `usage_ledger` table, where SQLite folds them into `usage_windows`
  with `model` in the primary key. Write reporting queries and ETL
  against the backend you are actually running, never against the
  assumption that the two are byte-identical.

## Known limitations (documented honestly, not papered over)

- **No TLS in this build (`NoTls`).** Run the connection over a trusted
  network segment, a local socket, or a TLS-terminating proxy
  (pgbouncer/stunnel).
- **No automatic reconnect.** A persistently dropped connection
  surfaces as store errors on the write-behind flush path and on admin
  operations; a permanently broken connection requires a process
  restart (let your supervisor handle it).

See the doc comments at the top of
[`store-postgres/src/lib.rs`](store-postgres/src/lib.rs)
for the full design rationale — that is where the actual store logic
lives (in this repo now, not busbarAI); `store-postgres-plugin/` is the
thin `cdylib` adapter around it.

## Build

Needs a Rust toolchain ([rustup](https://rustup.rs)), and — interim,
until [busbarAI](https://github.com/GetBusbar/busbar) ships publicly
— a sibling checkout of `busbarAI` at `../busbarAI` (see
[Dependencies](#dependencies) below).

```sh
cargo build --workspace --release   # cdylib: target/release/libbusbar_store_postgres_plugin.{so,dylib}
cargo test --workspace              # the end-to-end loader tests (see store-postgres-plugin/tests/e2e.rs) — need a real Postgres, see below
cargo clippy --workspace --all-targets -- -D warnings
cargo fmt --all -- --check
```

## Dependencies

This is a same-repo, 2-crate Cargo workspace (`store-postgres/`, the
real logic crate, and `store-postgres-plugin/`, the thin `cdylib`
adapter — see [members](Cargo.toml)). `busbar-store-postgres` is a
SAME-REPO sibling dependency; only `busbar-api` and `busbar-plugin-sdk`
(and, as a dev-dependency of the plugin adapter for the end-to-end
test, `busbar-plugin-loader`) still reach into the
[busbarAI](https://github.com/GetBusbar/busbar) monorepo. Because
busbarAI is not yet public, both crates' `Cargo.toml`s point at those
as **local path dependencies** (`../../busbarAI/crates/...`), which
means this repo expects to be checked out as a sibling of `busbarAI`:

```
some-parent-dir/
├── busbarAI/
└── store-postgres/
    ├── Cargo.toml                 # workspace root
    ├── store-postgres/            # busbar-store-postgres — the real logic crate
    └── store-postgres-plugin/     # busbar-store-postgres-plugin — the thin dlopen adapter
```

This is an interim measure — once busbarAI ships publicly, these
should become git (pinned rev/tag) or crates.io dependencies instead.
Grep both crates' `Cargo.toml` for the `INTERIM` comments when doing
that migration.

## Tests need a real Postgres

Unlike a `kind: hook` plugin, this store's only meaningful coverage is
against a **live Postgres** — there is no useful mock for "did the SQL
actually persist."

`store-postgres-plugin/tests/e2e.rs` installs the plugin the way an
operator does: it packs the built cdylib into a real tarball with the
same tool the release signs, drops it into a real `plugins.dir`, and
boots a real `busbar` process against `store: { module: postgres }`.
That boot runs against a disposable, freshly created database, so the
schema it finds afterwards can only have come from the boot under test.
Against a shared database the same check would pass whether or not the
plugin ever loaded.

`store-postgres-plugin/tests/admin_api_e2e.rs` goes one step further:
it installs the plugin over the real admin API, restarts onto it, mints
a key with an AWS-shaped credential over that API, and reads both rows
back with a raw client that never touches the plugin, the C ABI or the
loader.

`store-postgres/src/tests.rs` holds the store's own coverage against a
live database: tombstone semantics, slot-safe credential minting,
revocation, snapshot isolation, and each migration boundary on its own
throwaway database.

All of them are gated on the `BUSBAR_TEST_POSTGRES_URL` env var, and
they refuse to skip silently under CI. An unset variable there is a
hard failure, not a quiet pass:

```sh
# Point at any reachable Postgres 16+ database:
export BUSBAR_TEST_POSTGRES_URL=postgres://busbar:busbar@localhost:5432/busbar_test
cargo test --workspace
```

Locally, with the env var unset, both test suites print a `skip:`
message and pass — no database needed for a bare `cargo test`. Under
CI (`CI` env var set — see `.github/workflows/ci.yml`), a *missing*
`BUSBAR_TEST_POSTGRES_URL` is a **hard failure**, not a silent skip:
CI provisions a real `postgres:16` GitHub Actions service container on
every push, specifically so this coverage can never quietly vanish.

## Pack and sign

Once built, the cdylib is packed and signed like any other busbar
plugin — see
[`docs/plugins.md`](https://github.com/GetBusbar/busbar/blob/main/docs/plugins.md#signing-and-packaging)
in busbarAI for the full reference. In short:

```sh
BUSBAR_SIGN_KEY=<signing key> busbar-plugin-pack pack \
    --lib target/release/libbusbar_store_postgres_plugin.so \
    --name busbar-store-postgres-plugin --alias postgres --kind store \
    --version 1.0.0 --publisher busbar \
    --license Apache-2.0 \
    --out busbar-store-postgres-plugin-1.0.0-x86_64-linux.tar.gz
```

For local development without a signing key, `busbar-plugin-pack pack
--allow-unsigned` produces a tarball busbar loads only under
`plugins.trust.allow_unsigned: true`.

Drop the resulting tarball into busbar's configured `plugins.dir` and
set:

```yaml
store:
  module: postgres
  settings: { url: "postgres://user:pass@host/busbar" }
```

— see [`docs/configuration.md`](https://github.com/GetBusbar/busbar/blob/main/docs/configuration.md)
for the full store config reference.

## Config

| Setting | Required | Default | Notes |
|---|---|---|---|
| `url` | yes | — | A libpq connection string, e.g. `postgres://user:pass@host:5432/busbar`. Connects `NoTls`; run it over a trusted network segment or a TLS-terminating proxy. **No connect timeout is set by default** — a blackholed host wedges engine boot indefinitely. libpq honors a `connect_timeout` query param in the DSN, e.g. `postgres://user:pass@host:5432/busbar?connect_timeout=10`; set one if boot hanging on a dead host is a concern. |

## License

Licensed **Apache-2.0** ([LICENSE](LICENSE)). Contributions welcome — see
[CONTRIBUTING.md](CONTRIBUTING.md). Governed by our
[Code of Conduct](CODE_OF_CONDUCT.md); security issues go through
[SECURITY.md](SECURITY.md), not public issues.
