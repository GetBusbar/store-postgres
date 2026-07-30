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
`governance.store: postgres`; the engine loads it in-process at boot.
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
[`busbar-plugin-sdk`](https://github.com/GetBusbar/busbarAI/tree/main/crates/plugin-sdk))
and is loaded in-process by busbar over the signed hybrid plugin ABI —
`dlopen`'d, not spawned as a separate process. All the SQL and schema
logic lives in the `busbar-store-postgres` library crate (which a
custom build can also link statically instead of loading this cdylib);
this repo's own `src/lib.rs` only adapts the engine's JSON config
(`{"url": "postgres://..."}`) into a `PostgresStore`.

## What it is for

- **A shared, multi-node governance store.** `store: sqlite` is
  per-node; `store: postgres` puts virtual keys, budgets, and usage
  behind one database so a fleet of busbar nodes agrees on state.
- It mirrors the SQLite backend's schema and semantics exactly (same
  tables, same UPSERT shapes, same JSON encoding of `allowed_pools`) so
  `store: sqlite` and `store: postgres` are drop-in interchangeable —
  the only differences are the SQL dialect and that Postgres is a
  shared server.

## Known limitations (documented honestly, not papered over)

- **No TLS in this build (`NoTls`).** Run the connection over a trusted
  network segment, a local socket, or a TLS-terminating proxy
  (pgbouncer/stunnel).
- **No automatic reconnect.** A persistently dropped connection
  surfaces as store errors on the write-behind flush path and on admin
  operations; a permanently broken connection requires a process
  restart (let your supervisor handle it).

See the doc comments at the top of
[`busbar-store-postgres`'s `src/lib.rs`](https://github.com/GetBusbar/busbarAI/blob/1.5.0-dev/crates/store-postgres/src/lib.rs)
for the full design rationale — that is where the actual store logic
lives; this repo is the thin `cdylib` adapter around it.

## Build

Needs a Rust toolchain ([rustup](https://rustup.rs)), and — interim,
until [busbarAI](https://github.com/GetBusbar/busbarAI) ships publicly
— a sibling checkout of `busbarAI` at `../busbarAI` (see
[Dependencies](#dependencies) below).

```sh
cargo build --release      # cdylib: target/release/libbusbar_store_postgres_plugin.{so,dylib}
cargo test                 # the end-to-end loader tests (see tests/e2e.rs) — need a real Postgres, see below
cargo clippy --all-targets -- -D warnings
cargo fmt --all -- --check
```

## Dependencies

This crate depends on `busbar-api`, `busbar-store-postgres`, and
`busbar-plugin-sdk` (and, as a dev-dependency for the end-to-end test,
`busbar-plugin-loader`) from the
[busbarAI](https://github.com/GetBusbar/busbarAI) monorepo. Because
busbarAI is not yet public, `Cargo.toml` points at these as **local
path dependencies** (`../busbarAI/crates/...`), which means this repo
expects to be checked out as a sibling of `busbarAI`:

```
some-parent-dir/
├── busbarAI/
└── store-postgres/
```

This is an interim measure — once busbarAI ships publicly, these
should become git (pinned rev/tag) or crates.io dependencies instead.
Grep `Cargo.toml` for the `INTERIM` comments when doing that migration.

## Tests need a real Postgres

Unlike a `kind: hook` plugin, this store's only meaningful coverage is
against a **live Postgres** — there is no useful mock for "did the SQL
actually persist." `tests/e2e.rs` dlopens the built cdylib over the
real `busbar-plugin-loader` ABI seam (the same seam the engine uses for
`governance.store: postgres`), writes a key and a usage ledger through
it, closes the plugin, and then proves the data genuinely landed in
Postgres two independent ways: re-opening the same cdylib against the
same database, and connecting directly with the plain
`busbar-store-postgres::PostgresStore` — a path that never touches the
cdylib, the C ABI, or the loader at all.

Both `tests/e2e.rs` here and `busbar-store-postgres`'s own
`roundtrip_against_live_postgres` test (in the sibling `busbarAI`
checkout) are gated on the `BUSBAR_TEST_POSTGRES_URL` env var:

```sh
# Point at any reachable Postgres 16+ database:
export BUSBAR_TEST_POSTGRES_URL=postgres://busbar:busbar@localhost:5432/busbar_test
cargo test
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
[`docs/plugins.md`](https://github.com/GetBusbar/busbarAI/blob/main/docs/plugins.md#signing-and-packaging)
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
reference it as the governance store — see
[`docs/configuration.md`](https://github.com/GetBusbar/busbarAI/blob/main/docs/configuration.md)
in busbarAI for the `governance.store:` wiring.

## Config

| Setting | Required | Default | Notes |
|---|---|---|---|
| `url` | yes | — | A libpq connection string, e.g. `postgres://user:pass@host:5432/busbar`. Connects `NoTls`; run it over a trusted network segment or a TLS-terminating proxy. |

## License

Licensed **Apache-2.0** ([LICENSE](LICENSE)). Contributions welcome — see
[CONTRIBUTING.md](CONTRIBUTING.md). Governed by our
[Code of Conduct](CODE_OF_CONDUCT.md); security issues go through
[SECURITY.md](SECURITY.md), not public issues.
