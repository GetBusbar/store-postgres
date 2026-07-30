# Contributing to store-postgres

Thanks for your interest in improving `store-postgres`. This document covers
how to build, test, and submit changes.

## Ground rules

- Be respectful and constructive in all project spaces (see
  [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md)).
- By contributing, you agree your contributions are licensed under the project's
  [Apache-2.0](LICENSE) license.
- Security issues go through [SECURITY.md](SECURITY.md), **not** public issues.

## Development setup

`store-postgres` is a Rust `cdylib` plugin. You need a recent stable toolchain
(`rustup` recommended), and — until [busbarAI](https://github.com/GetBusbar/busbar)
ships publicly — a sibling checkout of it at `../busbarAI`, since this crate's
`Cargo.toml` points at busbar's crates as local path dependencies. See the
README's [Dependencies](README.md#dependencies) section for the exact layout;
CI checks out `GetBusbar/busbar` at the branch named in the reusable
`plugin-ci.yml` workflow reference in [`ci.yml`](.github/workflows/ci.yml).

The meaningful test coverage here needs a **live Postgres** — see the README's
[Tests need a real Postgres](README.md#tests-need-a-real-postgres) section.
Locally, `cargo test` skips that coverage cleanly if `BUSBAR_TEST_POSTGRES_URL`
is unset; set it to point at a real Postgres 16+ database to exercise it:

```bash
export BUSBAR_TEST_POSTGRES_URL=postgres://busbar:busbar@localhost:5432/busbar_test
cargo build --release                       # cdylib
cargo test                                   # unit tests + the e2e dlopen/live-Postgres test
cargo clippy --all-targets -- -D warnings    # lints must be clean
cargo fmt --all -- --check                   # format before committing
```

## Before you open a pull request

1. **`cargo fmt --all`** — code must be rustfmt-clean.
2. **`cargo clippy --all-targets -- -D warnings`** — no warnings.
3. **`cargo build && cargo test`** — green, including the live-Postgres
   end-to-end test in `tests/e2e.rs` (it hard-fails under `CI=1` rather than
   silently skipping — never let that coverage quietly vanish).
4. Add or update tests for any behavior change.
5. Update documentation (`README.md`, doc comments) when you change behavior or config.

## Architecture

This repo is deliberately a thin adapter (`src/lib.rs`): it turns the engine's
JSON `open` config into a `PostgresStore` and hands the trait object to
[`busbar-plugin-sdk`](https://github.com/GetBusbar/busbar/tree/main/crates/plugin-sdk),
which emits the C ABI symbols the loader resolves. All the SQL and schema logic
lives in the `busbar-store-postgres` library crate this plugin wraps, in the
`busbarAI` monorepo — most substantive changes belong there, not here.

## Commit & PR conventions

- Keep commits focused; squash noisy WIP commits before opening the PR.
- Write a clear PR description: what changed, why, and how it was verified.
- Reference any related issue.
- Stage files by name; avoid sweeping `git add -A` that pulls in unrelated changes.

## Questions

Open a discussion or issue. We're happy to help you get oriented.
