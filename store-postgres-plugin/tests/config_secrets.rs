// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Coverage for `tests/common`'s secret-reference scan.
//!
//! That scan is what keeps the real-binary e2e tests bootable, and when it misses a reference the
//! symptom surfaces a long way from here — as `busbar` exiting 1 before its listener comes up —
//! so it is worth testing directly rather than only through the e2e tests it supports.

mod common;

use common::referenced_env_vars;

#[test]
fn finds_secret_references_and_legacy_env_fields() {
    let config = "\
providers:\n  mock:\n    api_key: { env: MOCK_KEY }\n\
identity-providers:\n  admin-tokens: { module: admin-tokens, token: { env: BUSBAR_ADMIN_TOKEN } }\n\
auth:\n  signing_key: { env: BUSBAR_SIGNING_KEY }\n";
    assert_eq!(
        referenced_env_vars(config),
        vec!["MOCK_KEY", "BUSBAR_ADMIN_TOKEN", "BUSBAR_SIGNING_KEY"],
    );

    // The flat providers catalog still names variables through the legacy `*_env:` field rather
    // than a secret reference, and busbar resolves those too, so the same scan has to see them.
    assert_eq!(
        referenced_env_vars("mock:\n  api_key_env: MOCK_KEY\n"),
        vec!["MOCK_KEY"],
    );
}

#[test]
fn deduplicates_and_ignores_references_that_name_nothing() {
    assert_eq!(
        referenced_env_vars("a: { env: SAME }\nb: { env: SAME }\n"),
        vec!["SAME"],
        "a variable referenced twice must be exported once, not twice"
    );

    // A bare `env:` opening a nested mapping, or ending a line, names no variable; exporting an
    // empty-named one would be nonsense and on some platforms an outright error.
    assert!(referenced_env_vars("a: { env:\n  b: c }\n").is_empty());
    assert!(referenced_env_vars("listen: \"127.0.0.1:0\"\nauth:\n  chain: []\n").is_empty());
}
