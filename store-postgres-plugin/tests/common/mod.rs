// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Support code shared by this crate's integration tests: supplying the secrets a config fixture
//! references so the real `busbar` binary can start.
//!
//! busbar resolves every `env:`/`file:` secret reference during `--validate` AND at boot, and exits
//! non-zero when one of them cannot resolve. A fixture that names a variable nobody exported is
//! therefore a gateway that cannot come up, and the test reports that as an opaque timeout or
//! early-exit a long way from the YAML that caused it.
//!
//! The variable names are derived FROM the fixture text rather than listed here on purpose: the
//! next person to add a secret reference to a config in these tests must not have to also remember
//! to export it, because forgetting produces a failure that does not name the variable.
//!
//! This lives under `tests/common/` rather than `tests/` so cargo does not compile it as a test
//! binary of its own; its own coverage lives in `tests/config_secrets.rs`.

#![allow(dead_code)]
// Each integration test binary compiles this module separately and uses a different subset of it,
// so anything only one of them needs is genuinely dead code from the other's point of view.

use std::path::Path;
use std::process::Command;

/// Stands in for every secret a fixture references but the test does not otherwise set. The content
/// is irrelevant — what matters is only that resolution SUCCEEDS.
pub const SECRET_PLACEHOLDER: &str = "e2e-placeholder";

/// Every environment variable `config` names, whether through a `{ env: NAME }` secret reference or
/// through a legacy `*_env: NAME` field, in first-seen order and without duplicates.
pub fn referenced_env_vars(config: &str) -> Vec<String> {
    let mut names = Vec::new();
    for (idx, _) in config.match_indices("env:") {
        let name: String = config[idx + "env:".len()..]
            .trim_start_matches([' ', '\t'])
            .chars()
            .take_while(|c| c.is_ascii_alphanumeric() || *c == '_')
            .collect();
        // A bare `env:` with nothing usable after it (a line break, or the key of a nested mapping)
        // names no variable at all; skip it rather than exporting an empty-named one.
        if !name.is_empty() && !names.contains(&name) {
            names.push(name);
        }
    }
    names
}

/// Sets [`SECRET_PLACEHOLDER`] for every environment variable `config` references.
///
/// Call this BEFORE any `.env()` carrying a value the test actually asserts on (an admin token, a
/// signing key): the later `.env()` wins, so the placeholder only ever fills in the secrets whose
/// value the test does not care about.
pub fn apply_placeholder_secrets(cmd: &mut Command, config: &str) {
    for name in referenced_env_vars(config) {
        cmd.env(name, SECRET_PLACEHOLDER);
    }
}

/// [`apply_placeholder_secrets`] over the files busbar will actually read.
///
/// Reading the files back, rather than the strings the test built them from, is what makes this
/// impossible to get out of step: whatever landed on disk is exactly what busbar resolves.
pub fn apply_placeholder_secrets_from_files(cmd: &mut Command, paths: &[&Path]) {
    for path in paths {
        let text = std::fs::read_to_string(path).unwrap_or_else(|e| {
            panic!(
                "read config fixture {} for its secrets: {e}",
                path.display()
            )
        });
        apply_placeholder_secrets(cmd, &text);
    }
}
