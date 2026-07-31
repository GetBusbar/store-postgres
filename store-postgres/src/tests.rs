// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Unit tests for the Postgres store: DSN-password scrubbing, migration/versioning edge cases,
//! and (gated on `BUSBAR_TEST_POSTGRES_URL`) real round-trip and H1-migrate-regression coverage
//! against a live `postgres:16` — see this crate's own doc comment for the docker readiness-poll
//! pattern these live tests expect a caller (CI / local dev) to provide.

use super::*;

/// L2: a connect-error string must never leak the DSN password. `dsn_password` extracts it from
/// both the URL and libpq keyword forms, and `scrub` redacts BOTH raw and percent-decoded forms.
#[test]
fn dsn_password_extraction_and_scrub() {
    // URL form.
    assert_eq!(
        dsn_password("postgres://user:s3cr3t@host:5432/db").as_deref(),
        Some("s3cr3t")
    );
    // URL form, percent-encoded password.
    assert_eq!(
        dsn_password("postgresql://u:p%40ss@host/db").as_deref(),
        Some("p%40ss")
    );
    // libpq keyword form.
    assert_eq!(
        dsn_password("host=db user=u password=kwsecret dbname=x").as_deref(),
        Some("kwsecret")
    );
    // No password.
    assert_eq!(dsn_password("postgres://host:5432/db"), None);
    assert_eq!(dsn_password("host=db user=u"), None);

    // A connect error embedding the DSN is scrubbed of the raw AND decoded password.
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

/// End-to-end against a REAL Postgres, gated on `BUSBAR_TEST_POSTGRES_URL` (a docker
/// `postgres:16` service in CI). Skips cleanly when unset LOCALLY so the default `cargo test`
/// needs no database - but MUST NOT silently skip in CI: CI provisions the service and sets the
/// URL (see .github/workflows/ci.yml), so when `CI` is set the missing URL is a HARD FAILURE
/// rather than a silent skip. Otherwise a broken CI service block would let the only coverage of
/// the delete_key cascade / credential cleanup vanish unnoticed (P1 #6).
#[test]
fn roundtrip_against_live_postgres() {
    let url = match std::env::var("BUSBAR_TEST_POSTGRES_URL") {
        Ok(url) => url,
        Err(_) if std::env::var_os("CI").is_some() => {
            panic!(
                "BUSBAR_TEST_POSTGRES_URL is unset under CI: the Postgres service container must \
                 provision it (see .github/workflows/ci.yml). Refusing to silently skip the only \
                 live-DB coverage in CI."
            );
        }
        Err(_) => {
            eprintln!("skip: set BUSBAR_TEST_POSTGRES_URL to run the Postgres store test");
            return;
        }
    };
    let store = PostgresStore::connect(&url).expect("connect");
    // Isolate from any prior run.
    let _ = store.delete_key("vk_pg");

    let key = VirtualKey {
        id: "vk_pg".into(),
        key_hash: "h".into(),
        name: "pg".into(),
        allowed_pools: Some(vec!["prod,special".into()]),
        enabled: true,
        created_at: 99,
        group: Some("growth".into()),
        labels: std::collections::BTreeMap::from([("team".into(), "growth".into())]),
    };
    store.put_key(&key).unwrap();
    let got = store.get_key("vk_pg").unwrap().unwrap();
    // The comma-bearing pool name survives (JSON encoding, not a bare comma split).
    assert_eq!(got.allowed_pools, Some(vec!["prod,special".to_string()]));
    assert_eq!(
        got.group.as_deref(),
        Some("growth"),
        "the group binding survives the Postgres round-trip"
    );
    assert_eq!(got.labels.get("team").map(String::as_str), Some("growth"));
    // C6 grant intent round-trips: NULL (all pools) vs '[]' (no pools) never collapse.
    let mut all = key.clone();
    all.id = "vk_pg_all".into();
    all.key_hash = "h_all".into();
    all.allowed_pools = None;
    let mut none = key.clone();
    none.id = "vk_pg_none".into();
    none.key_hash = "h_none".into();
    none.allowed_pools = Some(vec![]);
    store.put_key(&all).unwrap();
    store.put_key(&none).unwrap();
    assert_eq!(
        store.get_key("vk_pg_all").unwrap().unwrap().allowed_pools,
        None
    );
    assert_eq!(
        store.get_key("vk_pg_none").unwrap().unwrap().allowed_pools,
        Some(vec![])
    );
    store.delete_key("vk_pg_all").unwrap();
    store.delete_key("vk_pg_none").unwrap();

    // Absolute put_usage of a per-model token ledger, then read back.
    let base = UsageLedger {
        requests: 3,
        // v4: only 2 of the 3 admitted requests are billable (one non-2xx refunded off the fee
        // base); the two axes must persist and read back INDEPENDENTLY.
        billable_requests: 2,
        models: vec![ModelTokens {
            model: "gpt-5".into(),
            tokens: TierTokens {
                input: 9,
                output: 4,
                cache_read: 2,
                cache_write: 1,
            },
        }],
    };
    store.put_usage("vk_pg", 100, &base).unwrap();
    let u = store.get_usage("vk_pg", 100).unwrap();
    assert_eq!(u.requests, 3);
    assert_eq!(
        u.billable_requests, 2,
        "billable_requests persists independently of requests"
    );
    assert_eq!(u.tokens_for("gpt-5").unwrap().input, 9);

    // ADDITIVE fleet flush primitive: add_usage accumulates per-model signed deltas on top
    // (and a negative delta refunds, floored at 0). A second model materializes its own row.
    let mk_delta = |requests: i64, model: &str, input: i64| busbar_api::UsageDelta {
        requests,
        // Mirror the billable axis onto the request delta for this token-focused block; the
        // billable-specific flooring is asserted below.
        billable_requests: requests,
        models: vec![busbar_api::ModelTokensDelta {
            model: model.into(),
            tokens: busbar_api::TierTokensDelta {
                input,
                output: 1,
                cache_read: 0,
                cache_write: 0,
            },
        }],
    };
    store
        .add_usage("vk_pg", 100, &mk_delta(2, "gpt-5", 1))
        .unwrap();
    let u = store.get_usage("vk_pg", 100).unwrap();
    assert_eq!(u.requests, 5, "add_usage accumulates the requests delta");
    assert_eq!(
        u.billable_requests, 4,
        "add_usage accumulates the billable_requests delta on its own axis (2 + 2)"
    );
    let t = u.tokens_for("gpt-5").unwrap();
    assert_eq!(
        (t.input, t.output),
        (10, 5),
        "add_usage accumulates per-model tier deltas"
    );
    store
        .add_usage("vk_pg", 100, &mk_delta(0, "haiku", 7))
        .unwrap();
    assert_eq!(
        store.get_usage("vk_pg", 100).unwrap().models.len(),
        2,
        "a second model materializes its own ledger row"
    );
    store
        .add_usage("vk_pg", 100, &mk_delta(-100, "gpt-5", -10_000))
        .unwrap();
    let u = store.get_usage("vk_pg", 100).unwrap();
    assert_eq!(
        (u.requests, u.tokens_for("gpt-5").unwrap().input),
        (0, 0),
        "an over-refund floors at 0, never negative"
    );
    assert_eq!(
        u.billable_requests, 0,
        "the billable fee base floors at 0 under an over-refund too"
    );

    // METERING: the billing-critical raw-consumption UPSERT. Two deltas for the SAME
    // (key, bucket, model, provider) must ACCUMULATE (ON CONFLICT DO UPDATE), not overwrite -
    // this is what a third party's cost reconstruction reads back. Use a private bucket so the
    // read-back is isolated from any other row in the table.
    let m_bucket = 20_260_722_u64;
    let delta = |ti, to, tcr, tcc| MeteringDelta {
        key_id: "vk_pg".into(),
        bucket: m_bucket,
        model: "gpt-x".into(),
        provider: "special".into(),
        tokens_input: ti,
        tokens_output: to,
        tokens_cache_read: tcr,
        tokens_cache_creation: tcc,
        requests: 1,
    };
    store.add_metering(&delta(10, 5, 2, 1)).unwrap();
    store.add_metering(&delta(30, 15, 4, 3)).unwrap();
    let rows: Vec<MeteringRow> = store
        .list_metering(m_bucket)
        .unwrap()
        .into_iter()
        .filter(|r| r.key_id == "vk_pg")
        .collect();
    assert_eq!(rows.len(), 1, "the two deltas UPSERT into ONE row");
    let r = &rows[0];
    assert_eq!(
        (
            r.model.as_str(),
            r.provider.as_str(),
            r.tokens_input,
            r.tokens_output,
            r.tokens_cache_read,
            r.tokens_cache_creation,
            r.requests,
        ),
        ("gpt-x", "special", 40, 20, 6, 4, 2),
        "the UPSERT accumulates every token class plus the request count"
    );
    // Cleanup so the test is re-runnable against a persistent CI database.
    store
        .lock()
        .execute(
            "DELETE FROM usage_metering WHERE key_id='vk_pg' AND bucket=$1",
            &[&(m_bucket as i64)],
        )
        .expect("metering cleanup");

    // AUDIT: the tamper-evidence chain must round-trip through the store verbatim, oldest-first
    // by seq (the store never interprets the hash chain - it is a dumb durable sink). Isolate on a
    // high seq band so a persistent CI table does not collide, and clean up afterward.
    let a_base = 900_000_000_u64;
    let mk = |seq: u64, prev: &str, hash: &str| AuditRecord {
        seq,
        ts: 1000 + seq,
        action: "plugin.install".into(),
        resource: format!("plugin:{seq}"),
        outcome: "applied".into(),
        principal: "admin".into(),
        prev_hash: prev.into(),
        hash: hash.into(),
    };
    // Append OUT of seq order to prove the ORDER BY seq on read.
    store.append_audit(&mk(a_base + 2, "h1", "h2")).unwrap();
    store.append_audit(&mk(a_base + 1, "", "h1")).unwrap();
    store.append_audit(&mk(a_base + 3, "h2", "h3")).unwrap();
    let chain: Vec<AuditRecord> = store
        .list_audit()
        .unwrap()
        .into_iter()
        .filter(|a| a.seq >= a_base)
        .collect();
    assert_eq!(chain.len(), 3);
    assert_eq!(
        (chain[0].seq, chain[1].seq, chain[2].seq),
        (a_base + 1, a_base + 2, a_base + 3),
        "audit records return oldest-first by seq"
    );
    assert_eq!(chain[0].prev_hash, "", "chain head links to nothing");
    assert_eq!(chain[1].prev_hash, "h1");
    assert_eq!(
        (chain[2].prev_hash.as_str(), chain[2].hash.as_str()),
        ("h2", "h3"),
        "the prev_hash -> hash links survive the round-trip verbatim"
    );
    assert_eq!(chain[2].resource, format!("plugin:{}", a_base + 3));
    // A re-append of the same seq UPSERTs (idempotent replay), never a UNIQUE violation.
    store.append_audit(&mk(a_base + 2, "h1", "h2b")).unwrap();
    let replayed: Vec<AuditRecord> = store
        .list_audit()
        .unwrap()
        .into_iter()
        .filter(|a| a.seq >= a_base)
        .collect();
    assert_eq!(replayed.len(), 3, "re-append of an existing seq upserts");
    assert_eq!(
        replayed[1].hash, "h2b",
        "the replayed record overwrites the prior digest"
    );
    // Cleanup so the test is re-runnable against a persistent CI database.
    store
        .lock()
        .execute("DELETE FROM audit_log WHERE seq >= $1", &[&(a_base as i64)])
        .expect("audit cleanup");

    // DENYLIST (P3, signed-token revocation): add a subject, list it back, and prove idempotency
    // (a repeat add leaves exactly one entry). Isolate on a unique sub and clean up afterward.
    let dsub = format!("sub_pg_{}", std::process::id());
    store
        .lock()
        .execute("DELETE FROM denylist WHERE sub=$1", &[&dsub])
        .expect("denylist pre-clean");
    store.add_denylist(&dsub, "compromised").unwrap();
    store.add_denylist(&dsub, "still compromised").unwrap();
    let denied = store.list_denylist().unwrap();
    assert_eq!(
        denied.iter().filter(|s| **s == dsub).count(),
        1,
        "add_denylist is idempotent: the sub is denied exactly once"
    );
    store
        .lock()
        .execute("DELETE FROM denylist WHERE sub=$1", &[&dsub])
        .expect("denylist cleanup");

    // Attach an AWS credential so delete_key's CASCADE (key + usage + credentials) can be
    // verified end to end - the credential-cleanup path P1 #6 flagged as untested.
    let cred = AwsCredential {
        access_key_id: "AKIA_PG_TEST".into(),
        key_id: "vk_pg".into(),
        secret_access_key: "s3cr3t".into(),
    };
    store.put_aws_credential(&cred).unwrap();
    assert!(
        store
            .list_aws_credentials()
            .unwrap()
            .iter()
            .any(|c| c.access_key_id == "AKIA_PG_TEST"),
        "the AWS credential must be present before delete_key"
    );

    store.delete_key("vk_pg").unwrap();
    // CASCADE: the key, its token ledger, AND its AWS credential are all gone.
    assert!(store.get_key("vk_pg").unwrap().is_none());
    assert_eq!(
        store.get_usage("vk_pg", 100).unwrap(),
        UsageLedger::default(),
        "delete_key must cascade to the token ledger"
    );
    assert!(
        !store
            .list_aws_credentials()
            .unwrap()
            .iter()
            .any(|c| c.access_key_id == "AKIA_PG_TEST"),
        "delete_key must cascade to the AWS credentials (credential cleanup, P1 #6)"
    );
    assert!(
        !store
            .list_metering(m_bucket)
            .unwrap()
            .iter()
            .any(|r| r.key_id == "vk_pg"),
        "delete_key must cascade to usage_metering (the raw billing ledger) too, or a reused id \
         inherits the old key's stale token/request counts"
    );
}

/// H1 (data-loss regression): migrate() must NEVER conflate a transient version-read error with
/// a fresh (unversioned) database. Only SQLSTATE 42P01 (`undefined_table`) counts as version 0;
/// every OTHER error class (connection/timeout/permission/syntax) is fatal and must PROPAGATE so
/// boot fails LOUDLY rather than defaulting to 0 and dropping every governance table on a healthy
/// v2 DB. This test builds REAL driver errors from a live connection and asserts the classifier:
/// a genuine missing-table error is version-0; any other error is NOT (so migrate returns Err).
/// Gated on `BUSBAR_TEST_POSTGRES_URL` (skips locally, HARD-FAILS in CI - same policy as the
/// round-trip test).
#[test]
fn migrate_version_read_error_is_not_treated_as_fresh_db() {
    let url = match std::env::var("BUSBAR_TEST_POSTGRES_URL") {
        Ok(url) => url,
        Err(_) if std::env::var_os("CI").is_some() => {
            panic!(
                "BUSBAR_TEST_POSTGRES_URL is unset under CI: refusing to silently skip the H1 \
                 data-loss regression (see .github/workflows/ci.yml)."
            );
        }
        Err(_) => {
            eprintln!("skip: set BUSBAR_TEST_POSTGRES_URL to run the H1 migrate regression");
            return;
        }
    };
    // Migrate first so `busbar_schema` exists - the undefined-COLUMN probe below then isolates
    // a non-42P01 error class (a missing table would itself be 42P01 and confuse the assertion).
    let store = PostgresStore::connect(&url).expect("connect+migrate");
    let mut client = Client::connect(&url, NoTls).expect("connect");

    // A genuine missing table (42P01) is the ONLY error migrate() may read as "version 0".
    let missing = client
        .query_opt("SELECT MAX(version) FROM busbar_no_such_table_zzz_h1", &[])
        .expect_err("querying a missing table must error");
    assert!(
        is_undefined_table(&missing),
        "a missing-table read must classify as undefined_table (version 0), got {:?}",
        missing.code()
    );

    // A DIFFERENT error class (undefined COLUMN, 42703) against the EXISTING busbar_schema table
    // must NOT be read as version 0 - migrate() propagates it and fails boot. This is the exact
    // class the old `.ok().flatten()...unwrap_or(0)` swallowed, then dropped every table.
    let other = client
        .query_opt("SELECT no_such_column_zzz_h1 FROM busbar_schema", &[])
        .expect_err("querying a missing column must error");
    assert_eq!(
        other.code(),
        Some(&postgres::error::SqlState::UNDEFINED_COLUMN),
        "sanity: the probe hits the missing-column class, not a missing-table"
    );
    assert!(
        !is_undefined_table(&other),
        "a non-missing-table error must NOT classify as version 0 (must fail boot), got {:?}",
        other.code()
    );

    // End to end: a healthy current-version DB carrying data survives a re-run of migrate()
    // (connect() runs it). Seed a key, reconnect (re-migrate), and assert the key is STILL
    // there - the legacy DROP path never fires on a correctly-read current version.
    let key = VirtualKey {
        id: "vk_h1".into(),
        key_hash: "h1_hash".into(),
        name: "h1".into(),
        allowed_pools: None,
        enabled: true,
        created_at: 1,
        group: None,
        labels: std::collections::BTreeMap::new(),
    };
    let _ = store.delete_key("vk_h1");
    store.put_key(&key).unwrap();
    drop(store);
    let store2 = PostgresStore::connect(&url).expect("re-connect+re-migrate");
    assert!(
        store2.get_key("vk_h1").unwrap().is_some(),
        "a healthy current-version DB must NOT be dropped by a migrate() re-run"
    );
    store2.delete_key("vk_h1").unwrap();
}

/// Isolated, minimal repro: delete_key must remove usage_metering rows for the deleted key.
#[test]
fn delete_key_cascades_to_usage_metering_isolated() {
    let url = match std::env::var("BUSBAR_TEST_POSTGRES_URL") {
        Ok(u) => u,
        Err(_) => {
            if std::env::var_os("CI").is_some() {
                panic!("BUSBAR_TEST_POSTGRES_URL is unset under CI");
            }
            eprintln!("skip: set BUSBAR_TEST_POSTGRES_URL");
            return;
        }
    };
    let store = PostgresStore::connect(&url).expect("connect+migrate");
    let _ = store.delete_key("vk_iso_test");
    let key = VirtualKey {
        id: "vk_iso_test".into(),
        key_hash: "h_iso".into(),
        name: "iso".into(),
        allowed_pools: None,
        enabled: true,
        created_at: 1,
        group: None,
        labels: std::collections::BTreeMap::new(),
    };
    store.put_key(&key).unwrap();
    let bucket = 99_999_888_u64;
    store
        .add_metering(&MeteringDelta {
            key_id: "vk_iso_test".into(),
            bucket,
            model: "m".into(),
            provider: "p".into(),
            tokens_input: 1,
            tokens_output: 1,
            tokens_cache_read: 0,
            tokens_cache_creation: 0,
            requests: 1,
        })
        .unwrap();
    let before = store.list_metering(bucket).unwrap();
    assert!(
        before.iter().any(|r| r.key_id == "vk_iso_test"),
        "metering row must exist before delete"
    );
    store.delete_key("vk_iso_test").unwrap();
    let after = store.list_metering(bucket).unwrap();
    assert!(
        !after.iter().any(|r| r.key_id == "vk_iso_test"),
        "delete_key must remove usage_metering rows too, got: {after:?}"
    );
}

/// `get_usage`'s two SELECTs need one consistent snapshot so a concurrent add_usage can never
/// produce a torn read (READ COMMITTED gives each statement its OWN fresh snapshot; REPEATABLE READ
/// takes one snapshot at the transaction's first statement and holds it). Proves the ACTUAL
/// transaction-open helper `get_usage` calls (`PostgresStore::snapshot_consistent_tx`, not a
/// hand-rolled duplicate) really opens at REPEATABLE READ, by asking Postgres itself.
///
/// RED (pre-fix, plain `client.transaction()`): reports "read committed".
/// GREEN: reports "repeatable read".
#[test]
fn get_usage_transaction_is_actually_repeatable_read() {
    let url = match std::env::var("BUSBAR_TEST_POSTGRES_URL") {
        Ok(u) => u,
        Err(_) => {
            if std::env::var_os("CI").is_some() {
                panic!("BUSBAR_TEST_POSTGRES_URL is unset under CI");
            }
            eprintln!("skip: set BUSBAR_TEST_POSTGRES_URL");
            return;
        }
    };
    let store = PostgresStore::connect(&url).expect("connect+migrate");
    let mut client = store.lock();
    let mut tx = PostgresStore::snapshot_consistent_tx(&mut client).expect("open tx");
    let level: String = tx
        .query_one("SHOW transaction_isolation", &[])
        .unwrap()
        .get(0);
    tx.rollback().unwrap();
    assert_eq!(
        level, "repeatable read",
        "get_usage's transaction-open helper must actually open at REPEATABLE READ, got: {level}"
    );
}

/// `list_metering(bucket)` filters on `bucket` alone -- NOT the leading column of
/// `usage_metering`'s primary key `(key_id, bucket, model, provider)` -- so without a dedicated
/// index Postgres cannot seek and must scan. Proves the index exists and is actually usable for
/// this exact query shape (checked via the query planner, not just presence in `pg_indexes`).
#[test]
fn usage_metering_bucket_index_exists_and_is_used() {
    let url = match std::env::var("BUSBAR_TEST_POSTGRES_URL") {
        Ok(u) => u,
        Err(_) => {
            if std::env::var_os("CI").is_some() {
                panic!("BUSBAR_TEST_POSTGRES_URL is unset under CI");
            }
            eprintln!("skip: set BUSBAR_TEST_POSTGRES_URL");
            return;
        }
    };
    let store = PostgresStore::connect(&url).expect("connect+migrate");
    let exists: bool = store
        .lock()
        .query_one(
            "SELECT EXISTS (SELECT 1 FROM pg_indexes WHERE tablename='usage_metering' \
             AND indexname='idx_usage_metering_bucket')",
            &[],
        )
        .unwrap()
        .get(0);
    assert!(exists, "idx_usage_metering_bucket must exist");

    let plan: Vec<String> = store
        .lock()
        .query(
            "EXPLAIN SELECT * FROM usage_metering WHERE bucket = 12345",
            &[],
        )
        .unwrap()
        .iter()
        .map(|r| r.get::<_, String>(0))
        .collect();
    let plan_text = plan.join("\n");
    assert!(
        plan_text.contains("idx_usage_metering_bucket"),
        "the planner must actually choose the bucket index for this query shape, got plan:\n{plan_text}"
    );
}

/// `put_usage`'s per-model loop now issues ONE multi-row INSERT instead of one round trip per
/// model. Proves the batched write is functionally identical to N separate inserts for 3+ models
/// (multiple distinct models land correctly, values are not swapped/misaligned across rows).
#[test]
fn put_usage_batched_insert_handles_multiple_models_correctly() {
    let url = match std::env::var("BUSBAR_TEST_POSTGRES_URL") {
        Ok(u) => u,
        Err(_) => {
            if std::env::var_os("CI").is_some() {
                panic!("BUSBAR_TEST_POSTGRES_URL is unset under CI");
            }
            eprintln!("skip: set BUSBAR_TEST_POSTGRES_URL");
            return;
        }
    };
    let store = PostgresStore::connect(&url).expect("connect+migrate");
    let bucket = "vk_batch_insert_test";
    let ws = 777_777_u64;
    let ledger = UsageLedger {
        requests: 3,
        billable_requests: 3,
        models: vec![
            ModelTokens {
                model: "model-a".into(),
                tokens: TierTokens {
                    input: 1,
                    output: 2,
                    cache_read: 3,
                    cache_write: 4,
                },
            },
            ModelTokens {
                model: "model-b".into(),
                tokens: TierTokens {
                    input: 10,
                    output: 20,
                    cache_read: 30,
                    cache_write: 40,
                },
            },
            ModelTokens {
                model: "model-c".into(),
                tokens: TierTokens {
                    input: 100,
                    output: 200,
                    cache_read: 300,
                    cache_write: 400,
                },
            },
        ],
    };
    store.put_usage(bucket, ws, &ledger).unwrap();
    let got = store.get_usage(bucket, ws).unwrap();
    assert_eq!(got.models.len(), 3);
    for m in &ledger.models {
        let t = got.tokens_for(&m.model).unwrap_or_else(|| {
            panic!(
                "model {} missing from batched-insert result: {got:?}",
                m.model
            )
        });
        assert_eq!(
            (t.input, t.output, t.cache_read, t.cache_write),
            (
                m.tokens.input,
                m.tokens.output,
                m.tokens.cache_read,
                m.tokens.cache_write
            ),
            "model {} got the wrong row's values -- rows misaligned in the batched insert",
            m.model
        );
    }
}
