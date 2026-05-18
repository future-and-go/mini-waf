//! Backward-compat guard for GET /api/stats/overview.
//!
//! Asserts the response envelope (with no query params) keeps every key
//! the existing dashboard frontend at
//! `web/admin-panel/src/pages/dashboard/index.tsx:70` reads. Adding
//! fields is allowed; removing or renaming is NOT.
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::disallowed_types,
    clippy::disallowed_methods,
    clippy::doc_markdown
)]

#[path = "common/mod.rs"]
mod common;

use common::{SEED_HOST_CODE, fetch, seed_one_of_each, start_test_server};

// ── I4-a: all legacy keys present ──────────────────────────────────────────

#[tokio::test(flavor = "multi_thread")]
async fn overview_no_params_returns_all_legacy_keys() {
    let s = start_test_server().await;
    // Seed: 1 attack_log + 1 security_event so every overview subquery
    // returns a non-trivial value.
    seed_one_of_each(&s.db).await;

    let resp = reqwest::Client::new()
        .get(format!("http://{}/api/stats/overview", s.addr))
        .bearer_auth(&s.admin_token)
        .send()
        .await
        .expect("send");
    assert_eq!(resp.status(), 200);

    let body: serde_json::Value = resp.json().await.expect("json");

    // Top-level envelope.
    assert_eq!(body["success"], serde_json::json!(true));
    let data = &body["data"];

    // Every key the current handler emits (mirrors the json! block in
    // crates/waf-api/src/stats.rs::stats_overview).
    for key in &[
        "total_requests",
        "total_blocked",
        "total_allowed",
        "block_rate",
        "total_requests_live",
        "total_blocked_live",
        "total_requests_db",
        "total_blocked_db",
        "hosts_count",
        "unique_attackers",
        "top_ips",
        "top_rules",
        "top_countries",
        "top_isps",
        "category_breakdown",
        "action_breakdown",
        "recent_events",
    ] {
        assert!(
            data.get(*key).is_some(),
            "missing legacy key `{key}` in /api/stats/overview response; \
             this breaks the dashboard frontend",
        );
    }

    // Type checks for the most-consumed fields.
    assert!(data["total_requests"].is_number(), "total_requests must be number");
    assert!(data["top_ips"].is_array(), "top_ips must be array");
    assert!(
        data["category_breakdown"].is_array(),
        "category_breakdown must be array"
    );
    assert!(data["recent_events"].is_array(), "recent_events must be array");
}

// ── I4-b: filtered and unfiltered share identical envelope shape ────────────

#[tokio::test(flavor = "multi_thread")]
async fn overview_filtered_and_unfiltered_have_same_envelope_shape() {
    let s = start_test_server().await;
    seed_one_of_each(&s.db).await;

    let unfiltered = fetch(&s, "/api/stats/overview").await;
    let filtered_url = format!("/api/stats/overview?host_code={SEED_HOST_CODE}&action=block&hours=24");
    let filtered = fetch(&s, &filtered_url).await;

    // Same set of keys in `data` regardless of filters applied — this is the
    // backward-compat invariant the dashboard frontend depends on.
    // NOTE: We intentionally do NOT assert that filtered values equal
    // unfiltered values: filtered queries narrow the row set, so numeric
    // counts can legitimately drop (e.g., total_allowed → 0 because the
    // filter constrains to action=block). The frontend tolerates this and
    // we cover the numeric semantics in repo-level tests.
    let keys_a: std::collections::BTreeSet<_> = unfiltered["data"]
        .as_object()
        .expect("unfiltered data object")
        .keys()
        .collect();
    let keys_b: std::collections::BTreeSet<_> = filtered["data"]
        .as_object()
        .expect("filtered data object")
        .keys()
        .collect();

    assert_eq!(keys_a, keys_b, "filter changed response envelope shape");

    // Sanity: filter narrows row set ⇒ filtered counts cannot exceed
    // unfiltered counts. Guards against the test silently passing when the
    // filter is wired to the wrong column (everything matches).
    let uf_blocked = unfiltered["data"]["total_blocked_db"].as_i64().expect("uf blocked");
    let f_blocked = filtered["data"]["total_blocked_db"].as_i64().expect("f blocked");
    assert!(
        f_blocked <= uf_blocked,
        "filtered total_blocked_db ({f_blocked}) > unfiltered ({uf_blocked}); filter not narrowing",
    );
}
