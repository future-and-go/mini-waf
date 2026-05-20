// Integration tests for the live-counter / block-rate branches of
// GET /api/stats/overview. The base overview tests never bump the in-process
// counters, so the `total_requests_live > 0` and `block_rate != 0` arms in
// crates/waf-api/src/stats.rs::stats_overview stay unexercised. These tests
// poke the AppState counters directly (they are Arc<AtomicU64>) and assert
// the response routes through the live values.
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

use common::{fetch, start_test_server};

#[tokio::test(flavor = "multi_thread")]
async fn overview_uses_live_counter_when_requests_present() {
    let s = start_test_server().await;

    // Bump the in-process counter so stats_overview takes the live-counter arm.
    for _ in 0..7 {
        s.state.increment_requests();
    }
    for _ in 0..3 {
        s.state.increment_blocked();
    }
    assert_eq!(s.state.total_requests(), 7);
    assert_eq!(s.state.total_blocked(), 3);

    let body = fetch(&s, "/api/stats/overview").await;
    assert_eq!(body["success"], serde_json::json!(true));

    // Live values must surface as the primary metrics.
    assert_eq!(body["data"]["total_requests"], serde_json::json!(7));
    assert_eq!(body["data"]["total_blocked"], serde_json::json!(3));
    assert_eq!(body["data"]["total_allowed"], serde_json::json!(4));
    assert_eq!(body["data"]["total_requests_live"], serde_json::json!(7));
    assert_eq!(body["data"]["total_blocked_live"], serde_json::json!(3));

    // block_rate = 3 / 7 ≈ 0.4286 (rounded to 4 dp).
    let rate = body["data"]["block_rate"].as_f64().expect("block_rate f64");
    assert!((rate - 0.4286).abs() < 1e-4, "expected ~0.4286, got {rate}");
}

#[tokio::test(flavor = "multi_thread")]
async fn overview_block_rate_zero_when_no_blocks() {
    let s = start_test_server().await;
    s.state.increment_requests();
    // No blocks yet → block_rate must be 0.0 (avoid div-by-zero is the
    // separate branch covered by overview_block_rate_zero_when_no_requests).
    let body = fetch(&s, "/api/stats/overview").await;
    assert_eq!(body["success"], serde_json::json!(true));
    assert_eq!(body["data"]["total_requests"], serde_json::json!(1));
    assert_eq!(body["data"]["total_blocked"], serde_json::json!(0));
    assert_eq!(body["data"]["block_rate"], serde_json::json!(0.0));
}

#[tokio::test(flavor = "multi_thread")]
async fn overview_block_rate_zero_when_no_requests() {
    // Untouched counters → total_requests == 0 → the `if total_requests == 0`
    // arm produces block_rate = 0 without division.
    let s = start_test_server().await;
    let body = fetch(&s, "/api/stats/overview").await;
    assert_eq!(body["success"], serde_json::json!(true));
    assert_eq!(body["data"]["block_rate"], serde_json::json!(0.0));
}

#[tokio::test(flavor = "multi_thread")]
async fn overview_total_allowed_saturates_when_blocks_exceed_requests() {
    // Pathological accounting (blocks > requests) must not underflow — the
    // handler uses saturating_sub. This locks the invariant against future
    // refactors that drop the saturating semantics.
    let s = start_test_server().await;
    s.state.increment_requests();
    for _ in 0..5 {
        s.state.increment_blocked();
    }
    let body = fetch(&s, "/api/stats/overview").await;
    assert_eq!(body["data"]["total_requests"], serde_json::json!(1));
    assert_eq!(body["data"]["total_blocked"], serde_json::json!(5));
    assert_eq!(
        body["data"]["total_allowed"],
        serde_json::json!(0),
        "saturating_sub must clamp to 0, not panic / underflow"
    );
}
