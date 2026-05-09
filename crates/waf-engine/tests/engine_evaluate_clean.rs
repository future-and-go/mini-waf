//! Phase 07 — `WafEngine::inspect()` returns Allow on benign requests.

#![allow(clippy::unwrap_used, clippy::expect_used)]

#[path = "common/mod.rs"]
mod common;

use bytes::Bytes;
use common::{make_ctx, start_engine};
use waf_common::WafAction;

const BENIGN_UA: &str = "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0";

fn with_ua(mut ctx: waf_common::RequestCtx) -> waf_common::RequestCtx {
    ctx.headers.insert("user-agent".into(), BENIGN_UA.into());
    ctx
}

#[tokio::test(flavor = "multi_thread")]
async fn clean_get_allowed() {
    let fx = start_engine().await;
    let mut ctx = with_ua(make_ctx("clean", "/", "1.2.3.4"));
    let decision = fx.engine.inspect(&mut ctx).await;
    assert!(matches!(decision.action, WafAction::Allow));
}

#[tokio::test(flavor = "multi_thread")]
async fn clean_post_with_small_json_body_allowed() {
    let fx = start_engine().await;
    let mut ctx = with_ua(make_ctx("clean", "/api/items", "1.2.3.4"));
    ctx.method = "POST".into();
    let body = br#"{"name":"hello","qty":1}"#;
    ctx.body_preview = Bytes::copy_from_slice(body);
    ctx.content_length = body.len() as u64;
    ctx.headers.insert("content-type".into(), "application/json".into());
    let decision = fx.engine.inspect(&mut ctx).await;
    assert!(matches!(decision.action, WafAction::Allow));
}

#[tokio::test(flavor = "multi_thread")]
async fn options_request_allowed() {
    let fx = start_engine().await;
    let mut ctx = with_ua(make_ctx("clean", "/api/anything", "1.2.3.4"));
    ctx.method = "OPTIONS".into();
    let decision = fx.engine.inspect(&mut ctx).await;
    assert!(matches!(decision.action, WafAction::Allow));
}

#[tokio::test(flavor = "multi_thread")]
async fn guard_disabled_short_circuits_to_allow() {
    use std::sync::Arc;
    use waf_common::HostConfig;

    let fx = start_engine().await;
    // Even a SQLi-shaped path should be allowed when guard_status=false.
    let mut ctx = make_ctx("off", "/products?id=1' OR '1'='1", "9.9.9.9");
    let host_config = Arc::new(HostConfig {
        code: "off".into(),
        host: "example.com".into(),
        guard_status: false,
        ..HostConfig::default()
    });
    ctx.host_config = host_config;
    let decision = fx.engine.inspect(&mut ctx).await;
    assert!(matches!(decision.action, WafAction::Allow));
}
