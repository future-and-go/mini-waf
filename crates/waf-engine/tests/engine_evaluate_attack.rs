//! Phase 07 — `WafEngine::inspect()` blocks classic attack payloads.

#![allow(clippy::unwrap_used, clippy::expect_used)]

#[path = "common/mod.rs"]
mod common;

use common::{make_ctx, start_engine};
use waf_common::WafAction;

#[tokio::test(flavor = "multi_thread")]
async fn sqli_in_query_string_blocked() {
    let fx = start_engine().await;
    let mut ctx = make_ctx("attack", "/products", "10.0.0.1");
    ctx.query = "id=1' OR '1'='1".into();
    let decision = fx.engine.inspect(&mut ctx).await;
    assert!(
        !matches!(decision.action, WafAction::Allow),
        "SQLi must not be allowed; got {:?}",
        decision.action
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn xss_in_query_blocked() {
    let fx = start_engine().await;
    let mut ctx = make_ctx("attack", "/search", "10.0.0.2");
    ctx.query = "q=<script>alert(1)</script>".into();
    let decision = fx.engine.inspect(&mut ctx).await;
    assert!(
        !matches!(decision.action, WafAction::Allow),
        "XSS must not be allowed; got {:?}",
        decision.action
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn directory_traversal_in_path_blocked() {
    let fx = start_engine().await;
    let mut ctx = make_ctx("attack", "/files/../../etc/passwd", "10.0.0.3");
    let decision = fx.engine.inspect(&mut ctx).await;
    assert!(
        !matches!(decision.action, WafAction::Allow),
        "directory traversal must not be allowed; got {:?}",
        decision.action
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn rce_payload_blocked() {
    let fx = start_engine().await;
    let mut ctx = make_ctx("attack", "/exec", "10.0.0.4");
    ctx.query = "cmd=cat%20/etc/passwd;%20id".into();
    let decision = fx.engine.inspect(&mut ctx).await;
    assert!(
        !matches!(decision.action, WafAction::Allow),
        "RCE must not be allowed; got {:?}",
        decision.action
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn scanner_user_agent_blocked() {
    let fx = start_engine().await;
    let mut ctx = make_ctx("attack", "/", "10.0.0.5");
    ctx.headers
        .insert("user-agent".into(), "sqlmap/1.5.7#stable (https://sqlmap.org)".into());
    let decision = fx.engine.inspect(&mut ctx).await;
    assert!(
        !matches!(decision.action, WafAction::Allow),
        "scanner UA must not be allowed; got {:?}",
        decision.action
    );
}
