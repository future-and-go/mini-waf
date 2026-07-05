//! Engine-level proof that `start_risk_watcher` wires the L0 seed layer and
//! the challenge-credit verifier into the scorer `inspect()` actually uses —
//! no hand-constructed `Scorer`. Regression coverage for the gap where
//! `build_scorer` attached only the canary layer, so `seed.enabled: true`
//! silently scored nothing.

#![allow(clippy::unwrap_used, clippy::expect_used)]

mod common;

use std::sync::Arc;

use waf_engine::risk::challenge_credit::{ChallengeIssuer, HmacSecret};
use waf_engine::risk::key::RiskKey;

/// Write a risk config into `dir` and return its path.
fn write_risk_yaml(dir: &std::path::Path, body: &str) -> std::path::PathBuf {
    let path = dir.join("risk.yaml");
    std::fs::write(&path, body).unwrap();
    path
}

/// `common::make_ctx` plus realistic browser headers.
///
/// The shared fixture sends no headers at all, which the bot check blocks at
/// L1 — and risk escalation only fires on a plain Allow, so these tests would
/// assert against the bot verdict instead of the risk one. A browser UA must
/// also bring `accept`/`accept-language`, or the header-sanity anomaly adds
/// +5 per missing header and skews every score expectation.
fn browser_ctx(host_code: &str, path: &str, ip: &str) -> waf_common::RequestCtx {
    let mut ctx = common::make_ctx(host_code, path, ip);
    ctx.headers.insert(
        "user-agent".into(),
        "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0".into(),
    );
    ctx.headers.insert(
        "accept".into(),
        "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8".into(),
    );
    ctx.headers.insert("accept-language".into(), "en-US,en;q=0.9".into());
    ctx
}

#[tokio::test]
async fn tor_exit_ip_accrues_seed_delta_through_inspect() {
    let fx = common::start_engine().await;
    let dir = tempfile::tempdir().unwrap();

    let tor_ip = "203.0.113.7";
    let tor_path = dir.path().join("tor-exits.txt");
    std::fs::write(&tor_path, format!("{tor_ip}\n")).unwrap();

    let risk_yaml = write_risk_yaml(
        dir.path(),
        &format!(
            "risk:\n  enabled: true\n  seed:\n    enabled: true\n    tor_exits_path: \"{}\"\n",
            tor_path.display()
        ),
    );
    fx.engine.start_risk_watcher(&risk_yaml).await;

    let mut ctx = browser_ctx("h1", "/", tor_ip);
    let decision = fx.engine.inspect(&mut ctx).await;

    // Default tor_delta is 30, which sits exactly at the default allow
    // threshold (30) — `threshold::decide` challenges at score >= allow, so
    // the seed contribution surfaces as both the score and a Challenge.
    assert_eq!(
        decision.risk_score, 30,
        "tor-exit seed delta must reach the request-path scorer"
    );
    assert!(
        matches!(decision.action, waf_common::WafAction::Challenge),
        "score at the allow threshold must challenge, got {:?}",
        decision.action
    );

    // A non-listed IP on the same engine accrues nothing.
    let mut clean_ctx = browser_ctx("h1", "/", "198.51.100.10");
    let clean = fx.engine.inspect(&mut clean_ctx).await;
    assert_eq!(clean.risk_score, 0, "non-tor IP must not inherit seed deltas");
}

#[tokio::test]
async fn challenge_credit_token_verifies_through_inspect() {
    let fx = common::start_engine().await;
    let dir = tempfile::tempdir().unwrap();

    let secret_path = dir.path().join("hmac.key");
    let risk_yaml = write_risk_yaml(
        dir.path(),
        &format!(
            "risk:\n  enabled: true\n  challenge:\n    enabled: true\n    hmac_secret_path: \"{}\"\n    header_name: \"x-waf-cred\"\n",
            secret_path.display()
        ),
    );
    fx.engine.start_risk_watcher(&risk_yaml).await;

    // The watcher's ChallengeBuilder bootstrapped the secret file; issue a
    // token with the same secret, bound to the IP-axis owner id the scorer
    // derives for this client.
    let ip = "198.51.100.9";
    let secret = HmacSecret::load_or_init(&secret_path).unwrap();
    let issuer = ChallengeIssuer::new(Arc::new(secret), 300);
    let owner = RiskKey::from_ip(ip.parse().unwrap()).owner_id();
    let now_ms = chrono::Utc::now().timestamp_millis();
    let token = issuer.issue(&owner, now_ms);

    // First presentation: Valid outcome, credit delta (-25) clamps to 0.
    let mut ctx = browser_ctx("h1", "/", ip);
    ctx.headers.insert("x-waf-cred".into(), token.clone());
    let first = fx.engine.inspect(&mut ctx).await;
    assert_eq!(first.risk_score, 0, "valid credit must not add risk");

    // Replay of the same token: the verifier consumed the nonce on the first
    // pass, so the second pass must score the replay delta (+30). The valid
    // credit banked raw -25 (`raw_score` is a pre-clamp accumulator; only the
    // exposed score clamps to 0..=100), so the replay lands at raw -25 + 30 =
    // 5. This only happens when the verifier inspect() uses is the one the
    // watcher built — unwired, the replay would score 0.
    let mut replay_ctx = browser_ctx("h1", "/", ip);
    replay_ctx.headers.insert("x-waf-cred".into(), token);
    let replay = fx.engine.inspect(&mut replay_ctx).await;
    assert_eq!(
        replay.risk_score, 5,
        "replayed token must apply replay_delta on top of the banked valid credit"
    );
}
