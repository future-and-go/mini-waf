---
phase: 5
title: "Gateway wiring + tests + docs"
status: complete
priority: P2
effort: "2-3h"
dependencies: [4]
---

# Phase 5: Gateway wiring + tests + docs

## Overview

**(Major Red-team adjustment — C2 + C8.)** The earlier draft hitched FR-012 onto the existing `proxy.rs:867` call inside `response_filter`. Two distinct problems with that:

1. `proxy.rs:867` is gated on `upstream_contacted`, which is a **misnomer** — `ctx.upstream_addr` is set inside `upstream_peer()` at `proxy.rs:478` BEFORE TCP connect, so origin-down 5xx synthesized by Pingora reaches that branch. FR-012 would mark `Outcome::Failed` on every origin outage and ban legitimate users.
2. `response_filter` fires at **response header arrival**, not body completion. For SSE/long-poll endpoints labeled as Withdrawal in operator config, this fires Outcome::Ok on a request that subsequently drops or times out.

Both are fixed by moving FR-012's dispatch into Pingora's **`logging()` hook at `proxy.rs:1179`** — fires once per request at completion (post-body), independent of `upstream_contacted`, and has the final response status available via `_session`.

This phase: introduce a new engine entry point `engine.on_request_complete(ctx, status, upstream_reached)`, wire it from `logging()`, add the regression integration test, update docs.

## Requirements

- **Functional**:
  - Through the real proxy pipeline, three POST `/api/withdraw` requests with `SID=u1` followed by 2xx responses produce one `Signal::WithdrawalVelocity { count: 3, ok_count: 3, .. }`.
  - The same three requests followed by 4xx responses produce one `Signal::WithdrawalVelocity { count: 3, ok_count: 0, .. }`.
  - A request with no cookie but a populated `FpKey` records under fingerprint identity.
- **Non-functional**:
  - No measurable additional latency on the request path (classifier work moved off it).
  - `cargo bench -p waf-engine --bench tx_velocity*` (if present) does not regress p99 by > 5%.

## Architecture

```
proxy.rs::response_filter (line 861-869)  [unchanged]
  ├─ if upstream_contacted {
  │      self.engine.on_response(req_ctx, status);   ← FR-018 brute-force only
  │  }
  └─ ... existing response filters

proxy.rs::logging() (line 1179)            [NEW dispatch]
  ├─ let status = _session.response_written().map(|h| h.status.as_u16()).unwrap_or(0);
  ├─ let upstream_reached = ctx.upstream_response_observed;   // new bool, set in upstream_response_filter
  ├─ if let Some(req_ctx) = &ctx.request_ctx {
  │      self.engine.on_request_complete(req_ctx, status, upstream_reached);
  │  }
  └─ existing debug log

waf-engine::WafEngine
  ├─ on_response(ctx, status)  ........... FR-018 brute-force (unchanged)
  └─ on_request_complete(ctx, status, upstream_reached) [NEW]
       └─ for check in checkers { check.on_request_complete(ctx, status, upstream_reached); }
       └─ TxVelocityCheck::on_request_complete:
            ├─ if !upstream_reached → skip (origin outage, not a user denial)
            ├─ if status == 0 → skip (client abort)
            ├─ outcome = if (200..300).contains(&status) { Ok } else { Failed }
            └─ store.set_outcome(token, outcome)
```

**Key decisions:**
- `Check` trait gains a new default-no-op method `on_request_complete(&self, ctx, status, upstream_reached)`. `on_response` stays as-is so FR-018 brute-force is untouched.
- `GatewayCtx.upstream_response_observed: bool` — set to `true` inside `upstream_response_filter` (a Pingora hook that fires only when an origin response actually arrives, not on Pingora-synthesized errors).
- `logging()` is the correct dispatch point because it fires exactly once per request, at completion, regardless of streaming/non-streaming bodies.
- WAF-gate-blocked requests do reach `logging()` (response is sent), but with `upstream_reached = false` → FR-012 skips, the event stays `Outcome::Pending`, classifiers ignore it. Identical to the request-never-completing case.

KNOWN GAP (acceptable): requests where the client disconnects mid-stream may reach `logging()` with `status = 0`. We skip those — `Outcome::Pending` is the correct attribution.

## Related Code Files

- **Modify** `crates/waf-engine/src/checks/mod.rs` — add `Check::on_request_complete(&self, _ctx, _status, _upstream_reached) {}` default no-op next to `on_response`.
- **Modify** `crates/waf-engine/src/engine.rs:856-861` area — add `WafEngine::on_request_complete` mirroring the dispatch loop.
- **Modify** `crates/waf-engine/src/checks/tx_velocity/check.rs` — move the `on_response` impl body (token-based set_outcome) onto `on_request_complete` instead. Default-no-op `on_response`.
- **Modify** `crates/gateway/src/proxy.rs`:
  - `GatewayCtx` (search for the struct in `context.rs` or `proxy.rs` — verify with grep) — add `pub upstream_response_observed: bool` (default `false`).
  - Add `upstream_response_filter` impl on `ProxyHttp` to set the bool to `true` when origin actually responds (Pingora calls this only for real upstream responses, not synthesized errors).
  - `logging()` at `:1179` — call `self.engine.on_request_complete(req_ctx, status, ctx.upstream_response_observed)`.
- **Add** `crates/waf-engine/tests/tx_velocity_request_complete_e2e.rs` — integration test (renamed from `tx_velocity_on_response_e2e.rs` to reflect the dispatch point change).
- **Modify** `docs/codebase-summary.md` (if it documents FR-012) — note new semantics + dispatch point.
- **Modify** `plans/260504-1632-fr-012-transaction-velocity/plan.md` — add follow-up note pointing here.
- **Modify** `crates/waf-engine/CLAUDE.md` — FR-012 features bullet must mention the `logging()` dispatch + tristate Outcome + `count`/`ok_count` payload.
- **Modify** `crates/gateway/CLAUDE.md` **(Red-team C27 — currently lacks any FR-012 mention)** — add tx_velocity to the Features bullets and document the `logging()` dispatch.

## TDD Steps

### Step 5.0 — extend the Check trait

In `crates/waf-engine/src/checks/mod.rs` next to the existing `on_response`:

```rust
/// Default no-op completion hook. Override in checks that need
/// upstream-confirmation semantics (FR-012 tx_velocity uses this to
/// distinguish origin-down vs user-denied responses).
///
/// `upstream_reached` is `false` when Pingora synthesized the response
/// (WAF gate block, origin down, ALPN mismatch, TLS handshake fail).
fn on_request_complete(&self, _ctx: &RequestCtx, _status: u16, _upstream_reached: bool) {}
```

In `crates/waf-engine/src/engine.rs` mirror `on_response`:

```rust
pub fn on_request_complete(&self, ctx: &RequestCtx, status: u16, upstream_reached: bool) {
    for check in &self.checkers {
        check.on_request_complete(ctx, status, upstream_reached);
    }
}
```

### Step 5.1 — failing end-to-end test

Create `crates/waf-engine/tests/tx_velocity_request_complete_e2e.rs`:

```rust
//! End-to-end FR-012: request → record → response → set_outcome → signal.
//!
//! Exercises the engine API surface (`evaluate` + `on_response`) without
//! standing up a real Pingora proxy. Locks in the contract that classifiers
//! see honest `ok` values.

use std::sync::Arc;
use arc_swap::ArcSwap;

use waf_engine::checks::tx_velocity::{
    EndpointRole, TxStore, TxVelocityCheck, TxVelocityConfig, TxVelocityFileConfig,
};
use waf_engine::checks::Check;
use waf_engine::device_fp::aggregator::LoggingAggregator;
use waf_engine::device_fp::signal::Signal;
// build_request_ctx is a small helper this test file defines below.

fn config_yaml() -> Arc<ArcSwap<TxVelocityConfig>> {
    let yaml = r#"
tx_velocity:
  enabled: true
  session_cookie: SID
  signal_cooldown_ms: 0
  endpoint_roles:
    - role: withdrawal
      path: "^/api/withdraw"
  classifiers:
    withdrawal_velocity:
      max_count: 2
      window_ms: 60000
"#;
    Arc::new(ArcSwap::from(
        TxVelocityFileConfig::from_yaml_str(yaml).expect("parse cfg"),
    ))
}

#[tokio::test]
async fn three_2xx_withdrawals_emit_full_ok_count() {
    let cfg = config_yaml();
    let agg = LoggingAggregator::new(8);
    let store = Arc::new(TxStore::with_pipeline(
        Arc::clone(&cfg),
        waf_engine::checks::tx_velocity::default_classifiers(&TxVelocityConfig::default()),
        Arc::new(agg.clone()),
    ));
    let check = TxVelocityCheck::new(cfg, Arc::clone(&store));

    let mut ctx = build_request_ctx("/api/withdraw", "SID", "u1");
    for _ in 0..3 {
        check.check(&mut ctx);
        check.on_request_complete(&ctx, 200, /* upstream_reached */ true);
    }
    flush().await;

    let snap = agg.snapshot();
    assert!(
        snap.iter().any(|s| matches!(
            s.signals.first(),
            Some(Signal::WithdrawalVelocity { count: 3, ok_count: 3, .. })
        )),
        "expected count=3 ok_count=3, got {snap:?}",
    );
}

#[tokio::test]
async fn three_4xx_withdrawals_emit_zero_ok_count() {
    let cfg = config_yaml();
    let agg = LoggingAggregator::new(8);
    let store = Arc::new(TxStore::with_pipeline(
        Arc::clone(&cfg),
        waf_engine::checks::tx_velocity::default_classifiers(&TxVelocityConfig::default()),
        Arc::new(agg.clone()),
    ));
    let check = TxVelocityCheck::new(cfg, Arc::clone(&store));

    let mut ctx = build_request_ctx("/api/withdraw", "SID", "u2");
    for _ in 0..3 {
        check.check(&mut ctx);
        check.on_request_complete(&ctx, 403, /* upstream_reached */ true);
    }
    flush().await;

    let snap = agg.snapshot();
    assert!(
        snap.iter().any(|s| matches!(
            s.signals.first(),
            Some(Signal::WithdrawalVelocity { count: 3, ok_count: 0, .. })
        )),
        "expected ok_count=0 for denied burst, got {snap:?}",
    );
}

#[tokio::test]
async fn fingerprint_fallback_when_no_cookie() {
    use waf_common::{FingerprintValue, FpKey};

    let cfg = config_yaml();
    let agg = LoggingAggregator::new(8);
    let store = Arc::new(TxStore::with_pipeline(
        Arc::clone(&cfg),
        waf_engine::checks::tx_velocity::default_classifiers(&TxVelocityConfig::default()),
        Arc::new(agg.clone()),
    ));
    let check = TxVelocityCheck::new(cfg, Arc::clone(&store));

    let fp = Arc::new(FpKey {
        ja3: Some(FingerprintValue::new("ja3-x")),
        ..FpKey::default()
    });
    let mut ctx = build_request_ctx("/api/withdraw", "SID", "");
    ctx.cookies.clear();
    ctx.device_fp = Some(Arc::clone(&fp));

    for _ in 0..3 {
        check.check(&mut ctx);
        check.on_request_complete(&ctx, 200, /* upstream_reached */ true);
    }
    flush().await;

    let snap = agg.snapshot();
    assert!(
        snap.iter().any(|s| s.key == *fp),
        "fp identity must appear in aggregator submission key: {snap:?}",
    );
}

// (Red-team C2 regression) Origin-down 502 with upstream_reached=false MUST
// NOT count as a user denial — events stay Pending.
#[tokio::test]
async fn origin_down_502_does_not_mark_failed() {
    let cfg = config_yaml();
    let agg = LoggingAggregator::new(8);
    let store = Arc::new(TxStore::with_pipeline(
        Arc::clone(&cfg),
        waf_engine::checks::tx_velocity::default_classifiers(&TxVelocityConfig::default()),
        Arc::new(agg.clone()),
    ));
    let check = TxVelocityCheck::new(cfg, Arc::clone(&store));

    let mut ctx = build_request_ctx("/api/withdraw", "SID", "u-orig-down");
    for _ in 0..3 {
        check.check(&mut ctx);
        check.on_request_complete(&ctx, 502, /* upstream_reached */ false);
    }
    flush().await;

    // Pending events ignored by classifier → no submissions.
    assert!(
        agg.snapshot().is_empty(),
        "origin-down must NOT register as user denial: {:?}",
        agg.snapshot()
    );
}

// (Red-team C6 regression) WAF-block (request never reaches upstream)
// MUST leave events as Pending; subsequent legit 2xx must NOT see a
// pre-poisoned ring.
#[tokio::test]
async fn waf_blocked_then_legit_2xx_emits_clean_count() {
    let cfg = config_yaml();
    let agg = LoggingAggregator::new(8);
    let store = Arc::new(TxStore::with_pipeline(
        Arc::clone(&cfg),
        waf_engine::checks::tx_velocity::default_classifiers(&TxVelocityConfig::default()),
        Arc::new(agg.clone()),
    ));
    let check = TxVelocityCheck::new(cfg, Arc::clone(&store));

    let mut ctx = build_request_ctx("/api/withdraw", "SID", "u-victim");
    // 16 WAF-blocked attempts pre-burn the ring as Pending events.
    for _ in 0..16 {
        check.check(&mut ctx);
        // logging() fires with upstream_reached=false (WAF self-block).
        check.on_request_complete(&ctx, 403, /* upstream_reached */ false);
    }
    // Now one legit 2xx (count=1) arrives.
    check.check(&mut ctx);
    check.on_request_complete(&ctx, 200, /* upstream_reached */ true);
    flush().await;

    // Threshold is max_count=2; count of settled events is 1 → no signal.
    let snap = agg.snapshot();
    assert!(
        snap.is_empty(),
        "victim's first legit withdrawal must NOT see a poisoned ring: {snap:?}"
    );
}

// ─── Helpers ───────────────────────────────────────────────────────────────────

async fn flush() {
    tokio::time::sleep(std::time::Duration::from_millis(10)).await;
}

fn build_request_ctx(path: &str, cookie_name: &str, cookie_val: &str) -> waf_common::RequestCtx {
    use std::collections::HashMap;
    use std::net::{IpAddr, Ipv4Addr};
    use waf_common::RequestCtx;

    let mut cookies = HashMap::new();
    if !cookie_val.is_empty() {
        cookies.insert(cookie_name.to_string(), cookie_val.to_string());
    }
    // Default impl (Phase 2) does the rest of the heavy lifting.
    RequestCtx {
        req_id: "r".to_string(),
        client_ip: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
        method: "POST".to_string(),
        host: "bank.example.com".to_string(),
        port: 443,
        path: path.to_string(),
        is_tls: true,
        cookies,
        ..Default::default()
    }
}
```

Run: `cargo test -p waf-engine --test tx_velocity_on_response_e2e`. **Expected: passes** if phases 1-4 are landed correctly. This phase's deliverable is the lock-in test plus a regression smoke through the integration boundary.

### Step 5.2 — gateway wiring changes

Three concrete code changes in `crates/gateway/src/proxy.rs` (and possibly `context.rs`):

1. **Add `upstream_response_observed: bool`** to `GatewayCtx`. Grep `grep -n "struct GatewayCtx\|pub struct GatewayCtx" crates/gateway/src/` to find the definition; add the field defaulting to `false`.

2. **Implement `upstream_response_filter`** on the `ProxyHttp` impl (this hook fires only when an origin response arrives, not on synthesized errors):
   ```rust
   async fn upstream_response_filter(
       &self,
       _session: &mut Session,
       _upstream_response: &mut pingora_http::ResponseHeader,
       ctx: &mut GatewayCtx,
   ) -> pingora_core::Result<()> {
       ctx.upstream_response_observed = true;
       Ok(())
   }
   ```

3. **Update `logging()` at `proxy.rs:1179`** to call the new engine entry:
   ```rust
   async fn logging(&self, session: &mut Session, _error: Option<&pingora_core::Error>, ctx: &mut GatewayCtx) {
       if let Some(req_ctx) = &ctx.request_ctx {
           let status = session
               .response_written()
               .map_or(0, |h| h.status.as_u16());
           self.engine.on_request_complete(
               req_ctx,
               status,
               ctx.upstream_response_observed,
           );
           debug!(
               tier = ?req_ctx.tier,
               "Request completed: {} {} {} → upstream={}",
               req_ctx.method, req_ctx.host, req_ctx.path,
               ctx.upstream_addr.as_deref().unwrap_or("unknown"),
           );
       }
   }
   ```

The existing `response_filter` call to `engine.on_response` (FR-018) stays untouched.

### Step 5.3 — docs updates

In `crates/waf-engine/CLAUDE.md` `## Features` block, the FR-012 line currently says (or near-equivalent):
> tx_velocity: signal-only; classifiers consume an in-memory ring buffer

Append the new semantics:

> tx_velocity (FR-012): signal-only; dispatched from gateway `logging()` hook (not `response_filter`) so streaming + WAF-blocked + origin-down paths are handled correctly. Events carry tristate `Outcome::{Pending, Ok, Failed}`; classifiers ignore Pending. Velocity signals carry both `count` (settled attempts in window) and `ok_count` (subset that succeeded). Cookie-less requests fall back to `RequestCtx.device_fp` scoped by `peer_ip` for session identity.

In `plans/260504-1632-fr-012-transaction-velocity/plan.md`, add at the bottom under `## Follow-ups`:

```md
## Follow-ups (post-completion)

- [Completed 2026-05-30] FR-010 fingerprint plumbing + response-side `ok` enrichment closed in
  [`260530-2325-fr012-fp-plumbing-and-ok-enrichment/plan.md`](../260530-2325-fr012-fp-plumbing-and-ok-enrichment/plan.md).
```

### Step 5.4 — green-light gates

```bash
cargo fmt --all
cargo fmt --all -- --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
cargo bench -p waf-engine --bench tx_velocity_eval 2>/dev/null || true   # if bench exists
```

## Success Criteria

- [ ] `tx_velocity_request_complete_e2e.rs` — all five tests pass (3 happy-path + origin-down + waf-blocked regression).
- [ ] `crates/gateway/src/proxy.rs` has `upstream_response_filter` impl AND `logging()` calls `engine.on_request_complete`.
- [ ] `crates/waf-engine/CLAUDE.md` features section reflects new semantics (logging() dispatch, tristate Outcome, count+ok_count).
- [ ] `crates/gateway/CLAUDE.md` Features bullets mention FR-012 dispatch via `logging()`.
- [ ] FR-012 parent plan has a follow-up link back to this plan.
- [ ] `cargo fmt --all -- --check` clean.
- [ ] `cargo clippy --workspace --all-targets -- -D warnings` clean.
- [ ] `cargo test --workspace` passes.
- [ ] Both original TODOs at `crates/waf-engine/src/checks/tx_velocity/check.rs:55` and `:60` are gone:
  ```bash
  grep -n "TODO: FR-010\|response-side enrichment deferred" \
      crates/waf-engine/src/checks/tx_velocity/check.rs
  ```
  returns empty.

## Risk Assessment

| Risk | Mitigation |
|---|---|
| `cargo bench` regression on hot path | Classifier work moved OFF the request path (faster), ONTO the response path (after upstream RTT, off critical latency). Bench should improve or stay flat. |
| E2E test brittle to `flush()` timing | Same `tokio::time::sleep(10ms)` pattern as existing pipeline tests in `recorder.rs:415-417`. Proven in CI. |
| Doc drift between plan and code | Single source of truth for the new semantics is `crates/waf-engine/src/checks/tx_velocity/*.rs`. Plan is a redirect. |

## Notes

Plan is fully closed when this phase passes. Both original TODO sites in `check.rs` are deleted, fingerprint-only sessions are tracked, classifiers see honest `ok`, and the risk pipeline receives a richer signal.

## Whole-Plan Consistency Sweep (mandatory)

Before recommending `/ck:cook`:

- Re-read `plan.md` + every `phase-*.md` in this plan dir.
- Confirm: `FpKey` location, `record()` signature, `set_outcome` semantics, and `Signal::WithdrawalVelocity` shape are described identically across all five phases.
- Confirm: no stale reference to `record(&key, role, true)` survives anywhere in the plan text.
- Confirm: the "Decisions (locked)" block in plan.md matches what each phase actually implements.
