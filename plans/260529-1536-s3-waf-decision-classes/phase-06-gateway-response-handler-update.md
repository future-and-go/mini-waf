---
phase: 6
title: "Gateway Response Handler Update"
status: done
priority: P1
effort: "2h"
dependencies: [2, 3]
---

# Phase 6: Gateway Response Handler Update

## Overview

Update the gateway's response handler (`write_waf_decision`, `write_waf_body_decision`, HTTP/3 handler) to properly handle the 3 new `WafAction` variants and respect `InteropMode::LogOnly` on `WafDecision`. Currently the gateway checks `is_allowed()` then matches on action variants — the new mode-aware `is_enforcement_allowed()` changes what "allowed" means.

## Context Links

- `write_waf_decision()`: `crates/gateway/src/proxy_waf_response.rs:30–84`
- `write_waf_body_decision()`: `crates/gateway/src/proxy_waf_response.rs:190–230`
- HTTP/3 handler: `crates/gateway/src/http3.rs:240–280`
- Proxy handoff: `crates/gateway/src/proxy.rs:681–692`
- Upstream error handling: `crates/gateway/src/proxy.rs:264–299` (`error_to_status`, `is_transport_unresponsive`)
- `fail_to_proxy()`: `crates/gateway/src/proxy.rs:1039–1066`

## Requirements

**Functional:**
- `write_waf_decision()` handles `RateLimit { status, body }` — writes HTTP response with given status (429)
- `write_waf_decision()` handles `Timeout { status }` — writes HTTP response with status (504), default body
- `write_waf_decision()` handles `CircuitBreaker { status, body }` — writes HTTP response with status (503), body
- Mode-aware: when `decision.mode == LogOnly`, `is_enforcement_allowed()` returns true → response NOT written, request passes to upstream
- `write_waf_body_decision()` has identical new match arms
- HTTP/3 handler has identical new match arms

**Non-functional:**
- No change to `write_waf_decision` function signature
- Existing test coverage for Allow/Block/Redirect/Challenge unchanged
- `Timeout` and `CircuitBreaker` actions are produced by upstream failure paths (Phase 6 adds the match arms; upstream wiring is out of scope for this plan — belongs to §8 binary contract work)

## Architecture

### Mode-Aware Response Flow

```
Engine returns WafDecision
  ├─ mode=Enforce + action=Block → write block response (existing)
  ├─ mode=Enforce + action=RateLimit → write 429 response (NEW)
  ├─ mode=Enforce + action=Timeout → write 504 response (NEW)
  ├─ mode=Enforce + action=CircuitBreaker → write 503 response (NEW)
  ├─ mode=LogOnly + action=Block → skip enforcement, pass to upstream (FIXED)
  ├─ mode=LogOnly + action=RateLimit → skip enforcement, pass to upstream (FIXED)
  └─ action=Allow → pass to upstream (existing)
```

The existing `if !decision.is_allowed()` guard already handles this correctly after Phase 3:
- `is_allowed()` → `is_enforcement_allowed()` → returns `true` when `mode == LogOnly`
- So log_only decisions skip the entire block/response-writing branch

### New Match Arms

```rust
WafAction::RateLimit { status, body } => {
    let status_code = *status;
    let body_str = body.clone().unwrap_or_else(|| "Rate Limit Exceeded".to_string());
    let response = pingora_http::ResponseHeader::build(status_code, None)?;
    session.write_response_header(Box::new(response), false).await?;
    session.write_response_body(Some(Bytes::from(body_str)), true).await?;
    return Ok(true);
}
WafAction::Timeout { status } => {
    let status_code = *status;
    let response = pingora_http::ResponseHeader::build(status_code, None)?;
    session.write_response_header(Box::new(response), false).await?;
    session.write_response_body(Some(Bytes::from("Gateway Timeout")), true).await?;
    return Ok(true);
}
WafAction::CircuitBreaker { status, body } => {
    let status_code = *status;
    let body_str = body.clone().unwrap_or_else(|| "Service Temporarily Unavailable".to_string());
    let response = pingora_http::ResponseHeader::build(status_code, None)?;
    session.write_response_header(Box::new(response), false).await?;
    session.write_response_body(Some(Bytes::from(body_str)), true).await?;
    return Ok(true);
}
```

### Logging in `write_waf_decision`

The existing `warn!()` log at line 53 only fires for `Block`. Extend logging to cover new variants. Use `decision.action.as_contract_str()` for the action field:

```rust
warn!(
    action = %decision.action.as_contract_str(),
    rule_id = %rule_id,
    // ... rest unchanged
    "WAF denied request",
);
```

### Upstream Error Wiring (OUT OF SCOPE)

`fail_to_proxy()` (proxy.rs:1039) currently returns a generic error page for upstream failures. Wiring it to produce `WafDecision::timeout(504)` or `WafDecision::circuit_breaker(503)` requires changes to the Pingora proxy lifecycle that belong to the §8 binary/startup contract work. This phase only adds the match arms so the gateway CAN handle these actions when produced.

## Related Code Files

**Modify:**
- `crates/gateway/src/proxy_waf_response.rs` — `write_waf_decision()` + `write_waf_body_decision()`
- `crates/gateway/src/http3.rs` — HTTP/3 handler match block
- `crates/gateway/tests/proxy_waf_response_writer.rs` — add tests for new variants

**No change:**
- `crates/gateway/src/proxy.rs` — `fail_to_proxy()` stays as-is (out of scope)

## Implementation Steps

### 1. Add match arms in `write_waf_decision()` (proxy_waf_response.rs:39)

Inside the `if !decision.is_allowed()` block, after the existing `Challenge` arm and before the `_ => {}` catch-all:

Add `RateLimit`, `Timeout`, `CircuitBreaker` match arms as shown in Architecture section.

### 2. Update logging in `write_waf_decision()`

Change the `warn!()` inside the `Block` arm to also fire for new variants. Two approaches:
- **Option A**: Duplicate the `warn!()` in each arm (verbose but explicit)
- **Option B**: Extract logging before the match, fire for any non-allow action

**Recommended: Option B** — move the logging before the match block:

```rust
if !decision.is_allowed() {
    blocked_counter.fetch_add(1, Ordering::Relaxed);

    // Log for all non-allow enforced actions
    if let Some(result) = &decision.result {
        warn!(
            action = %decision.action.as_contract_str(),
            rule_id = %result.rule_id.clone().unwrap_or_default(),
            rule_name = %result.rule_name,
            phase = %result.phase,
            detail = %result.detail,
            method = %request_ctx.method,
            path = %request_ctx.path,
            host = %request_ctx.host,
            ua = %request_ctx.headers.get("user-agent").cloned().unwrap_or_default(),
            "WAF denied request",
        );
    }

    match &decision.action {
        WafAction::Block { status, body } => { /* write response */ }
        WafAction::RateLimit { status, body } => { /* write response */ }
        WafAction::Timeout { status } => { /* write response */ }
        WafAction::CircuitBreaker { status, body } => { /* write response */ }
        WafAction::Redirect { url } => { /* write redirect */ }
        WafAction::Challenge => { /* handle challenge */ }
        _ => {}
    }
}
```

### 3. Add match arms in `write_waf_body_decision()` (proxy_waf_response.rs:198)

Same 3 new arms inside the `if !decision.is_allowed()` block. **RT-09 CRITICAL:** Each new arm MUST return `Err(pingora_core::Error::explain(...))` to halt body streaming — matching the existing `Block` arm at line 212. Returning `Ok(())` instead of `Err` would allow the body stream to continue after a WAF denial, which is a security bypass.

### 4. Add match arms in HTTP/3 handler (http3.rs:244)

Same 3 new arms. HTTP/3 handler uses `http::StatusCode::from_u16(*status)` instead of `pingora_http::ResponseHeader::build`.

### 5. Remove the `_ => {}` catch-all from all match blocks

After adding explicit arms for all 8 variants, the catch-all `_ => {}` should be replaced with explicit `#[allow(deprecated)] WafAction::LogOnly => {}` so the compiler catches any future additions.

### 6. Add gateway tests in `proxy_waf_response_writer.rs`

Tests follow the existing pattern (`write_waf_decision_block_writes_status_and_body`):

```rust
#[tokio::test]
async fn write_waf_decision_rate_limit_writes_429() {
    let decision = WafDecision {
        action: WafAction::RateLimit { status: 429, body: Some("Too many requests".into()) },
        result: None,
        risk_score: 0,
        mode: InteropMode::Enforce,
        rule_id: None,
    };
    // Assert: returns Ok(true), status 429 written
}

#[tokio::test]
async fn write_waf_decision_timeout_writes_504() {
    let decision = WafDecision::timeout(504);
    // Assert: returns Ok(true), status 504 written
}

#[tokio::test]
async fn write_waf_decision_circuit_breaker_writes_503() {
    let decision = WafDecision::circuit_breaker(503, Some("Backend down".into()));
    // Assert: returns Ok(true), status 503 written
}

#[tokio::test]
async fn write_waf_decision_log_only_block_returns_false() {
    let r = DetectionResult { ... };
    let decision = WafDecision::block(403, None, r).with_mode(InteropMode::LogOnly);
    // Assert: returns Ok(false) — enforcement skipped
}
```

### 7. Validate

Run `cargo check --workspace` — zero errors.
Run `cargo test -p gateway` — all tests pass.

## Success Criteria

- [x] `write_waf_decision()` handles RateLimit (429), Timeout (504), CircuitBreaker (503)
- [x] `write_waf_body_decision()` handles same 3 variants
- [x] HTTP/3 handler handles same 3 variants
- [x] Mode-aware: log_only decisions skip enforcement (return `Ok(false)`)
- [x] Logging uses `as_contract_str()` for action field
- [x] No `_ => {}` catch-all — all variants explicitly matched
- [x] 4 new gateway tests pass (rate_limit 429, timeout 504, circuit_breaker 503, log_only_block bypass)
- [x] `cargo test -p gateway` — zero failures (345 lib + 17 writer suite)

## Risk Assessment

| Risk | Impact | Mitigation |
|------|--------|------------|
| Timeout/CircuitBreaker never produced (no upstream wiring yet) | Dead code temporarily | Match arms ready for §8 binary contract phase to wire upstream errors |
| Log_only mode causes request to pass despite Block action | Correct per contract | `is_enforcement_allowed()` returns true → `if !decision.is_allowed()` skips block |
| HTTP/3 handler diverges from HTTP/1+2 handler | Inconsistent behavior | Same match arms in both; could extract shared helper in follow-up |
