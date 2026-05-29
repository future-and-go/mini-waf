---
phase: 2
title: "Response Observability Headers (§5)"
status: pending
priority: P1
effort: "1d"
dependencies: [1]
---

# Phase 2: Response Observability Headers (§5)

## Overview

Inject all 6 mandatory `X-WAF-*` response headers on every HTTP response. Uses the established `ResponseFilter` trait pattern — one new filter file, registered into the existing `ResponseFilterChain`.

## Context Links

- Contract §5: `analysis/docs/EN_waf_interop_contract_v2.3.md` lines 371–410
- Gap report §5: `plans/reports/contract-gap-analysis-260527-1133-waf-interop-v23-report.md` lines 67–83
- ResponseFilter trait: `crates/gateway/src/pipeline/mod.rs:55–61`
- ResponseFilterChain: `crates/gateway/src/pipeline/response_filter_chain.rs`
- FilterCtx struct: `crates/gateway/src/pipeline/mod.rs:24–33`
- proxy response_filter: `crates/gateway/src/proxy.rs` (response_filter method)
- Existing filters: `crates/gateway/src/filters/response_*.rs`

## Requirements

**Functional (contract §5.1):**

| Header | Value | Source |
|--------|-------|--------|
| `X-WAF-Request-Id` | UUID v4 string | `RequestCtx.req_id` |
| `X-WAF-Risk-Score` | integer 0–100 | `WafDecision.risk_score` (Phase 1) |
| `X-WAF-Action` | `allow\|block\|challenge\|rate_limit\|timeout\|circuit_breaker` | `WafDecision.action` mapped to lowercase string |
| `X-WAF-Rule-Id` | alphanumeric+hyphens or `none` | `WafDecision.rule_id` or `"none"` |
| `X-WAF-Cache` | `HIT\|MISS\|BYPASS` | Cache lookup result from response_cache_integration |
| `X-WAF-Mode` | `enforce\|log_only` | `WafDecision.mode` (Phase 1) |

**Consistency rules (contract §5.3):**
- Headers MUST appear on ALL responses — allow, block, challenge, rate_limit, timeout, circuit_breaker
- `X-WAF-Request-Id` MUST match audit log `request_id`
- `X-WAF-Action` MUST match actual behavior when `enforce`; MUST be intended action when `log_only`
- `X-WAF-Cache` = `BYPASS` for non-cacheable routes

**Non-functional:**
- Zero allocation when possible: use `&str` for static header values
- Filter must be first in ResponseFilterChain (before header stripping filters)
- Existing response filters must not strip `X-WAF-*` headers

## Red-Team Fixes Applied

| Finding | Fix |
|---------|-----|
| RT-02: WafDecision discarded after `request_filter`; local clone diverges from `ctx.request_ctx` | Populate interop fields on `ctx.request_ctx` (GatewayCtx) DIRECTLY, not on a local clone |
| RT-03: WAF-blocked responses bypass `ResponseFilterChain` entirely | **Dual injection**: inject headers in `write_waf_decision` for blocked responses + `ResponseFilter` for proxied responses |
| RT-05: Default blocklist includes `x-waf-version` | Remove `x-waf-version` from default blocklist; it's a legacy header |
| RT-12: HTTP/3 path builds independent responses | Add header injection in `http3.rs` WAF response builder |

## Architecture

### Data Flow Problem & Solution

The `ResponseFilter` trait receives `FilterCtx` which has `RequestCtx` + `HostConfig` + `peer_ip`. But it does NOT have `WafDecision` or cache status.

**Key insight from red-team (RT-02):** The `request_ctx` used for WAF evaluation is a **local variable** in `request_filter`. Changes to it don't propagate back to `ctx.request_ctx` (stored on `GatewayCtx`). We must write interop fields to `ctx.request_ctx` directly.

**Key insight from red-team (RT-03):** When WAF blocks a request, `write_waf_decision` builds the HTTP response directly and returns `Ok(true)`. Pingora never calls `response_filter`. Headers MUST be injected in both paths.

### Two-Path Header Injection Strategy

```
Request arrives
  ↓
request_filter() → engine.inspect() → WafDecision
  ↓
  ├── BLOCKED (write_waf_decision returns true)
  │   → inject_interop_headers() directly on the response in write_waf_decision
  │   → X-WAF-Cache: BYPASS (no upstream)
  │   → return Ok(true)
  │
  └── ALLOWED (proxy to upstream)
      → populate interop fields on ctx.request_ctx (GatewayCtx)
      → response_filter() → ResponseFilterChain
      → WafObservabilityHeaderFilter reads ctx.request_ctx interop fields
      → inject all 6 headers on upstream response
```

### Shared Header Injection Function

```rust
// crates/gateway/src/filters/response_waf_observability_header_filter.rs

/// Inject all 6 X-WAF-* headers on a ResponseHeader.
/// Used by BOTH the ResponseFilter (proxied responses) and
/// write_waf_decision (WAF-generated blocked responses).
pub fn inject_interop_headers(
    resp: &mut ResponseHeader,
    req_id: &str,
    risk_score: u16,
    action: &str,
    rule_id: Option<&str>,
    cache_status: &str,
    mode: &str,
) -> pingora_core::Result<()> {
    resp.insert_header("X-WAF-Request-Id", req_id)?;
    resp.insert_header("X-WAF-Risk-Score", &risk_score.to_string())?;
    resp.insert_header("X-WAF-Action", action)?;
    resp.insert_header("X-WAF-Rule-Id", rule_id.unwrap_or("none"))?;
    resp.insert_header("X-WAF-Cache", cache_status)?;
    resp.insert_header("X-WAF-Mode", mode)?;
    Ok(())
}
```

Both `WafObservabilityHeaderFilter::apply()` and `write_waf_decision()` call this function. DRY — single source of truth for header names and defaults.

### Interop Fields on RequestCtx

```rust
// In waf-common/src/types.rs — add to RequestCtx
pub struct RequestCtx {
    // ... existing fields ...
    
    /// Interop contract observability — populated after WAF decision
    #[serde(skip)]
    pub interop_action: Option<String>,
    #[serde(skip)]
    pub interop_risk_score: u16,
    #[serde(skip)]
    pub interop_rule_id: Option<String>,
    #[serde(skip)]
    pub interop_mode: InteropMode,
    #[serde(skip)]
    pub interop_cache_status: Option<String>,
}
```

### Propagation Fix (RT-02)

In `proxy.rs::request_filter()`, after `engine.inspect()` returns, populate interop fields on `ctx.request_ctx` (the GatewayCtx copy) — NOT on the local `request_ctx` clone:

```rust
let decision = self.engine.inspect(&mut request_ctx).await;

// Propagate interop fields to GatewayCtx so response_filter can see them
if let Some(ref mut ctx_ref) = ctx.request_ctx {
    ctx_ref.interop_action = Some(decision.action.as_contract_str().to_string());
    ctx_ref.interop_risk_score = decision.risk_score;
    ctx_ref.interop_rule_id = decision.rule_id.clone();
    ctx_ref.interop_mode = decision.mode;
}
```

### Header Stripping Protection (RT-05)

The default `header_blocklist` includes `x-waf-version`. Fix: remove it from the default list. It's a legacy internal header, not an interop contract header. The blocklist uses exact-name matching (not prefix), so other `X-WAF-*` headers are safe unless an operator explicitly adds them.

```rust
// BEFORE:
fn default_header_blocklist() -> Vec<String> {
    vec!["x-powered-by-waf".to_string(), "x-waf-version".to_string()]
}
// AFTER:
fn default_header_blocklist() -> Vec<String> {
    vec!["x-powered-by-waf".to_string()]
}
```

### Cache Status Propagation

Cache HIT/MISS/BYPASS is determined in `response_cache_integration.rs`. After cache lookup, set `ctx.request_ctx.interop_cache_status`:
- Cache hit → `"HIT"`
- Cache miss (went to upstream) → `"MISS"`  
- Cache bypass (non-cacheable, auth, dynamic) → `"BYPASS"`
- WAF-blocked (no cache lookup) → `"BYPASS"` (set in write_waf_decision)

### HTTP/3 Path (RT-12)

The `http3.rs` handler builds responses independently. After the WAF decision in the H3 code path, call `inject_interop_headers()` on the H3 response builder. This is a parallel injection point — same function, different response type.

### Access-Bypass Requests (User Decision)

When `ctx.access_bypass=true`, the engine is skipped. For contract compliance, inject minimal headers:
- `X-WAF-Action: allow`
- `X-WAF-Mode: enforce`
- `X-WAF-Cache: BYPASS`
- `X-WAF-Risk-Score: 0`
- `X-WAF-Rule-Id: none`
- `X-WAF-Request-Id: <req_id>`

Also write a minimal JSONL audit entry with `action: "allow"`. This ensures the benchmarker sees consistent observability on every response.

## Related Code Files

**Create:**
- `crates/gateway/src/filters/response_waf_observability_header_filter.rs` — new ResponseFilter impl

**Modify:**
- `crates/waf-common/src/types.rs` — add interop fields to RequestCtx
- `crates/gateway/src/filters/mod.rs` — register new filter module
- `crates/gateway/src/proxy.rs` — populate interop fields on RequestCtx after WAF decision + cache lookup; register filter in chain
- `crates/gateway/src/response_cache_integration.rs` — set cache status on ctx
- `crates/gateway/src/filters/response_header_blocklist_filter.rs` — exclude `X-WAF-*` from stripping

## Implementation Steps

### TDD: Write Tests First

1. **Unit test for `WafObservabilityHeaderFilter`** in the new filter file:
   - Given a FilterCtx with populated interop fields → all 6 headers present on response
   - Given a FilterCtx with default/None interop fields → headers use defaults ("allow", "none", "BYPASS", 0)
   - Verify exact header names and value formats match contract

2. **Unit test for header protection**:
   - Given a blocklist filter with `X-*` pattern → `X-WAF-Request-Id` is NOT stripped

3. **Integration test** in `crates/gateway/tests/`:
   - Build a mock pipeline with WAF decision → verify response headers end-to-end
   - Test for allow, block, challenge, rate_limit decisions — each produces correct `X-WAF-Action`

### Implement

4. **Add interop fields to `RequestCtx`** in `crates/waf-common/src/types.rs`:
   - `interop_action`, `interop_risk_score`, `interop_rule_id`, `interop_mode`, `interop_cache_status`
   - All with `#[serde(skip)]` (not persisted, runtime-only)
   - Default values: action=None, risk_score=0, rule_id=None, mode=Enforce, cache_status=None

5. **Add `as_header_str()` to `InteropMode`**:
   - `Enforce` → `"enforce"`, `LogOnly` → `"log_only"`

6. **Add `as_contract_str()` to `WafAction`**:
   - Maps each variant to the lowercase contract string: `"allow"`, `"block"`, `"challenge"`, `"rate_limit"`, `"timeout"`, `"circuit_breaker"`
   - `Redirect` → `"allow"` (not a contract action, treated as allow)
   - `LogOnly` (deprecated) → use mode field instead

7. **Create `response_waf_observability_header_filter.rs`** with TWO exports:
   - `inject_interop_headers()` — standalone fn for blocked responses (RT-03)
   - `WafObservabilityHeaderFilter` — ResponseFilter impl for proxied responses
   - Both call the same header injection logic (DRY)

8. **Populate interop fields on `ctx.request_ctx` (GatewayCtx)** in `proxy.rs` (RT-02 fix):
   - After `engine.inspect()`, write to `ctx.request_ctx` directly — NOT the local clone:
   ```rust
   if let Some(ref mut ctx_ref) = ctx.request_ctx {
       ctx_ref.interop_action = Some(decision.action.as_contract_str().to_string());
       ctx_ref.interop_risk_score = decision.risk_score;
       ctx_ref.interop_rule_id = decision.rule_id.clone();
       ctx_ref.interop_mode = decision.mode;
   }
   ```

9. **Inject headers on blocked responses** in `proxy_waf_response.rs` (RT-03 fix):
   - In `write_waf_decision`, after building the ResponseHeader for Block/RateLimit/Timeout/CircuitBreaker:
   ```rust
   inject_interop_headers(&mut response, &request_ctx.req_id, decision.risk_score,
       &decision.action.as_contract_str(), decision.rule_id.as_deref(), "BYPASS",
       decision.mode.as_header_str())?;
   ```
   - Same for `handle_challenge` — inject headers on the challenge response

10. **Inject headers on HTTP/3 blocked responses** in `http3.rs` (RT-12):
    - After WAF decision in the H3 code path, inject headers on the H3 response

11. **Populate cache status** in `response_cache_integration.rs`:
    - After cache lookup result is known, set `ctx.request_ctx.interop_cache_status`

12. **Register filter first** in ResponseFilterChain setup (before header blocklist):
    ```rust
    chain.register(Arc::new(WafObservabilityHeaderFilter));
    // ... existing filters
    ```

13. **Remove `x-waf-version` from default blocklist** in `types.rs` (RT-05):
    - Remove legacy entry; don't add prefix guard (filter uses exact-name match)

### Validate

12. `cargo check --workspace`
13. `cargo test --workspace` — all existing + new tests pass
14. `cargo clippy --workspace -- -D warnings`
15. Manual verification: blocked request returns all 6 headers; allowed request returns all 6 headers

## Success Criteria

- [ ] All 6 `X-WAF-*` headers present on blocked responses
- [ ] All 6 `X-WAF-*` headers present on allowed (proxied) responses
- [ ] `X-WAF-Action` value matches contract enum exactly (lowercase)
- [ ] `X-WAF-Cache` correctly reports HIT/MISS/BYPASS
- [ ] `X-WAF-Mode` reports `enforce` or `log_only` accurately
- [ ] Existing response header blocklist does NOT strip `X-WAF-*`
- [ ] `cargo check --workspace` passes
- [ ] All tests pass

## Risk Assessment

| Risk | Impact | Mitigation |
|------|--------|------------|
| Adding fields to RequestCtx bloats per-request allocation | Low | Fields are small (String + u16); Option<String> is 24 bytes |
| Filter ordering: headers set then stripped by downstream filter | High | Register first + add exclusion rule in blocklist filter |
| Cache status not available when response is WAF-generated (block/challenge) | Medium | For WAF-generated responses, set `BYPASS` — no upstream cache involved |
| RequestCtx is Clone — interop fields must survive clone | Low | String fields are Clone-compatible by default |
