# Scout: Gateway State for FR-039 (Circuit Breaker)

**Date:** 2026-05-12  
**Pingora Version:** 0.8 (workspace, crates/gateway/Cargo.toml:22–30)

---

## 1. Upstream Connection Flow

**File:** `/Users/admin/lab/mini-waf/crates/gateway/src/proxy.rs:200–246`

`upstream_peer()` is the sole entry point for backend connections:
- **Line 225:** `upstream_addr = format!("{}:{}", host_config.remote_host, host_config.remote_port)`
- **Line 242–246:** Constructs `HttpPeer::new(&upstream_addr, use_tls, ...)`

**No timeout injection seam currently exists** — Pingora's `HttpPeer` is instantiated with default Pingora connect timeouts. To inject `connect_timeout` config:
- Must pass timeout to `HttpPeer::new()` or configure per-backend pooling (depends on Pingora 0.8 API).
- **Integration point:** After line 241, before `HttpPeer::new()` — check if Pingora 0.8's `HttpPeer` builder supports `.connect_timeout()`.

---

## 2. ProxyHttp Trait Implementation

**File:** `/Users/admin/lab/mini-waf/crates/gateway/src/proxy.rs:193–539`

**Implemented methods:**
- `new_ctx()` — line 196 (default)
- `upstream_peer()` — line 200 (backend selection, **no timeout override**)
- `request_filter()` — line 249 (WAF + access-list gate)
- `upstream_request_filter()` — line 400 (filter chain apply)
- `response_filter()` — line 429 (response body masking setup)
- `response_body_filter()` — line 472 (streaming mask apply)
- `fail_to_proxy()` — line 498 (**error page rendering**)
- `logging()` — line 527

**NOT implemented:** `fail_to_connect`, `error_while_proxy`, `peer_picked_filter` — these remain Pingora defaults.

---

## 3. ErrorPageFactory & 503 Rendering

**File:** `/Users/admin/lab/mini-waf/crates/gateway/src/proxy.rs`

503 is rendered in **three places:**

1. **Line 307–312:** `request_filter()` — fail-closed (missing context)
   ```rust
   ErrorPageFactory::render(503, accept.as_deref())?
   ```

2. **Line 350:** `request_filter()` — access-list gate block
   ```rust
   ErrorPageFactory::render(status, accept.as_deref())?
   ```

3. **Line 498–520:** `fail_to_proxy()` — upstream errors mapped via `error_to_status()` (line 140–153)
   - **Line 146:** `ErrorSource::Upstream => 502` (not 503 — needs override logic)

**Current behavior:** Upstream connect failures → 502, not 503. Circuit breaker logic must intercept before `error_to_status()` is called or override its decision for specific error kinds.

---

## 4. FailMode / TierPolicy Plumbing

**Data flow:** Host header → `HostRouter::resolve()` → `HostConfig` → `RequestCtxBuilder::build()` → `TierPolicyRegistry::classify()` → `RequestCtx.tier_policy`

**File chain:**
- **waf-common/src/tier.rs:73** — `TierPolicy.fail_mode: FailMode` (enum: Close | Open)
- **waf-common/src/types.rs:48** — `RequestCtx.tier_policy: Arc<TierPolicy>`
- **crates/gateway/src/ctx_builder/request_ctx_builder.rs:112** — Classification snapshot at build time
- **crates/gateway/src/proxy.rs:303–316** — `request_ctx.tier_policy` available in `request_filter()`

**No current proxy decision keyed on `fail_mode`** — tier policy is captured but not consulted for upstream failures. **Integration seam:** After `error_to_status()` in `fail_to_proxy()`, check `ctx.request_ctx.tier_policy.fail_mode` to decide 503 vs circuit-breaker action.

---

## 5. degrade::resolve() Integration

**File:** `/Users/admin/lab/mini-waf/crates/waf-engine/src/checks/ddos/degrade.rs:1–60`

`degrade::resolve(tier, fail_mode, error_kind) → DegradeAction` is **not wired into proxy.rs today**. It implements FR-005 Phase 6 matrix (line 42–49):
- **Critical/High:** Block 503 (all error kinds)
- **Medium:** AllowAndWarn (all error kinds)
- **CatchAll:** Allow (all error kinds)
- **Override:** If `fail_mode == Close`, always Block 503

**Currently NOT used by gateway.** To integrate:
1. Import `degrade::{resolve, ErrorKind, DegradeAction}` in proxy.rs
2. In `fail_to_proxy()` after `error_to_status()`, call `degrade::resolve(ctx.request_ctx.tier, ctx.request_ctx.tier_policy.fail_mode, ErrorKind::BackendOverload)`
3. Match `DegradeAction` to decide whether to render 503 or allow

---

## 6. Existing Timeout Config

**Search results across workspace:**
- **waf-common/src/config.rs:141–142** — `AppConfig.appsec_timeout_ms: u64` (Crowdsec timeout, not upstream)
- **gateway/src/cache/valkey_store.rs:99** — `cfg.connect_timeout_ms` → Valkey connection timeout (not upstream)
- **waf-engine/src/rules/manager.rs:433** — `connect_timeout(Duration::from_secs(10))` (HTTP client for rule fetch)

**HostConfig (waf-common/src/types.rs:196–241):** NO upstream timeout fields. Must add:
- `upstream_connect_timeout_ms: u64`
- `upstream_read_timeout_ms: u64`
- `upstream_total_timeout_ms: u64` (optional, for overall transaction)

---

## 7. Test Infrastructure

**Location:** `/Users/admin/lab/mini-waf/crates/gateway/tests/`

19 integration test files (cache, ctx_builder, lb, proxy, tier, ssl, etc.). Key file for backend testing:
- **lb_strategies.rs** — Load balancer unit tests (health check via `tcp_health_check()` at line 261)
- **tier_e2e.rs** — Full tier classification e2e (14KB)
- **proxy_waf_response_writer.rs** — WAF response rendering (13KB)

**E2E harness:** `/Users/admin/lab/mini-waf/tests/e2e/` + Docker Compose (`docker-compose.e2e.yml`). Mock backends set up via shell scripts (`run-gateway.sh`, `run-rules-engine.sh`).

**No existing circuit-breaker or timeout-injection tests.** Will need to:
- Mock an unresponsive backend (slow connect, hang after connect)
- Assert 503 vs 502 based on tier/fail_mode
- Verify `Retry-After` header presence

---

## Summary for Planner

| Aspect | File | Current State | Integration Seam |
|--------|------|---------------|------------------|
| **Backend connect** | proxy.rs:200 | HttpPeer::new() default | Check Pingora 0.8 API for timeout override |
| **Error mapping** | proxy.rs:140–153 | Upstream → 502 always | Add tier/fail_mode check after error_to_status() |
| **FailMode check** | types.rs:48 | Available in RequestCtx | Access via ctx.request_ctx.tier_policy.fail_mode |
| **degrade::resolve()** | degrade.rs:55 | Pure, unused | Call in fail_to_proxy() on BackendOverload |
| **Timeout config** | types.rs:196–241 | Missing | Add upstream_*_timeout_ms fields to HostConfig |
| **Test mocks** | tests/e2e/ | Exists (lb, tier) | Extend with backend unresponsive scenario |

---

## Unresolved Questions

1. **Pingora 0.8 connect timeout API:** Does `HttpPeer` builder expose `.connect_timeout()`, or must we wrap it in a pooled connector?
2. **Distinguish timeout vs hard down:** Error kind classification — how to differentiate TCP timeout from immediate ECONNREFUSED?
3. **Circuit breaker state:** FR-039 implies stateful breaker (open/half-open/closed). `degrade::resolve()` is stateless; does gateway need to track backend health separately?

