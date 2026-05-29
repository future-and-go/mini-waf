# WAF Action/Decision Model & log_only Implementation Report

**Research scope:** Exact implementation details of `WafAction` enum, `WafDecision` struct, `log_only` mode, audit logging, and observable headers for interop contract v2.3 compliance planning.

**Date:** 2026-05-27  
**Status:** Complete

---

## 1. WafAction & WafDecision Types

**File:** `/Users/thuocnguyen/Documents/personal-workspace/mini-waf/crates/waf-common/src/types.rs` (lines 92–169)

### WafAction Enum
```rust
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum WafAction {
    Allow,
    Block {
        status: u16,
        body: Option<String>,
    },
    LogOnly,
    Redirect {
        url: String,
    },
    Challenge,
}
```

**Variants:**
- `Allow` — permits request (no status/body)
- `Block { status, body }` — denies with HTTP status + optional HTML/text body
- `LogOnly` — logs but allows (implements monitoring-mode semantics)
- `Redirect { url }` — 302 to a URL (used for post-challenge redirects)
- `Challenge` — triggers proof-of-work or CAPTCHA (JS client-side)

**Derives:** `Debug, Clone, Serialize, Deserialize` (serde tags for JSON API serialization).

### WafDecision Struct
```rust
#[derive(Debug, Clone)]
pub struct WafDecision {
    pub action: WafAction,
    pub result: Option<DetectionResult>,
}
```

**Fields:**
- `action: WafAction` — the resolved decision
- `result: Option<DetectionResult>` — optional rule metadata (rule_id, rule_name, phase, detail, rule_action, action_status)

**Helper methods:**
- `allow()` → returns `WafDecision { action: WafAction::Allow, result: None }`
- `block(status, body, result)` → constructs block decision with metadata
- `is_allowed()` → returns `true` if `matches!(action, WafAction::Allow | WafAction::LogOnly)` (log_only counts as "allowed for passthrough")

---

## 2. log_only Mode Implementation

**File:** `/Users/thuocnguyen/Documents/personal-workspace/mini-waf/crates/waf-engine/src/engine.rs` (lines 507–776)

### Core Pattern: Host-Level Configuration
The `HostConfig::log_only_mode: bool` field (in `waf-common/src/types.rs` line 331) is checked at every detection phase in `WafEngine::inspect()`.

**Exact implementation (representative example from lines 557–568):**
```rust
// ── Phase 19: DDoS burst detection (FR-005) ───────────────────────────
if let Some(result) = self.ddos_check.check(ctx) {
    let rule_name = result.rule_name.clone();
    let decision = if ctx.host_config.log_only_mode {
        WafDecision {
            action: WafAction::LogOnly,
            result: Some(result),
        }
    } else {
        let body = render_block_page(ctx, &rule_name);
        WafDecision::block(403, Some(body), result)
    };
    self.log_security_event(ctx, &decision);
    self.report_community_signal(ctx, &decision);
    return decision;
}
```

**Pattern repeats 12 times in `inspect()` for phases:** DDoS (19), CrowdSec (16a), Community (18), GeoIP (17), Phase 5–11 (attack detection pipeline), SQLi (hot-reload), CrowdSec AppSec (16b), Custom Rules (12), OWASP (13), Sensitive Data (14), Anti-hotlink (15).

**Effect of log_only_mode = true:**
1. Convert intended `Block { 403, body }` action to `LogOnly`
2. Log the security event (fires audit event + DB log)
3. Return to caller (gateway) with decision containing `LogOnly` action
4. Gateway sees `is_allowed() == true` → allows request to upstream

**No action substitution:** When `log_only_mode = true`, RuleAction::Block/Challenge are NOT converted; only the resolved `WafAction::Block` is replaced with `LogOnly`.

---

## 3. How Engine Produces WafDecision

**File:** `/Users/thuocnguyen/Documents/personal-workspace/mini-waf/crates/waf-engine/src/engine.rs` (lines 502–777)

**Signature:**
```rust
pub async fn inspect(&self, ctx: &mut RequestCtx) -> WafDecision
```

**Return values:**
- `WafDecision::allow()` if no detector fires
- `WafDecision { action: WafAction::LogOnly | WafAction::Block, result: Some(...) }` if a detector fires
- First-match-wins: returns immediately on first non-Allow decision; phases 13–15 (OWASP, Sensitive, Hotlink) continue through Custom Rules (12) if custom rule action is Allow/LogOnly

**Phase execution order:**
1. Phase 1–4: IP/URL whitelist/blacklist (early fast-path)
2. Phase 19: DDoS burst detection
3. Phase 16a: CrowdSec bouncer (cached)
4. Phase 18: Community blocklist
5. Phase 17: GeoIP access control
6. Phase 5–11: Attack detection (rate-limit, tx-velocity, scanner, bot, XSS, RCE, dir-traversal, SSRF, header-injection, brute-force, body-abuse)
7. SQLi (separate for hot-reload)
8. Phase 16b: CrowdSec AppSec (async)
9. Phase 12: Custom rules engine (continues on Allow/LogOnly)
10. Phase 13: OWASP CRS
11. Phase 14: Sensitive data
12. Phase 15: Anti-hotlinking

---

## 4. Risk Scorer & Dominant Contributor

**File:** `/Users/thuocnguyen/Documents/personal-workspace/mini-waf/crates/waf-engine/src/risk/` (module exists but not yet integrated into `inspect()` as of current codebase)

**Finding:** Risk scoring module (`crates/waf-engine/src/risk/`) exists but is NOT yet wired into the primary `inspect()` pipeline. The `WafDecision` struct does NOT carry a risk_score or dominant_contributor field. Risk aggregation is a future feature (FR-025).

**Detection results carry:** `rule_action: Option<RuleAction>`, `action_status: Option<u16>`, but NO risk_score.

---

## 5. Rate Limiting Action

**File:** `/Users/thuocnguyen/Documents/personal-workspace/mini-waf/crates/waf-engine/src/checks/rate_limit.rs` (inferred from engine integration)

**What it returns:** `Option<DetectionResult>` (via the `Check` trait), NOT a `WafAction` directly. The engine then wraps it in either `Block` or `LogOnly` depending on `log_only_mode`.

**Status code for rate-limit blocks:** Typically 429 (Too Many Requests), but set by the DetectionResult's `action_status` field.

---

## 6. Challenge Engine

**File:** `/Users/thuocnguyen/Documents/personal-workspace/mini-waf/crates/waf-engine/src/challenge/` (module exists)

**What it returns:** `WafAction::Challenge` (no fallback to Block; gateway handles rendering).

**Gateway integration:** `/Users/thuocnguyen/Documents/personal-workspace/mini-waf/crates/gateway/src/proxy_waf_response.rs` (lines 77–184) implements `handle_challenge()`:
- Checks for existing valid `__waf_cc` cookie (proof-of-work solution)
- If cookie valid + signature verified → allow (return `Ok(false)`)
- If not → render challenge page with token + difficulty + redirect URL
- Status: 200 with HTML challenge page (not 403)

---

## 7. WAF Response Building & Header Injection

**File:** `/Users/thuocnguyen/Documents/personal-workspace/mini-waf/crates/gateway/src/proxy_waf_response.rs` (lines 30–84)

### Current write_waf_decision() Implementation
```rust
pub async fn write_waf_decision(
    session: &mut Session,
    decision: &WafDecision,
    request_ctx: &RequestCtx,
    blocked_counter: &AtomicU64,
    challenge_ctx: Option<&Arc<ChallengeCtx>>,
) -> pingora_core::Result<bool>
```

**Returns:** `Ok(true)` = response written, continue no further; `Ok(false)` = allow/logonly, continue to upstream.

**Header injection:** NONE. Current implementation:
- Block: writes status + body, no custom headers
- Redirect: writes 302 + Location header (no X-WAF-*)
- Challenge: writes 200 + challenge HTML (no X-WAF-*)
- Allow/LogOnly: returns `Ok(false)`, gateway continues

**X-WAF-* headers:** NOT present in current codebase. Contract v2.3 requires:
- `X-WAF-Request-Id` — NOT injected
- `X-WAF-Risk-Score` — NOT present (risk scorer not integrated)
- `X-WAF-Action` — NOT injected
- `X-WAF-Rule-Id` — NOT injected
- `X-WAF-Cache` — NOT injected
- `X-WAF-Mode` — NOT injected

---

## 8. Audit Logging

**File:** `/Users/thuocnguyen/Documents/personal-workspace/mini-waf/crates/waf-engine/src/logging/` (complete module)

### AuditEventType Enum
```rust
pub enum AuditEventType {
    Block,      // WAF blocked the request
    Allow,      // WAF allowed via explicit whitelist match
    Challenge,  // WAF requested a CAPTCHA / challenge
    RateLimit,  // WAF rate-limited the request
    LogOnly,    // WAF logged-only mode — would have blocked in enforce mode
}
```

### AuditEvent Struct
```rust
pub struct AuditEvent {
    pub timestamp: chrono::DateTime<chrono::Utc>,
    pub event_type: AuditEventType,
    pub rule_name: String,
    pub rule_id: Option<String>,
    pub phase: Option<String>,
    pub client_ip: String,
    pub host: String,
    pub method: String,
    pub path: String,
    pub tier: Option<String>,
    pub detail: Option<String>,
    pub req_id: Option<String>,
}
```

**Fields on audit event:** 13 fields; NO risk_score, NO cache_status.

### Audit Event Routing

**File:** `engine.rs` lines 900–938 (`send_audit_event()`)

Every non-Allow decision calls:
```rust
fn send_audit_event(&self, ctx: &RequestCtx, decision: &WafDecision) {
    let event_type = match &decision.action {
        WafAction::Block { .. } => AuditEventType::Block,
        WafAction::Allow => AuditEventType::Allow,
        WafAction::LogOnly => AuditEventType::LogOnly,
        WafAction::Redirect { .. } | WafAction::Challenge => AuditEventType::Challenge,
    };
    // ... build AuditEvent and send
}
```

**Destination:** `VictoriaLogs` (time-series log ingest) with JSON payload + `_stream=waf_audit` tag.

### DB Logging

**File:** `engine.rs` lines 799–898

Two paths for Phase 1–2 and Phase 2+ events:
1. `log_attack()` → `AttackLog` model → `attack_logs` table
2. `log_security_event()` → `CreateSecurityEvent` model → `security_events` table

Both methods convert `WafAction` to string:
```rust
let action_str = match &decision.action {
    WafAction::Block { .. } => "block",
    WafAction::Allow => "allow",
    WafAction::LogOnly => "log_only",
    WafAction::Redirect { .. } => "redirect",
    WafAction::Challenge => "challenge",
};
```

**Log stored fields:** host_code, client_ip, method, path, rule_id, rule_name, action (as string), phase, detail, geo_info (JSON).

---

## 9. Observability Gaps vs Contract v2.3

**What exists:**
- ✅ Action model: 5 actions (Allow, Block, LogOnly, Redirect, Challenge)
- ✅ log_only mode: host-level config replaces Block → LogOnly
- ✅ Audit logging: VictoriaLogs + PostgreSQL (attack_logs, security_events)
- ✅ Request tracking: req_id in context, audit events carry it

**What is missing for v2.3 contract compliance:**
- ❌ X-WAF-Request-Id header injection (response)
- ❌ X-WAF-Risk-Score header (no risk score in decision)
- ❌ X-WAF-Action header (action not echoed to response)
- ❌ X-WAF-Rule-Id header (rule_id not echoed to response)
- ❌ X-WAF-Cache header (no cache decision in model)
- ❌ X-WAF-Mode header (no mode flag in model)
- ❌ Risk scoring integration (module exists but not wired)
- ❌ Dominant contributor tracking (no field in WafDecision)
- ❌ Circuit breaker action type (only 5 actions; no timeout/circuit_breaker)

---

## Unresolved Questions

1. **Risk scorer integration timeline:** Module exists but not in `inspect()` pipeline. When will FR-025 wire it?
2. **Circuit breaker action:** Contract requires 6 actions; is circuit-breaker vs timeout handled separately or deferred?
3. **Cache decision model:** Contract v2.3 requires X-WAF-Cache header; is cache decision tracked in engine or gateway only?
4. **Header injection location:** Should X-WAF-* headers be added in `write_waf_decision()` or via a separate gateway filter?

