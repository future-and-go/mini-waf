# Gateway ↔ Engine WAF Decision Integration Analysis

## Executive Summary

**Engine→Gateway decision flow**: Engine's `inspect()` returns `WafDecision` (includes `action`, `risk_score`, `rule_id`, `mode`). Gateway snapshots it into `WafDecisionMeta` at line 726 in `proxy.rs`, then uses that metadata across all egress paths (block, allow, error, cache). **Mode enforcement gates** via `is_enforcement_allowed()` at line 53 in `proxy_waf_response.rs`. Engine is NOT accessible from gateway—only passed as immutable `Arc<WafEngine>` at construction. Gateway receives `log_only_mode` from host config, NOT from a global ModeRegistry.

---

## Diagram: WAF Decision Flow

```
RequestCtx
    │
    ├─→ WafEngine::inspect(&mut request_ctx) [async]
    │   ├─ Runs all detection phases
    │   └─ Returns WafDecision {
    │       action: WafAction,
    │       risk_score: u8,
    │       rule_id: Option<String>,
    │       mode: InteropMode,  ← Set by engine
    │       result: Option<DetectionResult>,
    │       ...
    │     }
    │
    └─→ proxy.rs:726: WafDecisionMeta::from_decision(decision)
        │   └─ Snapshots decision into lightweight metadata
        │       action: &'static str    ("allow" | "block" | "challenge" | …)
        │       risk_score: u8          (0..=100)
        │       rule_id: Option<String> (None on allow)
        │       mode: &'static str      ("enforce" | "log_only")
        │
        └─→ GatewayCtx::waf_decision_meta = Some(meta)
            │
            ├─→ proxy_waf_response.rs:53  [write_waf_decision]
            │   if !decision.is_enforcement_allowed() {  ← mode check here
            │       blocked_counter++
            │       match action {
            │           Block | RateLimit | CircuitBreaker → write response + headers
            │           Challenge → handle_challenge()
            │           Redirect → 302
            │           Timeout → 504
            │       }
            │   }
            │   return Ok(false)  ← passthrough if allowed/log-only
            │
            └─→ waf_observability_headers.rs:73  [inject_for_passthrough]
                └─ 6 headers: X-WAF-{Request-Id, Risk-Score, Action, Rule-Id, Cache, Mode}
                   mode sourced from:
                   (a) waf_decision_meta.mode  OR
                   (b) fallback: host_config.log_only_mode ? "log_only" : "enforce"
```

---

## Key Integration Points

### 1. Engine Construction & Passing (main.rs:1582, proxy.rs:115)

```rust
// main.rs:1582 — Engine created with db + config
let engine = Arc::new(WafEngine::new(Arc::clone(&db), WafEngineConfig::default()));

// main.rs:1358 — Engine passed to proxy at construction
let mut proxy = WafProxy::new(router, engine);

// proxy.rs:54 — Stored as immutable Arc
pub struct WafProxy {
    pub engine: Arc<WafEngine>,
    // ...
}
```

**Implication**: Gateway does NOT hold `AppState` or access `ModeRegistry`. Engine is injected as-is; gateway only calls `engine.inspect()` and reads the response.

---

### 2. WafDecision → WafDecisionMeta Snapshot (proxy.rs:722–728)

```rust
let decision = self.engine.inspect(&mut request_ctx).await;  // line 722

// Snapshot metadata BEFORE write_waf_decision + cache HIT branch
let is_challenge = matches!(decision.action, waf_common::WafAction::Challenge);
let meta = WafDecisionMeta::from_decision(&decision);  // line 726
let meta_action_allow = meta.action == "allow";
ctx.waf_decision_meta = Some(meta);
```

**Why snapshot?** (context.rs:16–22)
- Avoids cloning heavy `DetectionResult`
- Provides safe defaults: `action = "allow"` (fast-path passthrough safety)
- Accessible from every egress path without reaching back into engine

**from_decision conversion** (context.rs:52–59):
```rust
pub fn from_decision(decision: &waf_common::WafDecision) -> Self {
    Self {
        action: decision.action.as_contract_str(),           // "allow" | "block" | "challenge" | …
        risk_score: decision.risk_score.min(100),
        rule_id: decision.rule_id.clone(),                 // alloc only on match
        mode: decision.mode.as_contract_str(),             // "enforce" | "log_only"
    }
}
```

---

### 3. Mode Enforcement Gate (proxy_waf_response.rs:53)

```rust
pub async fn write_waf_decision(
    session: &mut Session,
    decision: &WafDecision,
    request_ctx: &RequestCtx,
    blocked_counter: &AtomicU64,
    challenge_ctx: Option<&Arc<ChallengeCtx>>,
) -> pingora_core::Result<bool> {
    if !decision.is_enforcement_allowed() {  // ← LINE 53
        blocked_counter.fetch_add(1, Ordering::Relaxed);
        // Write block/challenge/redirect response
        match &decision.action {
            WafAction::Block { status, body } | WafAction::RateLimit { … } | WafAction::CircuitBreaker { … } => { … }
            WafAction::Challenge => handle_challenge(…) 
            WafAction::Redirect { url } => { … }
            WafAction::Timeout { status } => { … }
            WafAction::Allow | WafAction::LogOnly => {}  // no-op, fall through
        }
        return Ok(true);  // response already sent
    }
    Ok(false)  // passthrough to upstream
}
```

**is_enforcement_allowed() definition** (waf-common/types.rs:399–401):
```rust
pub fn is_enforcement_allowed(&self) -> bool {
    matches!(self.action, WafAction::Allow | WafAction::LogOnly) 
        || self.mode == InteropMode::LogOnly
}
```

**Semantics**: 
- Block/challenge → response only written if NOT in LogOnly mode
- If mode=LogOnly, suppresses enforcement regardless of action
- Action=Allow/LogOnly always passthrough (even if mode=Enforce)

---

### 4. X-WAF-Mode Header Injection (waf_observability_headers.rs)

#### Path A: Passthrough (inject_for_passthrough, line 73)
```rust
pub fn inject_for_passthrough(resp: &mut ResponseHeader, ctx: &GatewayCtx) 
    -> pingora_core::Result<()> 
{
    let fallback_mode = ctx
        .host_config
        .as_ref()
        .map_or("enforce", |hc| 
            if hc.log_only_mode { "log_only" } else { "enforce" }
        );
    let (action, risk_score, rule_id, mode) = ctx
        .waf_decision_meta
        .as_ref()
        .map_or(("allow", 0u8, None, fallback_mode), |m| {
            (m.action, m.risk_score, m.rule_id.as_deref(), m.mode)
        });
    // …inject mode into response…
}
```

**Mode source priority**:
1. `waf_decision_meta.mode` (from engine decision if inspect ran)
2. **Fallback** → `host_config.log_only_mode` (if meta=None, i.e., fast-path or error)

#### Path B: Pre-inspect/Error (inject_for_pre_inspect_or_error, line 122)
```rust
pub fn inject_for_pre_inspect_or_error(
    resp: &mut ResponseHeader,
    ctx: &GatewayCtx,
    action: &str,
    fallback_req_id: &str,
) -> pingora_core::Result<()> 
{
    let mode = ctx
        .host_config
        .as_ref()
        .map_or("enforce", |hc| 
            if hc.log_only_mode { "log_only" } else { "enforce" }
        );
    // …inject mode into response…
}
```

**Used for**: access-gate 403 (line 702), fail-closed 503 (line 607), HTTP→HTTPS 301 (line 649), health 200 (line 618), transport error (line 1165).

---

### 5. Access-Bypass Fast Path (proxy.rs:710–720)

```rust
if ctx.access_bypass {  // access-list whitelist hit
    let mut meta = WafDecisionMeta::default();  // action="allow", mode="enforce"
    if request_ctx.host_config.log_only_mode {
        meta.mode = "log_only";  // ← Override if host in log-only
    }
    ctx.waf_decision_meta = Some(meta);
    return Ok(false);  // Skip engine, passthrough
}
```

**Implication**: Even whitelisted requests emit X-WAF-Mode based on host config. Mode does NOT come from AppState; it's purely host-level.

---

## Architecture Findings

### Does Gateway Have Access to AppState?

**No.** 
- Gateway receives `Arc<WafEngine>` at construction
- Engine is NOT a gateway field—it's passed by value in method signatures
- No reference to `ModeRegistry` or `AppState` anywhere in `gateway/`

**Grep evidence**:
```bash
$ grep -rn "AppState\|app_state\|ModeRegistry" crates/gateway/
# Only hit: proxy.rs:59-61
#   pub request_counter: Arc<AtomicU64>,
#   pub blocked_counter: Arc<AtomicU64>,
#   /// Total request counter (cloned from `AppState`).
```
These are counters **copied** from AppState at setup time (main.rs:1360–1361), not live references.

---

### Mode Derivation Sources

**For engine-inspected requests**:
- Primary: `decision.mode` set by engine during inspection (engine-side logic)
- Fallback: `host_config.log_only_mode` (used if meta=None, rare)

**For fast-path requests** (whitelist bypass, health, errors):
- Always: `host_config.log_only_mode`

**No global ModeRegistry in gateway.** Mode is per-host config field only.

---

### WafDecision.mode: Where It's Set

The engine emits `decision.mode` during inspection. Gateway **never modifies** it. To understand when/how engine sets mode, requires inspection of `waf_engine::inspect()` implementation (outside scope of this analysis).

---

## Code Paths Traced

| Path | File | Lines | Mode Source |
|------|------|-------|-------------|
| Normal block/allow | proxy_waf_response.rs | 46–121 | decision.mode (snapshot in meta) |
| Challenge | proxy_waf_response.rs | 111–230 | decision.mode |
| Access-gate 403 | proxy.rs | 690–707 | host_config (no inspect) |
| Fail-closed 503 | proxy.rs | 580–611 | host_config (no inspect) |
| HTTP→HTTPS 301 | proxy.rs | 640–652 | host_config (no inspect) |
| Health 200 | proxy.rs | 613–621 | host_config (no inspect) |
| Transport error | proxy.rs | 1112–1184 | host_config (no inspect) |
| Cache HIT | response_cache_integration.rs (via inject_for_passthrough) | line 73 | meta OR host_config |
| Passthrough (allow) | proxy.rs | response_filter @ 1016 | meta OR host_config |

---

## Line Number Reference

### proxy.rs (Main decision orchestration)
- **54**: Engine field declaration
- **115**: WafProxy::new constructor
- **722**: engine.inspect() call
- **726**: WafDecisionMeta::from_decision snapshot
- **710–720**: Access-bypass fast-path
- **613–621**: Health 200 response
- **640–652**: HTTP→HTTPS 301
- **690–707**: Access-gate 403 block
- **580–611**: Fail-closed 503
- **1112–1184**: fail_to_proxy error response

### proxy_waf_response.rs (Decision→response conversion)
- **24–33**: waf_header_values_from_decision (extracts decision fields)
- **46–121**: write_waf_decision main logic
- **53**: is_enforcement_allowed() gate
- **59–94**: Block/RateLimit/CircuitBreaker handler
- **104–110**: Redirect handler
- **111–230**: Challenge handler
- **236–304**: write_waf_body_decision (body inspection)

### waf_observability_headers.rs (Mode header injection)
- **43–57**: inject_waf_observability_headers (core 6-header logic)
- **73–105**: inject_for_passthrough (mode from meta OR host_config)
- **122–143**: inject_for_pre_inspect_or_error (mode from host_config only)

### context.rs (Decision snapshot structure)
- **24–35**: WafDecisionMeta struct definition
- **52–59**: from_decision conversion
- **88**: ChallengeCtx struct

---

## Unresolved Questions

1. **Engine mode assignment logic**: When/how does `WafEngine::inspect()` set `decision.mode`? Is it rule-driven, config-driven, or hardcoded? (Requires `waf-engine/src/inspect.rs` read)

2. **ModeRegistry purpose**: If gateway never accesses it, what is its intended use? (Likely API-side only for admin overrides that don't reach data plane)

3. **Host config hot-reload**: Does `log_only_mode` on HostConfig participate in config reload watchers? Can it change mid-request? (Requires `waf_api/` scope check)

4. **Challenge mode semantics**: When a decision is `Challenge` with `mode=LogOnly`, does the challenge page still render, or is it suppressed? (Code suggests page renders but enforcement skipped — verify at line 111)

5. **Risk score accumulation**: Is risk_score on WafDecision per-request cumulative, or per-matched-rule? How does mode affect its calculation? (Engine-side question)

