# WAF Engine Detection Pipeline Analysis

**Date:** 2026-06-03  
**Scope:** Detection pipeline orchestration, checker invocation flow, mode/enforcement decision-making  
**Status:** Complete

---

## Executive Summary

The WAF engine's detection pipeline flows through 19 phases (plus risk scoring) with two critical control points:
1. **Mode decision via `log_only_mode` flag** on the `HostConfig` struct (line 571 in types.rs)
2. **Enforcement via `is_enforcement_allowed()`** that checks both action type AND `InteropMode` enum (lines 399-401 in types.rs)

All 15+ checkers emit `DetectionResult` structs which feed into `WafDecision` via the `make_block_decision()` helper (line 827 in engine.rs). The pipeline respects host-level enforcement mode at decision time, *not* at detection time — every detection is logged/audited regardless of mode.

---

## WafDecision & InteropMode Architecture

### InteropMode Enum
**Location:** `crates/waf-common/src/types.rs:275-308`

```rust
pub enum InteropMode {
    #[default]
    Enforce,      // Decision enforced (block/challenge take effect)
    LogOnly,      // Decision observed + logged, enforcement bypassed
}
```

**Contract strings:**
- `Enforce` → `"enforce"` (contract header)
- `LogOnly` → `"log_only"` (contract header)

**Key method:**
```rust
pub fn is_enforcement_allowed(&self) -> bool {
    matches!(self.action, WafAction::Allow | WafAction::LogOnly) 
        || self.mode == InteropMode::LogOnly
}
```

Mode-aware enforcement: request passes if action is non-blocking OR mode bypasses enforcement.

### WafDecision Struct
**Location:** `crates/waf-common/src/types.rs:310-408`

```rust
pub struct WafDecision {
    pub action: WafAction,           // Block, Allow, RateLimit, Challenge, etc.
    pub result: Option<DetectionResult>,
    pub risk_score: u8,              // 0..=100
    pub mode: InteropMode,           // Enforce | LogOnly (controls enforcement)
    pub rule_id: Option<String>,
}
```

**Default:** All decisions start with `mode = InteropMode::Enforce` (default).

---

## HostConfig Log-Only Mode

**Location:** `crates/waf-common/src/types.rs:571`

```rust
pub log_only_mode: bool,
```

**Purpose:** Per-host enforcement bypass flag. When `true`, all block decisions are converted to log-only mode.

**Usage Pattern (in engine.rs):**
```rust
if ctx.host_config.log_only_mode {
    decision.mode = InteropMode::LogOnly;
}
```

This line appears in TWO contexts:
1. Line 720-722: Phase 5-11 checker pipeline (rate-limit special case)
2. Line 778-780: Custom rules engine (allows mixed mode intent from rules)

---

## Complete Checker Invocation List

### Fast-Path Checkers (IP/URL Rules) — Phase 1-4
**No mode enforcement at these phases** — IP whitelist allows immediately, IP/URL blacklist blocks outright.

| Phase | Checker Call | Line | Returns | Guard |
|-------|---|---|---|---|
| 1 | `check_ip_whitelist(ctx, &self.store)` | 638 | `WafDecision` | `matches!(action, Allow) && phase == IpWhitelist` → return |
| 2 | `check_ip_blacklist(ctx, &self.store)` | 648 | `WafDecision` | `!is_enforcement_allowed()` → log + return |
| 3 | `check_url_whitelist(ctx, &self.store)` | 656 | `Option<WafDecision>` | `Some(_)` → log + return |
| 4 | `check_url_blacklist(ctx, &self.store)` | 662 | `WafDecision` | `!is_enforcement_allowed()` → log + return |

### Phase 19: DDoS Check
**Location:** Line 672-678

```rust
if let Some(result) = self.ddos_check.check(ctx) {
    let decision = Self::make_block_decision(ctx, &rule_name, result, 403);
    self.log_security_event(ctx, &decision);
    self.report_community_signal(ctx, &decision);
    return decision;
}
```

**Field:** `ddos_check: Arc<DdosCheck>` (line 121)  
**Returns:** `Option<DetectionResult>`  
**Mode applied:** Via `make_block_decision()` (respects `log_only_mode`)

### Phase 16a: CrowdSec Bouncer
**Location:** Line 681-689

```rust
if let Some(cs) = self.crowdsec_checker.get()
    && let Some(result) = cs.check(ctx)
{
    let decision = Self::make_block_decision(ctx, &rule_name, result, 403);
    self.log_security_event(ctx, &decision);
    self.report_community_signal(ctx, &decision);
    return decision;
}
```

**Field:** `crowdsec_checker: OnceLock<Arc<CrowdSecChecker>>` (line 81)  
**Returns:** `Option<DetectionResult>` via `.get()` lazy-load  
**Mode applied:** Via `make_block_decision()`

### Phase 18: Community Blocklist
**Location:** Line 692-699

```rust
if let Some(cc) = self.community_checker.get()
    && let Some(result) = cc.check(ctx)
{
    let decision = Self::make_block_decision(ctx, &rule_name, result, 403);
    self.log_security_event(ctx, &decision);
    return decision;
}
```

**Field:** `community_checker: OnceLock<Arc<CommunityChecker>>` (line 85)  
**Note:** Community signal NOT reported here (no `report_community_signal` call)  
**Mode applied:** Via `make_block_decision()`

### Phase 17: GeoIP Access Control
**Location:** Line 702-708

```rust
if let Some(result) = self.geo_check.check(ctx) {
    let decision = Self::make_block_decision(ctx, &rule_name, result, 403);
    self.log_security_event(ctx, &decision);
    self.report_community_signal(ctx, &decision);
    return decision;
}
```

**Field:** `geo_check: Arc<GeoCheck>` (line 76)  
**Returns:** `Option<DetectionResult>`  
**Mode applied:** Via `make_block_decision()`

### Phase 5-11: Dynamic Checker Pipeline
**Location:** Line 711-732

```rust
for checker in &self.checkers {
    if let Some(result) = checker.check(ctx) {
        let rule_name = result.rule_name.clone();

        // Special handling for RateLimit phase
        let decision = if result.phase == waf_common::Phase::RateLimit {
            let body = render_block_page(ctx, &rule_name);
            let mut d = WafDecision::rate_limit(429, Some(body), result);
            if ctx.host_config.log_only_mode {
                d.mode = InteropMode::LogOnly;
            }
            d
        } else {
            Self::make_block_decision(ctx, &rule_name, result, 403)
        };

        self.log_security_event(ctx, &decision);
        self.report_community_signal(ctx, &decision);
        return decision;
    }
}
```

**Checkers vec (lines 202-217):**
1. `RateLimitCheck` (Phase 11 — rate limit tokens)
2. `TxVelocityCheck` (Phase 12 — transaction velocity, signal-only)
3. `ScannerCheck` (Phase 8 — endpoint enumeration/OPTIONS abuse)
4. `BotCheck` (Phase 10 — bot detection)
5. `XssCheck` (Phase 6 — XSS patterns)
6. `RceCheck` (Phase 7 — RCE patterns)
7. `DirTraversalCheck` (Phase 9 — directory traversal)
8. `SsrfCheck` (Phase 21 — SSRF validation)
9. `HeaderInjectionCheck` (Phase 22 — HTTP header smuggling)
10. `BruteForceCheck` (Phase 23 — brute-force/credential spraying)
11. `RequestBodyAbuseCheck` (Phase 24 — oversized/nested JSON abuse)

**Mode applied:** Via `make_block_decision()` for non-RateLimit phases; manual mode set for RateLimit

### Phase 5 (Separate): SQL Injection Check
**Location:** Line 735-741

```rust
if let Some(result) = self.sqli_check.check(ctx) {
    let rule_name = result.rule_name.clone();
    let decision = Self::make_block_decision(ctx, &rule_name, result, 403);
    self.log_security_event(ctx, &decision);
    self.report_community_signal(ctx, &decision);
    return decision;
}
```

**Field:** `sqli_check: Arc<SqlInjectionCheck>` (line 78)  
**Reason separate:** Hot-reload support — SQLi config reloadable via `reload_sqli_scan_config(cfg)` (line 522)  
**Returns:** `Option<DetectionResult>`  
**Mode applied:** Via `make_block_decision()`

### Phase 16b: CrowdSec AppSec
**Location:** Line 744-756

```rust
if let Some(appsec) = self.appsec_client.get() {
    match appsec.check_request(ctx).await {
        AppSecResult::Block { message } => {
            let result = appsec_to_detection(message);
            let rule_name = result.rule_name.clone();
            let decision = Self::make_block_decision(ctx, &rule_name, result, 403);
            self.log_security_event(ctx, &decision);
            self.report_community_signal(ctx, &decision);
            return decision;
        }
        AppSecResult::Allow | AppSecResult::Unavailable => {}
    }
}
```

**Field:** `appsec_client: OnceLock<Arc<AppSecClient>>` (line 82)  
**Returns:** `AppSecResult` → converted to `DetectionResult` via `appsec_to_detection()`  
**Mode applied:** Via `make_block_decision()`  
**Note:** Only `Block` variant triggers decision return; `Allow`/`Unavailable` continue pipeline

### Phase 12: Custom Rules Engine
**Location:** Line 759-789

```rust
if let Some(result) = self.custom_rules.check(ctx) {
    let rule_name = result.rule_name.clone();
    let action_intent = result.rule_action.unwrap_or(RuleAction::Block);
    let status = result.action_status.unwrap_or(403);
    let body = if action_intent == RuleAction::Block {
        Some(render_block_page(ctx, &rule_name))
    } else {
        None
    };
    let rule_id = result.rule_id.clone();
    let mut decision = WafDecision {
        action: action_intent.to_waf_action(status, body),
        result: Some(result),
        risk_score: 0,
        mode: InteropMode::Enforce,
        rule_id,
    };
    if ctx.host_config.log_only_mode {
        decision.mode = InteropMode::LogOnly;
    }
    self.log_security_event(ctx, &decision);
    self.report_community_signal(ctx, &decision);
    
    // CRITICAL: Custom rules are continuable on Allow/Log intent
    if !decision.is_enforcement_allowed() {
        return decision;
    }
}
```

**Field:** `custom_rules: Arc<CustomRulesEngine>` (line 66)  
**Returns:** `Option<DetectionResult>` with custom `rule_action` + `action_status` overrides  
**Mode applied:** Manual mode set based on `log_only_mode`  
**Key behavior:** Only returns on Block/Challenge intent; Allow/Log intent falls through to Phase 13+

### Phase 13: OWASP CRS
**Location:** Line 792-798

```rust
if let Some(result) = self.owasp.check(ctx) {
    let rule_name = result.rule_name.clone();
    let decision = Self::make_block_decision(ctx, &rule_name, result, 403);
    self.log_security_event(ctx, &decision);
    self.report_community_signal(ctx, &decision);
    return decision;
}
```

**Field:** `owasp: Arc<OWASPCheck>` (line 74)  
**Returns:** `Option<DetectionResult>`  
**Mode applied:** Via `make_block_decision()`

### Phase 14: Sensitive Data Detection
**Location:** Line 801-807

```rust
if let Some(result) = self.sensitive.check(ctx) {
    let rule_name = result.rule_name.clone();
    let decision = Self::make_block_decision(ctx, &rule_name, result, 403);
    self.log_security_event(ctx, &decision);
    self.report_community_signal(ctx, &decision);
    return decision;
}
```

**Field:** `sensitive: Arc<SensitiveCheck>` (line 67)  
**Returns:** `Option<DetectionResult>`  
**Mode applied:** Via `make_block_decision()`

### Phase 15: Anti-Hotlinking
**Location:** Line 810-816

```rust
if let Some(result) = self.hotlink.check(ctx) {
    let rule_name = result.rule_name.clone();
    let decision = Self::make_block_decision(ctx, &rule_name, result, 403);
    self.log_security_event(ctx, &decision);
    self.report_community_signal(ctx, &decision);
    return decision;
}
```

**Field:** `hotlink: Arc<AntiHotlinkCheck>` (line 68)  
**Returns:** `Option<DetectionResult>`  
**Mode applied:** Via `make_block_decision()`

### Final: Allow Decision
**Location:** Line 818

```rust
WafDecision::allow()
```

No detection → default allow with `mode = InteropMode::Enforce` (default).

---

## make_block_decision() Helper

**Location:** Line 827-834

```rust
fn make_block_decision(
    ctx: &RequestCtx, 
    rule_name: &str, 
    result: DetectionResult, 
    status: u16
) -> WafDecision {
    let body = render_block_page(ctx, rule_name);
    let mut decision = WafDecision::block(status, Some(body), result);
    if ctx.host_config.log_only_mode {
        decision.mode = InteropMode::LogOnly;
    }
    decision
}
```

**Responsibility:**
1. Render the block page HTML
2. Create a `Block` action with status code
3. **Apply host-level `log_only_mode`** — converts decision mode to `LogOnly` if enabled
4. Return complete `WafDecision`

This is the **single enforcement-mode control point** for all 15+ checkers.

---

## Detection Flow Diagram

```
Request arrives
    ↓
inspect() called (line 608)
    ├─ GeoIP enrichment (line 633)
    ├─ Risk scoring (lines 611-615)
    └─ invoke inspect_pipeline() (line 617)
        ↓
    inspect_pipeline() (line 626)
        ↓
    Phase 1-4: IP/URL fast-path
        ├─ IP whitelist → return allow (no mode check)
        ├─ IP blacklist → make_block_decision() → return
        ├─ URL whitelist → return allow (no mode check)
        └─ URL blacklist → make_block_decision() → return
        ↓
    Phase 19: DDoS burst → make_block_decision() → return
    Phase 16a: CrowdSec bouncer → make_block_decision() → return
    Phase 18: Community blocklist → make_block_decision() → return
    Phase 17: GeoIP geo-control → make_block_decision() → return
        ↓
    Phase 5-11: Checker pipeline loop
        └─ for each checker: check() → [RateLimit special case | make_block_decision()] → return
        ↓
    Phase 5: SQLi (separate) → make_block_decision() → return
        ↓
    Phase 16b: CrowdSec AppSec → make_block_decision() → return on Block
        ↓
    Phase 12: Custom rules → [manual mode set] → return if Block/Challenge
        ↓
    Phase 13: OWASP CRS → make_block_decision() → return
    Phase 14: Sensitive → make_block_decision() → return
    Phase 15: Anti-hotlink → make_block_decision() → return
        ↓
    No detection → return allow()
        ↓
send_audit_event() (line 619) ← ALL decisions audited here
```

---

## Audit & Logging Integration

**Single audit point:** `send_audit_event()` called ONCE at end of `inspect()` (line 619), after risk score attached.

**Location:** Line 982-1028

```rust
fn send_audit_event(
    &self, 
    ctx: &RequestCtx, 
    decision: &WafDecision, 
    timestamp: chrono::DateTime<chrono::Utc>
) {
    let Some(sender) = self.audit_sender.get() else { return; };
    
    let event_type = match &decision.action {
        WafAction::Block { .. } => AuditEventType::Block,
        WafAction::Allow => AuditEventType::Allow,
        WafAction::LogOnly => AuditEventType::LogOnly,
        WafAction::RateLimit { .. } => AuditEventType::Block,
        // ... other variants
    };
    
    let event = AuditEvent {
        mode: decision.mode,  ← **MODE EMBEDDED HERE**
        // ... other fields
    };
    sender.send(event);
}
```

**Key:** Audit event captures `decision.mode` — allows operators to distinguish enforced vs. log-only detections.

---

## WafEngine Constructor & Initialization

**Location:** Line 145-256

```rust
pub fn new(db: Arc<Database>, config: WafEngineConfig) -> Self {
    Self::with_sqli_config(db, config, SqliScanConfig::default())
}

pub fn with_sqli_config(
    db: Arc<Database>, 
    config: WafEngineConfig, 
    sqli_cfg: SqliScanConfig
) -> Self {
    // ── Core checkers (Phase 5-11) ────────────────────────────
    let rl_store = Arc::new(RlMemoryStore::new());
    let rate_limit_cfg = Arc::new(ArcSwap::from(Arc::new(RateLimitConfig::default())));
    
    let tx_velocity_cfg = Arc::new(ArcSwap::from(Arc::new(TxVelocityConfig::default())));
    let tx_velocity_store = Arc::new(TxStore::new(Arc::clone(&tx_velocity_cfg)));
    
    // ── DDoS (Phase 19) ────────────────────────────────────
    let ddos_cfg = Arc::new(ArcSwap::from(Arc::new(DdosConfig::default())));
    let ddos_check = Arc::new(DdosCheck::new(/* ... */));
    
    // ── Build checkers vec ─────────────────────────────────
    let checkers: Vec<Box<dyn Check>> = vec![
        Box::new(RateLimitCheck::new(rl_store, Arc::clone(&rate_limit_cfg))),
        Box::new(TxVelocityCheck::new(/* ... */)),
        Box::new(ScannerCheck::new()),
        Box::new(BotCheck::new()),
        // ... 7 more checks
    ];
    
    // ── Risk scorer ────────────────────────────────────────
    let risk_cfg = Arc::new(ArcSwap::from(Arc::new(RiskConfig::default())));
    let scorer = Arc::new(Scorer::new(Arc::new(MemoryRiskStore::new()), Arc::clone(&risk_cfg)));
    
    Self {
        store,
        custom_rules,
        sensitive,
        hotlink,
        db,
        config,
        checkers,
        owasp,
        geo_check,
        sqli_check,
        crowdsec_checker: OnceLock::new(),
        appsec_client: OnceLock::new(),
        community_checker: OnceLock::new(),
        community_reporter: OnceLock::new(),
        geoip: OnceLock::new(),
        rules_dir: OnceLock::new(),
        file_watcher: OnceLock::new(),
        rate_limit_cfg,
        rate_limit_reloader: OnceLock::new(),
        tx_velocity_cfg,
        tx_velocity_store,
        tx_velocity_reloader: OnceLock::new(),
        ddos_cfg,
        ddos_check,
        ddos_reloader: OnceLock::new(),
        audit_sender: OnceLock::new(),
        db_batch_writer: OnceLock::new(),
        risk_cfg,
        scorer,
    }
}
```

**Constructor fields:**
- **Static (line 65-78):** `store`, `custom_rules`, `sensitive`, `hotlink`, `db`, `config`, `checkers`, `owasp`, `geo_check`, `sqli_check`
- **Lazy (OnceLock, set post-init):** `crowdsec_checker`, `appsec_client`, `community_checker`, `community_reporter`, `geoip`, `rules_dir`, `file_watcher`, `audit_sender`, `db_batch_writer`
- **Hot-reloadable (ArcSwap):** `rate_limit_cfg`, `tx_velocity_cfg`, `ddos_cfg`, `risk_cfg`

---

## Log-Only Mode Enforcement Points

**Two locations where `log_only_mode` is checked:**

1. **Line 720-722** — Rate-limit phase special case
   ```rust
   if ctx.host_config.log_only_mode {
       d.mode = InteropMode::LogOnly;
   }
   ```

2. **Line 778-780** — Custom rules phase (before deciding whether to return)
   ```rust
   if ctx.host_config.log_only_mode {
       decision.mode = InteropMode::LogOnly;
   }
   ```

3. **Line 830-832** — All other phases (via `make_block_decision()`)
   ```rust
   if ctx.host_config.log_only_mode {
       decision.mode = InteropMode::LogOnly;
   }
   ```

**All three sites set the SAME field:** `decision.mode = InteropMode::LogOnly`

---

## Response Lifecycle Hooks

**Location:** Line 836-863

```rust
pub fn on_response(&self, ctx: &RequestCtx, status: u16) {
    for check in &self.checkers {
        check.on_response(ctx, status);
    }
    self.sqli_check.on_response(ctx, status);
}

pub fn on_request_complete(&self, ctx: &RequestCtx, status: u16, upstream_reached: bool) {
    for check in &self.checkers {
        check.on_request_complete(ctx, status, upstream_reached);
    }
}
```

**Purpose:**
- `on_response()` — Called after upstream sends response status (used by brute-force to count 401/403)
- `on_request_complete()` — Called at end of request lifecycle (used by tx_velocity to finalize `Outcome` field)

Neither hook affects enforcement decisions — they update state for velocity classifiers.

---

## Summary Table: All Checker Phases

| Phase | Checker | Field | Returns | Make Decision? | Can Skip? |
|-------|---------|-------|---------|---|---|
| 1 | IP Whitelist | `store` | `WafDecision` | No | Yes (whitelist) |
| 2 | IP Blacklist | `store` | `WafDecision` | No | No (blocks) |
| 3 | URL Whitelist | `store` | `Option<WafDecision>` | No | Yes (whitelist) |
| 4 | URL Blacklist | `store` | `WafDecision` | No | No (blocks) |
| 5 | SQL Injection | `sqli_check` | `Option<DetectionResult>` | Yes | No |
| 5-11 | Checker pipeline | `checkers` | `Option<DetectionResult>` | Yes | No |
| 6 | XSS | `checkers[3]` | `Option<DetectionResult>` | Yes | No |
| 7 | RCE | `checkers[4]` | `Option<DetectionResult>` | Yes | No |
| 8 | Scanner | `checkers[2]` | `Option<DetectionResult>` | Yes | No |
| 9 | Dir Traversal | `checkers[6]` | `Option<DetectionResult>` | Yes | No |
| 10 | Bot | `checkers[3]` | `Option<DetectionResult>` | Yes | No |
| 11 | Rate Limit | `checkers[0]` | `Option<DetectionResult>` | Manual | No |
| 12 | Custom Rules | `custom_rules` | `Option<DetectionResult>` | Manual | Conditional |
| 13 | OWASP | `owasp` | `Option<DetectionResult>` | Yes | No |
| 14 | Sensitive | `sensitive` | `Option<DetectionResult>` | Yes | No |
| 15 | Anti-Hotlink | `hotlink` | `Option<DetectionResult>` | Yes | No |
| 16a | CrowdSec Bouncer | `crowdsec_checker` | `Option<DetectionResult>` | Yes | No |
| 16b | CrowdSec AppSec | `appsec_client` | `AppSecResult` | Yes | No |
| 17 | GeoIP | `geo_check` | `Option<DetectionResult>` | Yes | No |
| 18 | Community | `community_checker` | `Option<DetectionResult>` | Yes | No |
| 19 | DDoS | `ddos_check` | `Option<DetectionResult>` | Yes | No |
| 20 | Risk Score | `scorer` | Attached post-pipeline | No | No |

---

## Key Insights

### 1. Single Enforcement Control Point
All block decisions route through `make_block_decision()` **except**:
- Rate-limit (manual mode set, line 720)
- Custom rules (manual mode set, line 778)

This concentrates mode logic in one place (line 830).

### 2. All Detections Are Audited
Even log-only detections reach `send_audit_event()` (line 619) with `mode = LogOnly`, allowing operators to:
- See what *would* have blocked in audit logs
- Distinguish enforcement from observation
- Tune rules without blocking

### 3. Custom Rules Are Continuable
Phase 12 (Custom Rules) is the only phase that doesn't always return on detection — it only returns if `is_enforcement_allowed()` is false. Allow/Log intent passes through to Phase 13+ (OWASP, Sensitive, Hotlink).

### 4. Risk Score Attached Post-Pipeline
Risk score computed BEFORE pipeline (lines 611-615), then attached to decision AFTER detection (line 618). All audit/logging sees the final score.

### 5. DDoS Runs Early (Phase 19)
Despite being numbered 19, DDoS runs after IP/URL allowlists but BEFORE rate-limit & attack detection. Banned IPs blocked here before pattern checks.

### 6. Lazy Initialization Pattern
Non-critical checkers (`crowdsec`, `appsec`, `community`, `geoip`, `audit_sender`, `db_batch_writer`) use `OnceLock` for optional runtime wire-up. Engine never panics if not set — checks guard with `.get()`.

---

## Unresolved Questions

1. **Phase ordering rationale:** Why does DDoS (19) run after Phase 4 but before Phase 5-11? Is the numbering historical?
2. **Custom rules continuability:** Should rules with Log intent also be haltable via a config flag, or is "continue to Phase 13+" the intended design?
3. **Rate-limit special case:** Why does rate-limit use `WafDecision::rate_limit()` with manual mode set instead of `make_block_decision()` like other phases?
4. **Community reporter dropout:** Phase 18 (Community blocklist) doesn't call `report_community_signal()` — intentional or oversight?
