---
phase: 4
title: "Control Interface (§2)"
status: pending
priority: P1
effort: "1-2d"
dependencies: [1]
---

# Phase 4: Control Interface (§2)

## Overview

Implement 4 `/__waf_control/*` endpoints with `X-Benchmark-Secret` header authentication. These allow the benchmarker to discover capabilities, reset runtime state, toggle enforce/log_only per feature/policy, and flush cache.

## Context Links

- Contract §2: `analysis/docs/EN_waf_interop_contract_v2.3.md` lines 25–282
- Gap report §2: `plans/reports/contract-gap-analysis-260527-1133-waf-interop-v23-report.md` lines 17–39
- Current API router: `crates/waf-api/src/server.rs:59–293`
- Existing cache API: `crates/waf-api/src/cache_api.rs`
- AppState: `crates/waf-api/src/` (shared state pattern)
- HostConfig log_only_mode: `crates/waf-common/src/types.rs:331`

## Requirements

**Functional (contract §2.1–2.6):**

| Endpoint | Method | Purpose |
|----------|--------|---------|
| `/__waf_control/capabilities` | GET | Discover supported features, policies, toggle controls |
| `/__waf_control/reset_state` | POST | Clear temporary runtime state between test runs |
| `/__waf_control/set_profile` | POST | Toggle enforce/log_only per feature/policy |
| `/__waf_control/flush_cache` | POST | Clear WAF cache |

**Authentication (§2.2):**
- All endpoints require `X-Benchmark-Secret: waf-hackathon-2026-ctrl`
- Missing/invalid → `403 Forbidden`
- Secret configurable in TOML (default: `waf-hackathon-2026-ctrl`)

**Capabilities response (§2.3):**
- List all WAF features with `supported`, `toggleable`, `policies[]`
- Include `active.default_mode` and `active.overrides`

**Reset state (§2.4):**
- Clear: risk state, rate-limit counters, cache, challenge/session state, temp enforcement state
- MUST NOT modify `./waf_audit.log`
- Synchronous — success only after full clear

**Set profile (§2.5):**
- Scope: `all`, `features`, `policies`
- Mode: `enforce`, `log_only`
- Per-feature and per-policy granularity
- Unsupported items reported in response

**Flush cache (§2.6):**
- Clear all cached responses
- Synchronous — success only after cache cleared

## Architecture

### ModeRegistry: Runtime Mode State

Central to `set_profile` is a runtime mode registry that tracks enforce/log_only state per feature and policy. This replaces the per-host `log_only_mode: bool`.

```rust
// crates/waf-engine/src/interop/mode_registry.rs
pub struct ModeRegistry {
    state: ArcSwap<ModeState>,
}

pub struct ModeState {
    pub default_mode: InteropMode,
    pub feature_overrides: HashMap<String, InteropMode>,
    pub policy_overrides: HashMap<String, InteropMode>,  // key: "feature.policy"
}
```

- Hot-swappable via `ArcSwap` (lock-free reads from request pipeline)
- Engine reads `mode_registry.resolve(feature, policy)` to determine mode for each detection phase
- `set_profile` atomically swaps the entire `ModeState`
- **RT-06 fix:** `set_all(mode)` MUST clear both `feature_overrides` and `policy_overrides` maps (contract line 186: "Any previous overrides SHOULD be cleared")

### Feature/Policy Mapping

Map existing detection phases to contract features + policies:

| Contract Feature | Phases | Policies |
|-----------------|--------|----------|
| `access_control` | IpWhitelist, IpBlacklist, UrlWhitelist, UrlBlacklist | `ip_whitelist`, `ip_blacklist`, `url_whitelist`, `url_blacklist` |
| `attack_detection` | SqlInjection, Xss, Rce, DirTraversal, Ssrf, HeaderInjection | `sqli`, `xss`, `rce`, `dir_traversal`, `ssrf`, `header_injection` |
| `rate_limiting` | RateLimit | `ip_rate_limit`, `session_rate_limit` |
| `ddos_protection` | Ddos | `per_ip`, `per_fingerprint`, `per_tier` |
| `bot_detection` | Scanner, Bot | `scanner`, `bot` |
| `challenge` | RiskScore (challenge threshold) | `pow_challenge` |
| `custom_rules` | CustomRule | `yaml_rules`, `rhai_scripts`, `wasm_plugins` |
| `owasp_crs` | Owasp | `owasp_core_ruleset` |
| `threat_intel` | CrowdSec, Community | `crowdsec`, `community_feeds` |
| `geo_access` | GeoIp | `geoip_block` |
| `sensitive_data` | Sensitive | `data_leak_detection` |
| `anti_hotlink` | AntiHotlink | `referer_check` |
| `brute_force` | BruteForce | `credential_stuffing` |
| `request_body` | RequestBodyAbuse | `oversized_body` |

### Route Group Structure

```rust
// crates/waf-api/src/interop_control_api.rs
pub fn interop_control_routes() -> Router<AppState> {
    Router::new()
        .route("/capabilities", get(capabilities_handler))
        .route("/reset_state", post(reset_state_handler))
        .route("/set_profile", post(set_profile_handler))
        .route("/flush_cache", post(flush_cache_handler))
        .layer(middleware::from_fn(benchmark_secret_guard))
}

// Mounted in server.rs:
// app.nest("/__waf_control", interop_control_routes())
```

### Benchmark Secret Middleware

```rust
async fn benchmark_secret_guard(req: Request, next: Next) -> Response {
    let expected = /* from config or default */;
    match req.headers().get("x-benchmark-secret") {
        Some(v) if v == expected => next.run(req).await,
        _ => (StatusCode::FORBIDDEN, Json(json!({"ok": false, "error": "invalid secret"}))).into_response(),
    }
}
```

### Reset State Implementation

Reset must clear across multiple subsystems. Use the existing `Arc`-shared components:

```rust
async fn reset_state_handler(State(state): State<AppState>) -> Json<Value> {
    // 1. Clear rate-limit counters (MemoryStore::clear + Redis FLUSHDB scoped)
    // 2. Clear DDoS ban table
    // 3. Clear risk scorer state (per-actor accumulators)
    // 4. Clear challenge session state
    // 5. Flush response cache (reuse cache_api logic)
    // 6. Clear behavioral anomaly state
    // 7. Clear transaction velocity state
    // DO NOT touch ./waf_audit.log
    
    Json(json!({
        "ok": true,
        "action": "reset_state",
        "audit_log_preserved": true,
        "ts_ms": epoch_ms_now()
    }))
}
```

## Related Code Files

**Create:**
- `crates/waf-engine/src/interop/mod.rs` — interop module root
- `crates/waf-engine/src/interop/mode_registry.rs` — ModeRegistry + ModeState
- `crates/waf-engine/src/interop/feature_catalog.rs` — feature/policy mapping constants
- `crates/waf-api/src/interop_control_api.rs` — 4 endpoint handlers + middleware

**Modify:**
- `crates/waf-engine/src/lib.rs` — export interop module
- `crates/waf-engine/src/engine.rs` — read ModeRegistry instead of HostConfig.log_only_mode
- `crates/waf-api/src/server.rs` — mount `/__waf_control` route group
- `crates/waf-common/src/config.rs` — add `benchmark_secret` config field
- `crates/prx-waf/src/main.rs` — create ModeRegistry, inject into AppState + Engine

## Implementation Steps

### TDD: Write Tests First

1. **Unit tests for ModeRegistry**:
   - Default state: all features `enforce`
   - `set_all(log_only)` → every feature resolves to `log_only`
   - `set_feature("attack_detection", log_only)` → only that feature is `log_only`, others unchanged
   - `set_policy("attack_detection", "sqli", log_only)` → only that policy is `log_only`
   - `set_all(enforce)` clears all overrides

2. **Unit tests for benchmark_secret_guard middleware**:
   - Missing header → 403
   - Wrong value → 403
   - Correct value → passes through

3. **Handler tests for each endpoint**:
   - `GET /capabilities` → returns JSON with features map + active state
   - `POST /reset_state` → returns `{"ok": true, "audit_log_preserved": true}`
   - `POST /set_profile` with `scope: "all"` → mode changed, response confirms
   - `POST /set_profile` with unsupported feature → response includes `unsupported` list
   - `POST /flush_cache` → returns `{"ok": true}`

4. **Integration test: mode toggle affects engine behavior**:
   - Set `attack_detection` to `log_only` via `set_profile`
   - Send SQLi payload → verify `X-WAF-Action: block` + `X-WAF-Mode: log_only` (request not actually blocked)
   - Set back to `enforce` → same payload → request actually blocked

### Implement

5. **Create `ModeRegistry`** with `ArcSwap<ModeState>`:
   - `resolve(feature: &str, policy: Option<&str>) -> InteropMode`
   - `set_all(mode)`, `set_features(features, mode)`, `set_policies(feature, policies, mode)`
   - `snapshot() -> ModeState` for capabilities response

6. **Create `feature_catalog.rs`**:
   - Static mapping of feature names → Phase list + policy names
   - `FeatureCatalog::capabilities() -> HashMap<String, FeatureInfo>`

7. **Create `interop_control_api.rs`**:
   - `benchmark_secret_guard` middleware
   - `capabilities_handler` — reads FeatureCatalog + ModeRegistry snapshot
   - `reset_state_handler` — calls clear on each subsystem component
   - `set_profile_handler` — validates request body, applies to ModeRegistry, returns new state
   - `flush_cache_handler` — delegates to existing cache flush logic

8. **Wire ModeRegistry into engine**:
   - Engine's `inspect()` calls `mode_registry.resolve(feature, policy)` at each detection phase
   - If mode is `LogOnly`: evaluate normally, set `decision.mode = LogOnly`, skip enforcement
   - Replaces the per-host `log_only_mode` boolean check (HostConfig.log_only_mode still works as fallback)

9. **Mount routes** in `server.rs`:
   ```rust
   .nest("/__waf_control", interop_control_routes())
   ```
   No JWT middleware on this group — uses benchmark secret instead.

10. **Add config field** `benchmark_secret`:
    ```toml
    [interop]
    benchmark_secret = "waf-hackathon-2026-ctrl"
    audit_log_path = "./waf_audit.log"
    ```

### Validate

11. `cargo check --workspace`
12. `cargo test --workspace`
13. `cargo clippy --workspace -- -D warnings`
14. Manual: `curl -H "X-Benchmark-Secret: waf-hackathon-2026-ctrl" localhost:9527/__waf_control/capabilities`
15. Manual: toggle mode, send attack payload, verify headers reflect log_only

## Success Criteria

- [ ] `GET /__waf_control/capabilities` returns feature/policy map with modes
- [ ] `POST /__waf_control/reset_state` clears all runtime state, preserves audit log
- [ ] `POST /__waf_control/set_profile` toggles mode per feature/policy/all
- [ ] `POST /__waf_control/flush_cache` clears response cache
- [ ] Missing/wrong `X-Benchmark-Secret` → 403
- [ ] ModeRegistry is ArcSwap — lock-free reads from hot path
- [ ] Engine reads ModeRegistry for per-feature mode resolution
- [ ] `cargo check --workspace` passes
- [ ] All tests pass

## Risk Assessment

| Risk | Impact | Mitigation |
|------|--------|------------|
| ModeRegistry adds latency to hot path | Low | ArcSwap is ~1ns load; HashMap lookup is O(1) amortized |
| Reset state misses a subsystem | High | Enumerate all Arc-shared state in AppState; add reset method to each |
| Feature catalog becomes stale when new detectors added | Medium | Catalog is static const; document that new features must register |
| Benchmark secret hardcoded in contract | Low | Configurable via TOML with contract default |
| set_profile race with concurrent requests | Medium | ArcSwap atomic swap; in-flight requests see old or new state, never partial |
