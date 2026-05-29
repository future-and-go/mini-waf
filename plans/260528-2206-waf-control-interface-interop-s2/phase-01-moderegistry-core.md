---
phase: 1
title: "ModeRegistry Core"
status: completed
priority: P1
effort: "4-6h"
dependencies: []
---

# Phase 1: ModeRegistry Core

## Overview

Build the `ModeRegistry` — a lock-free, ArcSwap-backed runtime mode state that tracks enforce/log_only per feature and per policy. This is the foundation for `set_profile` (Phase 5) and `capabilities` (Phase 3). The engine's hot path reads this instead of `HostConfig.log_only_mode`.

## Context Links

- Architecture report: `plans/reports/researcher-260528-2206-waf-control-interface-architecture-patterns-report.md` §1
- Contract §2.5: `analysis/docs/EN_waf_interop_contract_v2.3.md` lines 132–259
- Existing ArcSwap usage: `crates/waf-engine/src/risk/reload.rs`
- Existing pattern: `crates/waf-engine/src/checks/rate_limit/` (hot-reloadable config via ArcSwap)

## Requirements

**Functional:**
- `InteropMode` enum: `Enforce`, `LogOnly` with serde + contract string conversion
- `ModeState`: default mode + feature override map + policy override map
- `ModeRegistry`: ArcSwap wrapper with lock-free `resolve()` and atomic `apply()`
- Hierarchical resolution: policy override > feature override > default mode
- `FeatureCatalog`: static mapping of WAF detection phases → contract feature/policy names
- `FeatureInfo`: per-feature metadata (supported, toggleable, policies list)

**Non-functional:**
- `resolve()` must be < 5ns (single ArcSwap load + 2 HashMap lookups)
- Zero heap allocation on the read path
- `Send + Sync` for cross-thread sharing

## Architecture

```
ModeRegistry (Arc)
  └─ ArcSwap<ModeState>
       ├─ default_mode: InteropMode          // "enforce" | "log_only"
       ├─ feature_overrides: HashMap<String, InteropMode>  // "injection_control" → LogOnly
       └─ policy_overrides: HashMap<String, InteropMode>   // "injection_control.sqli" → LogOnly

Resolution order (first match wins):
  1. policy_overrides["feature.policy"]
  2. feature_overrides["feature"]
  3. default_mode
```

## Related Code Files

**Create:**
- `crates/waf-engine/src/interop/mod.rs` — module root, re-exports
- `crates/waf-engine/src/interop/mode_registry.rs` — ModeRegistry + ModeState + InteropMode
- `crates/waf-engine/src/interop/feature_catalog.rs` — FeatureCatalog + FeatureInfo

**Modify:**
- `crates/waf-engine/src/lib.rs` — add `pub mod interop;`
- `crates/waf-engine/Cargo.toml` — no new deps (arc-swap already in workspace)

## Implementation Steps

### TDD: Write Tests First

1. Create `crates/waf-engine/tests/interop_mode_registry.rs`:

```rust
// Test: default state returns Enforce for all features
#[test]
fn default_mode_is_enforce() {
    let reg = ModeRegistry::new();
    assert_eq!(reg.resolve("injection_control", None), InteropMode::Enforce);
    assert_eq!(reg.resolve("rate_limiting", Some("per_ip")), InteropMode::Enforce);
}

// Test: set_all(LogOnly) switches everything
#[test]
fn set_all_log_only() {
    let reg = ModeRegistry::new();
    reg.set_all(InteropMode::LogOnly);
    assert_eq!(reg.resolve("injection_control", None), InteropMode::LogOnly);
    assert_eq!(reg.resolve("rate_limiting", Some("per_ip")), InteropMode::LogOnly);
}

// Test: set_all(Enforce) clears all overrides (contract §2.5 line 186)
#[test]
fn set_all_enforce_clears_overrides() {
    let reg = ModeRegistry::new();
    reg.set_feature("injection_control", InteropMode::LogOnly);
    reg.set_policy("injection_control", "sqli", InteropMode::LogOnly);
    reg.set_all(InteropMode::Enforce);
    let snap = reg.snapshot();
    assert!(snap.feature_overrides.is_empty());
    assert!(snap.policy_overrides.is_empty());
    assert_eq!(snap.default_mode, InteropMode::Enforce);
}

// Test: feature override takes precedence over default
#[test]
fn feature_override_over_default() {
    let reg = ModeRegistry::new();
    reg.set_feature("injection_control", InteropMode::LogOnly);
    assert_eq!(reg.resolve("injection_control", None), InteropMode::LogOnly);
    assert_eq!(reg.resolve("rate_limiting", None), InteropMode::Enforce); // unchanged
}

// Test: policy override takes precedence over feature override
#[test]
fn policy_override_over_feature() {
    let reg = ModeRegistry::new();
    reg.set_feature("injection_control", InteropMode::LogOnly);
    reg.set_policy("injection_control", "xss", InteropMode::Enforce);
    assert_eq!(reg.resolve("injection_control", Some("sqli")), InteropMode::LogOnly);  // feature
    assert_eq!(reg.resolve("injection_control", Some("xss")), InteropMode::Enforce);   // policy
}

// Test: snapshot returns current state for capabilities
#[test]
fn snapshot_reflects_overrides() {
    let reg = ModeRegistry::new();
    reg.set_feature("bot_detection", InteropMode::LogOnly);
    let snap = reg.snapshot();
    assert_eq!(snap.feature_overrides.get("bot_detection"), Some(&InteropMode::LogOnly));
}

// Test: InteropMode serde round-trip
#[test]
fn interop_mode_serde() {
    assert_eq!(InteropMode::Enforce.as_contract_str(), "enforce");
    assert_eq!(InteropMode::LogOnly.as_contract_str(), "log_only");
    assert_eq!(InteropMode::from_contract_str("enforce"), Some(InteropMode::Enforce));
    assert_eq!(InteropMode::from_contract_str("log_only"), Some(InteropMode::LogOnly));
    assert_eq!(InteropMode::from_contract_str("invalid"), None);
}

// Test: concurrent reads and writes don't panic or corrupt
#[test]
fn concurrent_access() {
    let reg = Arc::new(ModeRegistry::new());
    let handles: Vec<_> = (0..8).map(|i| {
        let r = Arc::clone(&reg);
        std::thread::spawn(move || {
            for _ in 0..1000 {
                if i % 2 == 0 {
                    r.set_feature("injection_control", InteropMode::LogOnly);
                } else {
                    let _ = r.resolve("injection_control", Some("sqli"));
                }
            }
        })
    }).collect();
    for h in handles { h.join().unwrap(); }
}
```

2. Create `crates/waf-engine/tests/interop_feature_catalog.rs`:

```rust
// Test: catalog has all expected features
#[test]
fn catalog_contains_core_features() {
    let cat = FeatureCatalog::all();
    assert!(cat.contains_key("access_control"));
    assert!(cat.contains_key("injection_control"));
    assert!(cat.contains_key("rate_limiting"));
    assert!(cat.contains_key("ddos_protection"));
    assert!(cat.contains_key("bot_detection"));
    assert!(cat.contains_key("owasp_rules"));
    assert!(cat.contains_key("custom_rules"));
}

// Test: each feature has at least one policy
#[test]
fn all_features_have_policies() {
    for (name, info) in FeatureCatalog::all() {
        assert!(!info.policies.is_empty(), "feature {name} has no policies");
        assert!(info.supported, "feature {name} is not supported");
    }
}

// Test: feature_exists and policy_exists
#[test]
fn feature_and_policy_existence_checks() {
    assert!(FeatureCatalog::feature_exists("injection_control"));
    assert!(!FeatureCatalog::feature_exists("nonexistent"));
    assert!(FeatureCatalog::policy_exists("injection_control", "sqli"));
    assert!(!FeatureCatalog::policy_exists("injection_control", "nonexistent"));
}
```

### Implement

3. Create `crates/waf-engine/src/interop/mod.rs`:
   - `pub mod mode_registry;`
   - `pub mod feature_catalog;`
   - Re-export: `ModeRegistry`, `ModeState`, `InteropMode`, `FeatureCatalog`, `FeatureInfo`

4. Create `crates/waf-engine/src/interop/mode_registry.rs`:
   - `InteropMode` enum with `Enforce`, `LogOnly` variants
   - `as_contract_str() -> &'static str` and `from_contract_str(s: &str) -> Option<Self>`
   - Derive `Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize`
   - `ModeState` struct: `default_mode`, `feature_overrides: HashMap<String, InteropMode>`, `policy_overrides: HashMap<String, InteropMode>`
   - `ModeRegistry` struct wrapping `Arc<ArcSwap<ModeState>>`
   - `resolve(feature: &str, policy: Option<&str>) -> InteropMode` — hot path, lock-free
   - `set_all(mode)` — sets default, clears both override maps
   - `set_feature(feature, mode)` — adds/updates feature override
   - `set_features(features: &[&str], mode)` — batch feature override
   - `set_policy(feature, policy, mode)` — adds/updates policy override (key: `"feature.policy"`)
   - `set_policies(feature, policies: &[&str], mode)` — batch policy override
   - `snapshot() -> ModeState` — clone current state for responses
   - `reset()` — returns to default state (all Enforce, no overrides)

5. Create `crates/waf-engine/src/interop/feature_catalog.rs`:
   - `FeatureInfo` struct: `supported: bool`, `toggleable: bool`, `policies: Vec<&'static str>`
   - `FeatureCatalog` with `all() -> HashMap<&'static str, FeatureInfo>`
   - `feature_exists(name: &str) -> bool`
   - `policy_exists(feature: &str, policy: &str) -> bool`
   - `validate_features(names: &[String]) -> (Vec<String>, Vec<String>)` → (supported, unsupported)
   - `validate_policies(feature: &str, names: &[String]) -> (Vec<String>, Vec<String>)`
   - Static catalog mapping (see Feature Catalog section below)

6. Add `pub mod interop;` to `crates/waf-engine/src/lib.rs`

### Validate

7. `cargo check --workspace`
8. `cargo test -p waf-engine --test interop_mode_registry --test interop_feature_catalog`
9. `cargo clippy --workspace -- -D warnings`

## Feature Catalog

| Feature Name | Policies | Detection Phases |
|-------------|----------|-----------------|
| `access_control` | `ip_whitelist`, `ip_blacklist`, `url_whitelist`, `url_blacklist` | 1-4 |
| `injection_control` | `sqli`, `xss`, `rce` | 9, 10, 16 |
| `path_traversal` | `dir_traversal` | 11 |
| `network_protection` | `ssrf`, `header_injection` | 12, 13 |
| `rate_limiting` | `per_ip`, `per_session` | 5 |
| `ddos_protection` | `per_ip_burst`, `per_tier` | 19 |
| `bot_detection` | `scanner`, `bot` | 7, 8 |
| `owasp_rules` | `core_ruleset` | 13 |
| `custom_rules` | `yaml_rules`, `rhai_scripts`, `wasm_plugins` | 12 |
| `geo_protection` | `geo_blocking` | 17 |
| `data_protection` | `sensitive_data`, `anti_hotlink` | 14, 15 |
| `reputation` | `crowdsec`, `community_blocklist` | 16a, 18 |
| `risk_assessment` | `cumulative_risk` | 21 |
| `velocity_control` | `tx_velocity` | 6a |
| `device_intelligence` | `fingerprint_analysis` | 24 |
| `auth_protection` | `brute_force` | 14 |
| `payload_protection` | `body_abuse` | 15 |

## Success Criteria

- [ ] `InteropMode` enum with contract string conversion
- [ ] `ModeRegistry` with ArcSwap — lock-free `resolve()`
- [ ] Hierarchical resolution: policy > feature > default
- [ ] `set_all()` clears overrides (contract §2.5 line 186)
- [ ] `FeatureCatalog` maps all 17 detection features
- [ ] `validate_features()` / `validate_policies()` report unsupported items
- [ ] Concurrent read/write test passes
- [ ] `cargo check --workspace` passes
- [ ] All tests pass

## Risk Assessment

| Risk | Impact | Mitigation |
|------|--------|------------|
| HashMap clone on write path | Low | Writes are rare control-plane ops (~1/min max) |
| Feature catalog staleness | Medium | Document that new detectors must register in catalog |
| ArcSwap memory leak | None | Old Arc deallocated when last reader drops reference |
