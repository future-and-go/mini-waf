---
phase: 1
title: "TDD Feature Identity Map"
status: pending
priority: P0
effort: "1h"
dependencies: []
---

# Phase 1: TDD Feature Identity Map

## Overview

Create a central mapping from `Phase` enum → `(feature, policy)` catalog identifiers. This mapping is the bridge between checker detections and ModeRegistry's per-feature mode resolution. Tests first, then implementation.

## Requirements

- Functional: Every `Phase` variant maps to a valid `FeatureCatalog` feature+policy pair
- Non-functional: Pure function, zero allocation (returns `&'static str`), exhaustive match (compiler enforces new phases get mapped)

## Architecture

```
Phase enum (waf-common/types.rs)
  └── phase_feature_identity(phase) → (&'static str, Option<&'static str>)
        └── Used by engine.apply_mode() to call mode_registry.resolve(feature, policy)
```

New file in `crates/waf-engine/src/interop/checker_feature_map.rs` — colocated with `feature_catalog.rs` and `mode_registry.rs`.

## Phase→Feature Mapping Table

| Phase | Feature | Policy |
|-------|---------|--------|
| `IpWhitelist` | `access_control` | `ip_whitelist` |
| `IpBlacklist` | `access_control` | `ip_blacklist` |
| `UrlWhitelist` | `access_control` | `url_whitelist` |
| `UrlBlacklist` | `access_control` | `url_blacklist` |
| `SqlInjection` | `injection_control` | `sqli` |
| `Xss` | `injection_control` | `xss` |
| `Rce` | `injection_control` | `rce` |
| `Scanner` | `bot_detection` | `scanner` |
| `DirTraversal` | `path_traversal` | `dir_traversal` |
| `Bot` | `bot_detection` | `bot` |
| `RateLimit` | `rate_limiting` | `per_ip` |
| `CustomRule` | `custom_rules` | `None` |
| `Owasp` | `owasp_rules` | `core_ruleset` |
| `Sensitive` | `data_protection` | `sensitive_data` |
| `AntiHotlink` | `data_protection` | `anti_hotlink` |
| `CrowdSec` | `reputation` | `crowdsec` |
| `GeoIp` | `geo_protection` | `geo_blocking` |
| `Community` | `reputation` | `community_blocklist` |
| `Ddos` | `ddos_protection` | `per_ip_burst` |
| `RiskScore` | `risk_assessment` | `cumulative_risk` |
| `Ssrf` | `network_protection` | `ssrf` |
| `HeaderInjection` | `network_protection` | `header_injection` |
| `BruteForce` | `auth_protection` | `brute_force` |
| `RequestBodyAbuse` | `payload_protection` | `body_abuse` |

**Notes:**
- `CustomRule` → policy=None because custom rules span yaml/rhai/wasm — cannot determine at the Phase level. Feature-level mode resolution is sufficient.
- `RateLimit` → `per_ip` as default policy. Rate-limit doesn't distinguish per_ip vs per_session at the Phase level.
- `RiskScore` → mapped for completeness but risk scoring doesn't produce block decisions (signal-only).
- `velocity_control` and `device_intelligence` catalog features have NO Phase mapping — they are signal-only subsystems that don't produce block decisions. This is expected, not a gap.

## Related Code Files

- Create: `crates/waf-engine/src/interop/checker_feature_map.rs`
- Modify: `crates/waf-engine/src/interop/mod.rs` (add `pub mod checker_feature_map;`)
- Create: `crates/waf-engine/tests/checker_feature_map.rs`
- Read: `crates/waf-common/src/types.rs` (Phase enum, lines 412-450)
- Read: `crates/waf-engine/src/interop/feature_catalog.rs` (validation helpers)

## Implementation Steps

### TDD: Write Tests First

1. Create `crates/waf-engine/tests/checker_feature_map.rs`
2. Write test `every_phase_maps_to_valid_catalog_feature` — iterate all Phase variants, call `phase_feature_identity()`, validate feature exists via `FeatureCatalog::feature_exists()`
3. Write test `every_phase_policy_is_valid` — for phases with `Some(policy)`, validate via `FeatureCatalog::policy_exists(feature, policy)`
4. Write test `signal_only_phases_documented` — verify `RiskScore` mapping has a comment noting it's signal-only. (`velocity_control` and `device_intelligence` have no Phase at all — no mapping needed.)
5. Run tests — they should fail (function doesn't exist yet)

### Implement

6. Create `crates/waf-engine/src/interop/checker_feature_map.rs`
7. Implement `pub fn phase_feature_identity(phase: Phase) -> (&'static str, Option<&'static str>)` with exhaustive match
8. Add `pub mod checker_feature_map;` to `crates/waf-engine/src/interop/mod.rs`
9. Run `cargo check -p waf-engine` — verify compiles
10. Run tests — all should pass

## Success Criteria

- [ ] `phase_feature_identity()` exhaustively matches all 24 Phase variants
- [ ] Every returned feature name exists in `FeatureCatalog`
- [ ] Every returned policy (when Some) is valid for its feature
- [ ] Compiler will error if a new Phase variant is added without mapping
- [ ] `cargo check -p waf-engine` passes
- [ ] All unit tests pass

## Risk Assessment

- **Low risk:** Pure mapping function with no side effects. Exhaustive match ensures compile-time completeness.
- **Edge case:** `CustomRule` phase can't determine policy (yaml vs rhai vs wasm) — use `None` for feature-level resolution only.
