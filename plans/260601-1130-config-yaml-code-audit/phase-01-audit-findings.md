---
phase: 1
title: "Audit Findings"
status: pending
priority: P1
effort: "0h (documentation only)"
dependencies: []
---

# Phase 1: Audit Findings

## Overview

Complete field-by-field mapping of all 8 YAML config files to their Rust deserialization structs. This phase is documentation-only — captures the verified audit results so subsequent phases have precise fix targets.

## Config-to-Code Mapping

### ✅ challenge.yaml — PASS

| YAML Path | Rust Struct | Field | Type |
|-----------|-------------|-------|------|
| `challenge.enabled` | `ChallengeFileConfig` | `enabled` | `bool` |
| `challenge.type` | `ChallengeFileConfig` | `challenge_type` | `String` (`#[serde(rename)]`) |
| `challenge.difficulty.default` | `DifficultyConfig` | `default` | `u8` |
| `challenge.difficulty.tiers[].min_risk` | `DifficultyTier` | `min_risk` | `u32` |
| `challenge.difficulty.tiers[].max_risk` | `DifficultyTier` | `max_risk` | `u32` |
| `challenge.difficulty.tiers[].difficulty` | `DifficultyTier` | `difficulty` | `u8` |
| `challenge.token.*` | `TokenConfig` | all fields | match |
| `challenge.branding.*` | `BrandingConfig` | all fields | match |
| `challenge.nonce_store.capacity` | `NonceStoreConfig` | `capacity` | `usize` |

**Loading**: `ChallengeFileConfig::from_yaml_str()` → `serde_yaml::from_str()` → validate → `Arc<ChallengeConfig>`
**Hot-reload**: notify watcher + debounce + ArcSwap ✅

### ❌ ddos.yaml — BROKEN (F1)

**Current YAML** (what's on disk + what admin API writes):
```yaml
enabled: true
per_ip:
  threshold_rps: 100
  window_secs: 10
per_fingerprint:
  threshold_rps: 200
  window_secs: 10
ban_durations_secs: [60, 300, 3600]
store:
  backend: memory
```

**Engine expects** (`DdosDocument` → `DdosFileConfig`):
```yaml
ddos:
  schema_version: 1
  enabled: true
  hot_reload: true
  gc_interval_s: 60
  max_keys: 100000
  tiers:
    critical:
      per_fp_threshold: 10
      per_fp_window_s: 60
      per_tier_threshold: 1000
      per_tier_window_s: 60
```

**Why it fails**: `DdosDocument` has `#[serde(deny_unknown_fields)]`. Top-level keys `enabled`, `per_ip`, `per_fingerprint`, `ban_durations_secs`, `store` are unknown → parse error.

**Runtime caveat**: `start_ddos_watcher()` (`engine.rs:340`) is never called from `main.rs` — the file is never loaded today. This is a time bomb, not an active bug. Structs also lack `Serialize`.

**Admin API** (`ddos_api.rs:55-79`): `yaml_to_fe()` reads `per_ip`, `per_fingerprint`, `ban_durations_secs`, `store` — completely different field set than `DdosFileConfig`.

### ✅ device-fp.yaml — PASS

All 30+ fields map correctly. Root key `device_fp:` matches `DeviceFpDocument`. Behavior sub-config at `device_fp.behavior.*` maps to `BehaviorConfig`. Provider names match Rust struct field discrimination. Hot-reload works via notify + ArcSwap.

### ✅ rate-limit.yaml — PASS

Root key `rate_limit:` matches `RateLimitDocument`. All tier fields (`burst_capacity`, `burst_refill_per_s`, `window_secs`, `window_limit`) map to `TierRateLimitCfg`. Redis block optional, commented out. `deny_unknown_fields` present. Minor: `breaker_threshold` missing from YAML comment but has Rust default.

### ❌ relay.yaml — BROKEN (F2)

**Current YAML** (what's on disk + what admin API writes):
```yaml
enabled: false
providers:
  asn_classifier:
    enabled: true
    risk_weight: 15
  tor_exit: ...
  datacenter: ...
  proxy_chain: ...
  xff_validator: ...
intel:
  asn_feed: ...
  tor_feed: ...
  datacenter_set: ...
trusted_proxies: []
risk_weights:
  tor: 30
  datacenter: 15
  bad_asn: 25
```

**Engine expects** (`RelayDetectionDocument` → `RelayConfig`):
```yaml
relay_detection:
  trusted_proxies: []
  max_chain_depth: 3
  headers:
    forwarded_for: ["X-Forwarded-For", "X-Real-IP"]
  asn:
    provider: "ipinfo_lite"
    mmdb_path: ...
  tor:
    list_path: ...
    refresh: ...
  signals:
    enabled: ["tor_exit", "asn_classifier"]
    risk_score_delta:
      tor_exit: 30
      bad_asn: 25
```

**Why it's broken**: `RelayDetectionDocument` has NO `deny_unknown_fields`. All current YAML keys (`enabled`, `providers`, `intel`, `risk_weights`) silently ignored. `relay_detection` field defaults to `RelayConfig::default()`.

**Runtime caveat**: `RelayReloader::start()` never called from `main.rs` — file never loaded today. Time bomb, not active bug. Structs also lack `Serialize`.

**Admin API** (`relay_api.rs`): reads/writes the old schema as generic `Value`. Engine never sees these values.

### ✅ risk.yaml — PASS

Root key `risk:` matches `RiskDocument`. Nested structs: `DecayConfig`, `SeedConfig`, `CanaryConfig`, `StoreConfig` all map correctly. `max_decay: 50` is semantically a floor (not a max) — confusing name but loads correctly. Hot-reload via notify + ArcSwap.

### ⚠️ tier-policies.yaml — ARCHITECTURE ISSUE (F3)

**Admin API** (`tier_policies_api.rs`): reads/writes as generic YAML `Value` — works for FE display.

**Gateway watcher** (`tier_config_watcher.rs:134`): `toml::from_str(&raw)` → `TomlEnvelope { tiered_protection: Option<TierConfig> }`. YAML file will fail TOML parse. Watcher NOT bootstrapped from `main.rs` → no runtime impact today.

**Additional issues if watcher were wired up**:
- Missing `default_tier` (required, no default in `TierConfig`)
- `cache_policy: aggressive` won't deserialize — `CachePolicy` uses `#[serde(tag = "mode")]`, needs `{mode: "aggressive", ttl_seconds: 300}`
- Missing policies for all 4 tiers (validation requires all present)

### ✅ tx-velocity.yaml — PASS

Root key `tx_velocity:` matches `TxVelocityDocument`. All fields map. `EndpointRole` enum uses `#[serde(rename_all = "snake_case")]` — role names in YAML match. `dedupe_window_ms` omitted from YAML but has correct default. Hot-reload works.

## Success Criteria

- [x] All 8 configs mapped field-by-field to Rust structs
- [x] 3 broken configs identified with root cause (F1, F2, F3)
- [x] Admin API vs engine schema divergence documented
- [x] Fix targets identified for phases 2-5
