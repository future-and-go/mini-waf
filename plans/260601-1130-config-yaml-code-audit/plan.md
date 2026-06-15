---
title: "Config YAML-to-Code Audit: Fix Schema Divergence"
description: "Deep audit of 8 configs/ YAML files vs Rust loader structs. Fixes schema mismatches between admin API and engine loaders for ddos, relay, and tier-policies."
status: pending
priority: P1
branch: "main"
tags: ["config", "audit", "bugfix"]
blockedBy: []
blocks: ["260530-2254-configs-yaml-to-toml-migration"]
created: "2026-06-01T04:37:40.261Z"
createdBy: "ck:plan"
source: skill
---

# Config YAML-to-Code Audit: Fix Schema Divergence

## Overview

Deep audit of all 8 YAML config files in `configs/` against their Rust deserialization structs. Found **3 diverged configs** where the YAML on disk does not match the engine's typed struct schema, and **1 architecture inconsistency** (tier-policies format mismatch).

**Runtime impact caveat** (from red-team review): `start_ddos_watcher()` and `RelayReloader::start()` are **never called from `main.rs`** — the engine never loads `configs/ddos.yaml` or `configs/relay.yaml` at startup today. The schema divergence is a **time bomb** (will break when watchers are wired up) rather than an active runtime bug. The tier-policies watcher is also not bootstrapped.

Root cause: admin API endpoints (`waf-api/src/*_api.rs`) read/write generic `serde_json::Value` YAML with one schema, while engine loaders (`waf-engine/src/*/config.rs`) deserialize into typed structs with a completely different schema. The two codepaths were never reconciled. **All 6 config API endpoints** (ddos, relay, risk, device-fp, challenge, tier-policies) use the same `Value`-based anti-pattern with duplicated `resolve_path`/`read_yaml_opt`/`write_yaml` helpers.

## Audit Results

| Config | Engine Load | Admin API | Verdict |
|--------|------------|-----------|---------|
| `challenge.yaml` | ✅ | ✅ | PASS |
| `ddos.yaml` | ❌ hard-fail (`deny_unknown_fields`) | ✅ (different schema) | **BROKEN** |
| `device-fp.yaml` | ✅ | ✅ | PASS |
| `rate-limit.yaml` | ✅ | N/A (no API endpoint for raw YAML) | PASS |
| `relay.yaml` | ⚠️ silently ignored → defaults | ✅ (different schema) | **BROKEN** |
| `risk.yaml` | ✅ | ✅ | PASS |
| `tier-policies.yaml` | N/A (TOML watcher not bootstrapped) | ✅ (YAML `Value`) | **ARCH ISSUE** |
| `tx-velocity.yaml` | ✅ | N/A | PASS |

## Critical Findings

### F1 — DDoS: Admin API vs Engine Schema Mismatch
- **Admin API** (`ddos_api.rs`): writes `{enabled, per_ip, per_fingerprint, ban_durations_secs, store}` — NO `ddos:` wrapper
- **Engine** (`DdosFileConfig`): expects `ddos:` root → `{schema_version, enabled, tiers: {critical: {per_fp_threshold, ...}}}` with `#[serde(deny_unknown_fields)]`
- **Watcher NOT bootstrapped**: `start_ddos_watcher()` (`engine.rs:340`) is never called from `main.rs`. Time bomb, not active bug.
- **Impact when wired up**: Engine parse **hard-fails**; DDoS subsystem falls back to inert default.
- **Serialize gap**: `DdosFileConfig` and nested structs do NOT derive `Serialize` — typed API round-trip requires adding it.
- **Files**: `crates/waf-api/src/ddos_api.rs`, `crates/waf-engine/src/checks/ddos/config.rs`

### F2 — Relay: Admin API vs Engine Schema Mismatch
- **Admin API** (`relay_api.rs`): writes `{enabled, providers: {asn_classifier: ...}, intel: ..., risk_weights: ...}`
- **Engine** (`RelayConfig`): expects `relay_detection:` root → `{trusted_proxies, max_chain_depth, headers, asn, tor, signals}`
- **Watcher NOT bootstrapped**: `RelayReloader::start()` never called from `main.rs`. Time bomb, not active bug.
- **No `deny_unknown_fields`** on `RelayDetectionDocument` → silently parses to defaults
- **Serialize gap**: `RelayConfig` and nested structs do NOT derive `Serialize` — typed API round-trip requires adding it.
- **Files**: `crates/waf-api/src/relay_api.rs`, `crates/waf-engine/src/relay/config.rs`

### F5 — Systemic: All 6 config APIs use Value-based anti-pattern
- `challenge_api.rs`, `risk_api.rs`, `device_fp_api.rs` also use `yaml_to_fe()`/`fe_to_yaml()` manual Value translation
- These happen to produce valid YAML today (they wrap with correct root key), but writes are **unvalidated** — invalid values pass the API and crash the engine on hot-reload
- `resolve_path()`, `read_yaml_opt()`, `write_yaml()` are copy-pasted identically across all 6 files
- Challenge/risk config structs already derive `Serialize`; device-fp needs checking

### F3 — Tier-Policies: TOML/YAML Format Mismatch
- **Admin API** (`tier_policies_api.rs`): reads/writes `configs/tier-policies.yaml` as generic YAML `Value`
- **Gateway watcher** (`tier_config_watcher.rs`): uses `toml::from_str()` with `[tiered_protection]` envelope
- **Watcher NOT bootstrapped** from `main.rs` → not a runtime bug today
- `CachePolicy` uses `#[serde(tag = "mode")]` → YAML bare string `"aggressive"` won't deserialize
- `TierConfig.default_tier` has no default → missing field error
- **Impact**: Will fail when watcher is wired up. Already in scope for `260530-2254-configs-yaml-to-toml-migration`.
- **Files**: `crates/waf-api/src/tier_policies_api.rs`, `crates/gateway/src/tiered/tier_config_watcher.rs`, `crates/waf-common/src/tier.rs`

### F4 — risk.yaml: Semantic Naming Issue (Minor)
- `max_decay: 50` is semantically a **floor** (score can't decay below 50), not a ceiling
- Rust field name matches YAML, so no loading issue — just confusing naming

## Research Reports

- [Researcher 1: challenge + ddos + rate-limit](../reports/researcher-260601-1131-yaml-rust-config-audit-report.md)
- [Researcher 2: device-fp + relay + tx-velocity](../reports/researcher-260601-1131-config-audit-yaml-vs-rust-structs-report.md)
- [Researcher 3: risk + tier-policies](../reports/researcher-260601-1132-config-yaml-to-rust-audit-report.md)

## Phases

| Phase | Name | Status | Priority |
|-------|------|--------|----------|
| 1 | [Audit Findings](./phase-01-audit-findings.md) | Pending | P1 |
| 2 | [Fix DDoS Schema](./phase-02-fix-ddos-schema.md) | Pending | P1 |
| 3 | [Fix Relay Schema](./phase-03-fix-relay-schema.md) | Pending | P1 |
| 4 | [Fix Tier-Policies Schema](./phase-04-fix-tier-policies-schema.md) | Pending | P2 |
| 5 | [Reconcile Admin API](./phase-05-reconcile-admin-api.md) | Pending | P1 |
| 6 | [Regression Tests](./phase-06-regression-tests.md) | Pending | P1 |

## Dependencies

- **Blocks**: `260530-2254-configs-yaml-to-toml-migration` — schema must be correct before migrating format
- No blockers

## Key Decisions

1. **Fix YAML to match engine structs** (not the other way around). Engine structs are correct, tested, and validated. YAML files and admin API endpoints are the ones that drifted.
2. **Admin API endpoints must round-trip through typed structs**, not generic `Value`. This prevents future divergence. Requires adding `#[derive(Serialize)]` to DDoS and Relay config structs.
3. **tier-policies fix deferred to TOML migration plan** — watcher isn't bootstrapped, no runtime impact today.
4. **Frontend pages must be updated** in lockstep — `ddos-protection/`, `relay-intel/`, `tier-policies/` pages hardcode the old schema field names.

## Red-Team Corrections Applied

| Finding | Severity | Resolution |
|---------|----------|------------|
| F-1: DDoS watcher not bootstrapped | FATAL | Corrected impact assessment. YAML fix is prep for bootstrap. |
| F-2: Relay watcher not bootstrapped | FATAL | Same. |
| F-3: `Serialize` not derived on DDoS/Relay structs | FATAL | Added to Phase 2/3 scope. |
| H-1: Frontend 3-page rewrite unscoped | HIGH | Noted in Key Decision #4. FE changes out of scope for this plan — they belong in a separate FE task. |
| H-2: risk/device-fp/challenge APIs same anti-pattern | HIGH | Added finding F5. Typed round-trip for these deferred (they work today). |
| H-3: TOML migration plan conflict | HIGH | Sequencing noted in Dependencies. |
| M-3: `deny_unknown_fields` missing on RelayDetectionDocument | MEDIUM | Added to Phase 3. |
| M-5: Duplicated helpers across 6 API files | MEDIUM | Noted for future DRY pass. |

## Validated Scope Decisions

1. **Schema-only** — no watcher bootstrap. Leave wiring `start_ddos_watcher()` / `RelayReloader::start()` into `main.rs` for a separate plan.
2. **Backend-only** — FE page updates (`ddos-protection/`, `relay-intel/`, `tier-policies/`) are a separate task. Admin API may need to temporarily serve both old and new schemas if FE isn't updated simultaneously.
3. **Fix ddos + relay only** — risk/device-fp/challenge APIs have the same anti-pattern but work today. Don't fix what isn't broken.

## Unresolved Questions

1. Are DDoS/Relay watchers intentionally not bootstrapped (future phase) or oversight? The `OnceLock` + fully-built watcher API in `engine.rs` suggests they were meant to be wired in.
