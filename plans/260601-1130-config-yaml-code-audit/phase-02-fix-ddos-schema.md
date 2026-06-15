---
phase: 2
title: "Fix DDoS Schema"
status: pending
priority: P1
effort: "2h"
dependencies: [1]
---

# Phase 2: Fix DDoS Schema

## Overview

Rewrite `configs/ddos.yaml` to match the `DdosFileConfig` struct. The engine struct is correct and well-tested — the YAML file and admin API endpoint drifted.

## Red-Team Correction

**Watcher not bootstrapped**: `start_ddos_watcher()` (`engine.rs:340`) is never called from `main.rs`. Fixing the YAML alone doesn't change runtime behavior today — this is prep work for when the watcher is wired up. The schema divergence is still real and must be fixed before the TOML migration.

**Serialize gap**: `DdosFileConfig`, `DdosDocument`, `DdosTierMap`, `TierThresholdCfg`, `RedisCfg` do NOT derive `Serialize`. Must add it for the typed API round-trip to work.

## Requirements

- Functional: `configs/ddos.yaml` must parse through `DdosFileConfig::from_path()` without error
- Functional: All DDoS config structs must derive `Serialize` (for API JSON response)
- Functional: Admin API `GET /api/ddos/config` must return the correct schema to the frontend
- Functional: Admin API `PUT /api/ddos/config` must write YAML that the engine can parse
- Non-functional: Hot-reload must work once watcher is bootstrapped

## Architecture

The admin API (`ddos_api.rs`) currently operates on a completely different schema than the engine. Two approaches:

**Option A (recommended)**: Rewrite `ddos_api.rs` to deserialize through `DdosFileConfig` (typed) instead of generic `Value`. The FE receives the engine's canonical schema. This prevents future divergence.

**Option B**: Keep `ddos_api.rs` as a translation layer — read/write the engine schema but present the old FE schema. More work, more maintenance, risk of re-divergence.

## Related Code Files

- Modify: `configs/ddos.yaml` — rewrite to engine schema
- Modify: `crates/waf-api/src/ddos_api.rs` — switch from `Value` to typed `DdosFileConfig`
- Read: `crates/waf-engine/src/checks/ddos/config.rs` — reference struct
- Read: `crates/waf-engine/src/checks/ddos/config.rs:252-270` — reference test YAML

## Implementation Steps

0. Add `#[derive(Serialize)]` to: `DdosDocument`, `DdosFileConfig`, `DdosTierMap`, `TierThresholdCfg`, `RedisCfg` in `crates/waf-engine/src/checks/ddos/config.rs`. Add `use serde::{Deserialize, Serialize};` import.

1. Rewrite `configs/ddos.yaml` to match engine schema:
   ```yaml
   ddos:
     schema_version: 1
     enabled: true
     hot_reload: true
     gc_interval_s: 60
     max_keys: 100000
     tiers:
       critical:
         per_fp_threshold: 50
         per_fp_window_s: 10
         per_tier_threshold: 500
         per_tier_window_s: 10
       high:
         per_fp_threshold: 100
         per_fp_window_s: 10
         per_tier_threshold: 1000
         per_tier_window_s: 10
       medium:
         per_fp_threshold: 200
         per_fp_window_s: 10
         per_tier_threshold: 2000
         per_tier_window_s: 10
       catch_all:
         per_fp_threshold: 500
         per_fp_window_s: 10
         per_tier_threshold: 5000
         per_tier_window_s: 10
   ```
2. Verify: `DdosFileConfig::from_path("configs/ddos.yaml")` succeeds (add a `#[test]` or run in a scratch binary)
3. Rewrite `ddos_api.rs`:
   - `get_ddos_config`: read file → `DdosFileConfig::from_yaml_str()` → serialize to JSON via `serde_json::to_value()`
   - `put_ddos_config`: deserialize JSON body → validate via `DdosFileConfig::validate()` → write YAML via `serde_yaml::to_string()`
   - Remove `yaml_to_fe()`, `default_ddos_fe()` helper functions
4. If the admin panel frontend expects the old schema (`per_ip`, `per_fingerprint`), update the frontend to match the new schema or add a thin FE adapter

## Success Criteria

- [ ] `configs/ddos.yaml` parses through `DdosFileConfig::from_path()` without error
- [ ] `cargo test -p waf-engine -- ddos` passes (existing tests still green)
- [ ] Admin API GET returns engine-schema JSON
- [ ] Admin API PUT writes engine-parseable YAML
- [ ] Hot-reload test: modify file → engine picks up new config

## Risk Assessment

- **FE breakage**: Admin panel may expect old schema fields (`per_ip`, `per_fingerprint`). Need to check `web/admin-panel/src/pages/` for DDoS config page. If FE is form-driven (not raw YAML editor), the form fields need updating too.
- **Threshold mapping**: Old schema had `per_ip.threshold_rps: 100` — new schema maps per-tier `per_fp_threshold`. Need operator input on what tier thresholds should be. The values in step 1 are reasonable defaults.
