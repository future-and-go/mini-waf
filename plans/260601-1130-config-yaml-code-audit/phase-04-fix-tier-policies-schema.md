---
phase: 4
title: "Fix Tier-Policies Schema"
status: pending
priority: P2
effort: "1h"
dependencies: [1]
---

# Phase 4: Fix Tier-Policies Schema

## Overview

Fix `configs/tier-policies.yaml` to be consistent with the `TierConfig` struct. The gateway's `tier_config_watcher.rs` is NOT bootstrapped yet (no runtime bug), but the YAML on disk should still represent valid config even if only the admin API reads it today.

This phase does NOT switch the watcher from TOML to YAML — that's deferred to `260530-2254-configs-yaml-to-toml-migration`. It only fixes the YAML content to match `TierConfig` semantics.

## Requirements

- Functional: `configs/tier-policies.yaml` content must be semantically valid per `TierConfig`
- Functional: Add `default_tier` field
- Functional: Fix `cache_policy` to tagged enum structure
- Non-functional: Admin API continues working (it reads generic `Value`, so any valid YAML works)

## Related Code Files

- Modify: `configs/tier-policies.yaml` — fix content
- Read: `crates/waf-common/src/tier.rs` — `TierConfig`, `CachePolicy`, `TierPolicy` structs
- Read: `crates/gateway/src/tiered/tier_config_watcher.rs:183-214` — test TOML fixtures showing correct structure
- Read: `crates/waf-api/src/tier_policies_api.rs` — admin API (reads generic `Value`)

## Implementation Steps

1. Rewrite `configs/tier-policies.yaml`:
   ```yaml
   default_tier: catch_all
   classifier_rules: []
   policies:
     critical:
       fail_mode: close
       ddos_threshold_rps: 50
       cache_policy:
         mode: no_cache
       risk_thresholds:
         allow: 20
         challenge: 60
         block: 85
     high:
       fail_mode: close
       ddos_threshold_rps: 200
       cache_policy:
         mode: default
         ttl_seconds: 300
       risk_thresholds:
         allow: 20
         challenge: 60
         block: 85
     medium:
       fail_mode: open
       ddos_threshold_rps: 500
       cache_policy:
         mode: short_ttl
         ttl_seconds: 120
       risk_thresholds:
         allow: 20
         challenge: 60
         block: 85
     catch_all:
       fail_mode: open
       ddos_threshold_rps: 1000
       cache_policy:
         mode: aggressive
         ttl_seconds: 600
       risk_thresholds:
         allow: 20
         challenge: 60
         block: 85
   ```
2. Verify the admin API still works: `GET /api/tier-policies` returns the updated structure
3. Update `tier_policies_api.rs:51-68` (`default_tier_config()`) to include `default_tier` and tagged `cache_policy`
4. Consider: add `deny_unknown_fields` to `RelayDetectionDocument` to prevent silent field drops (separate commit)

## Success Criteria

- [ ] `configs/tier-policies.yaml` includes `default_tier: catch_all`
- [ ] All `cache_policy` values use tagged struct format `{mode: ..., ttl_seconds: ...}`
- [ ] Admin API GET/PUT still works
- [ ] `default_tier_config()` in `tier_policies_api.rs` updated to match

## Risk Assessment

- **FE breakage**: Admin panel may render `cache_policy` as a dropdown (string `"aggressive"`). If it expects a plain string instead of `{mode: "aggressive", ttl_seconds: 600}`, the FE needs updating. Check `web/admin-panel/src/pages/` for tier-policies page.
- **Low risk overall**: Watcher not bootstrapped, admin API reads generic `Value`. Changes here are cosmetic correctness until the TOML migration wires up the watcher.
