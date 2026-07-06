---
phase: 4
title: "Full Verification"
status: completed
priority: P1
dependencies: [1, 2]
---

# Phase 4: Full Verification

## Overview

Gate the plan: full waf-engine suite green, config diff minimal, no naming or
scope leaks.

## Implementation Steps

1. `cargo test -p waf-engine` — entire crate, all new + existing tests.
2. `cargo clippy -p waf-engine --all-targets` and `cargo fmt --check` if the
   repo's usual gates include them (match existing CI expectations; do not
   introduce new gates).
3. `git diff --stat` review:
   - `configs/geo-rules.yaml`: only the id-4 action change.
   - `configs/risk.yaml`: no diff (reverted).
   - Test files: additive changes only.
4. Grep the diff for report IDs (`GEO-`, `RSK-`) in code, test names, and
   comments — none allowed; names must describe behavior.

## Success Criteria

- [x] `cargo test -p waf-engine` green for everything this diff can reach:
      1450/1460 lib tests pass; the 10 failures are pre-existing and
      environmental (9 need the Docker socket for postgres testcontainers —
      permission denied on this machine; 1 is committed
      `configs/device-fp.yaml` carrying an unknown `enabled` field, untouched
      here). geoip_lookup 14/14, geoip_updater_schedule 18/18, geo tests
      22/22, clippy + fmt clean.
<!-- Updated: Validation Session 1 - phase 3 dropped; diff scope narrowed -->
- [x] Diff limited to: `tests/geoip_lookup.rs`, geo_config.rs test module,
      configs/geo-rules.yaml one-line action fix. No fixture was needed.
- [x] Plan acceptance criteria in `plan.md` all check off.

## Risk Assessment

- None beyond upstream phases; this phase only observes.
