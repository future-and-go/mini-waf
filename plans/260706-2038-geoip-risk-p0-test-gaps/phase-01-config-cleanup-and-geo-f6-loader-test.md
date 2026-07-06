---
phase: 1
title: "Config Cleanup and GEO-F6 Loader Test"
status: completed
priority: P1
dependencies: []
---

# Phase 1: Config Cleanup and GEO-F6 Loader Test

<!-- Updated: Validation Session 1 - IR row conversion to block user-confirmed -->

## Overview

Restore the two live config files to committed values, remove the unsupported
legacy `action: challenge` row, and add a loader test documenting that
non-`allow` action rows are enforced as block (fail-safe fallback).

## Requirements

- Functional: config files carry only supported actions (`allow`, `block`);
  loader behavior for unknown actions is pinned by a test.
- Non-functional: no loader code change — behavior at
  `crates/waf-engine/src/checks/geo_config.rs:77` (`if row.action == "allow"`
  else block-union) is intentional and stays.

## Related Code Files

- Modify: `configs/risk.yaml` (revert only)
- Modify: `configs/geo-rules.yaml` (revert, then cleanup edit)
- Modify: `crates/waf-engine/src/checks/geo_config.rs` (test module only)

## Implementation Steps

1. Revert leftover manual tweaks (user decision — they are not pending changes):
   `git checkout -- configs/risk.yaml configs/geo-rules.yaml`.
   This restores `risk.enabled: true`, `min_clean_streak: 12`,
   `ttl_secs: 1808`, and re-enables the CN geo rule.
2. In `configs/geo-rules.yaml`, fix the row with `id: 4` (iso `IR`,
   `action: challenge`): change `action: challenge` → `action: block`.
   The engine only supports `allow`/`block`; today the loader already enforces
   this row as block, so the enforced behavior is unchanged — the file just
   stops lying about it. (Removing the whole row would *change* enforcement;
   keep the block.)
3. In the `#[cfg(test)]` module of `geo_config.rs` (existing inline-YAML tests
   around lines 200–250 show the fixture pattern), add a test:
   - YAML with one row `action: challenge` (enabled, global scope, iso `IR`)
     plus one normal `action: block` row for contrast.
   - Assert the challenge row is NOT dropped: it unions into the Block rule's
     ISO set exactly like a block row (fail-safe: unknown action → block).
   - Suggested name: `unsupported_action_row_falls_back_to_block`.
4. Run `cargo test -p waf-engine geo_config`.

## Success Criteria

- [x] `git diff configs/` shows only the id-4 `challenge` → `block` change.
- [x] New loader test passes; existing geo_config tests unchanged and green.
      (`unsupported_action_row_falls_back_to_block`; 12/12 geo_config tests.)

## Risk Assessment

- Low. Enforcement is identical before/after (loader already blocked the row).
  If admin intent for the IR row was something other than block, that is a
  product decision outside this plan — the user chose cleanup, not removal.
