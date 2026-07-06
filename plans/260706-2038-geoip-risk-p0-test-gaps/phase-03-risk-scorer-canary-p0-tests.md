---
phase: 3
title: Risk Scorer Canary P0 Tests
status: completed
priority: P1
dependencies: []
---

# Phase 3: Risk Scorer Canary P0 Tests

<!-- Updated: Validation Session 1 - phase dropped; coverage already exists -->

## Overview

**Closed without work — validation found both planned tests already exist.**
The scenario report marked these as gaps after checking
`tests/ddos_risk_bump_acceptance.rs` and `tests/risk_scorer_extended.rs`, but
the coverage lives in `crates/waf-engine/src/risk/tests/canary.rs`:

- Whitelist-vs-canary ordering: `whitelist_bypasses_canary` (line 374) —
  seed-whitelisted IP on a canary path gets Allow, score 0, and no ban-table
  entry.
- Canary → ban table with TTL: `canary_path_triggers_block_and_score_100`
  (line 119) asserts `ban_table.contains(ip, now_ms)` after a hit;
  `canary_pin_expires_after_ttl` (line 177) asserts the entry expires at
  `now_ms + ttl*1000 + 1`.

No new tests to write. User confirmed dropping this phase
(validation session 1, 2026-07-06).

## Success Criteria

- [x] Existing coverage verified at the cited locations; nothing added.
