---
title: GeoIP & Risk Engine P0 Test Gaps
description: >-
  Close the two real P0 test gaps from the geoip/risk-engine scenario catalog:
  legacy challenge-action config cleanup + loader fallback test, and
  service-level geoip reload preservation. The two risk-side P0 items
  (whitelist-vs-canary ordering, canary-to-ban-table TTL) were found already
  covered during validation and dropped.
status: completed
priority: P1
branch: main-harness
tags:
  - tests
  - 'area:engine'
  - geoip
  - risk
  - p0
blockedBy: []
blocks: []
created: '2026-07-06T13:44:20.633Z'
createdBy: 'ck:plan'
source: skill
---

# GeoIP & Risk Engine P0 Test Gaps

## Overview

Tracking issue: https://github.com/future-and-go/mini-waf/issues/250

Source: `plans/reports/test-scenarios-260706-1540-geoip-risk-engine-report.md`
(scenario catalog for `crates/waf-engine/src/{geoip.rs, geoip_updater.rs,
checks/geo*.rs}` and `crates/waf-engine/src/risk/**`).

Scope (user decision 2026-07-06): **P0 gaps only** —

| Report ID | Gap | Phase |
|-----------|-----|-------|
| GEO-F6 | Legacy `action: challenge` row silently enforced as block; live `configs/geo-rules.yaml` id 4 (IR) affected | 1 |
| GEO-L6 | Service-level: failed `reload()` must preserve the working searcher | 2 |
| RSK-SE2 | Whitelisted IP hitting canary path must still Allow (ordering) | 3 — dropped, already covered by `src/risk/tests/canary.rs::whitelist_bypasses_canary` |
| RSK-C1 | Canary hit must insert IP into `DynamicBanTable` with configured TTL | 3 — dropped, already covered by `src/risk/tests/canary.rs::{canary_path_triggers_block_and_score_100, canary_pin_expires_after_ttl}` |

User decisions baked in:

1. **GEO-F6**: `challenge` is not supported by waf-engine → **convert the
   id-4 row to `action: block`** (validated: enforcement unchanged; do not
   delete the row). Loader stays as-is (non-`allow` → block fail-safe); add a
   test documenting that fallback.
2. **Working-tree config edits** (`risk.enabled: false`, `min_clean_streak: 15`,
   `ttl_secs: 1810`, CN rule disabled): leftover manual tweaks → **revert to
   committed values** before the cleanup edit.
3. Redis scenarios (RSK-ST1/ST2) are **out of scope** — already covered by
   in-progress plan `260704-2309-gh-198-redis-riskstate-roundtrip` (Valkey CI
   service container + Lua fixes).

Naming rule: test names describe behavior; no report IDs (GEO-F6 etc.) in test
names, comments, or commit messages.

## Phases

| Phase | Name | Status |
|-------|------|--------|
| 1 | [Config Cleanup and GEO-F6 Loader Test](./phase-01-config-cleanup-and-geo-f6-loader-test.md) | Completed |
| 2 | [GeoIP Reload Preserve Service Test](./phase-02-geoip-reload-preserve-service-test.md) | Completed |
| 3 | [Risk Scorer Canary P0 Tests](./phase-03-risk-scorer-canary-p0-tests.md) | Completed |
| 4 | [Full Verification](./phase-04-full-verification.md) | Completed |

Phases 1–2 are independent (different files); phase 3 was closed at
validation with no work (coverage pre-existed); phase 4 gates completion.

## Dependencies

- No `blockedBy`: the P0 scope shares no files with in-progress
  `260704-2309-gh-198-redis-riskstate-roundtrip`. That plan owns all Redis
  store scenarios; do not duplicate them here.

## Acceptance Criteria

- [x] `configs/risk.yaml` and `configs/geo-rules.yaml` restored to committed
      values; the only new config change is the legacy `challenge` row cleanup.
- [x] Loader test proves a non-`allow` action row is enforced as block (fail-safe).
- [x] Service-level test proves failed geoip reload returns `Err` naming the
      family while lookups keep working on the old searcher.
- [x] Whitelist-before-canary ordering and canary→ban-table TTL: covered by
      pre-existing tests in `src/risk/tests/canary.rs` (verified at
      validation; no new tests needed).
- [x] `cargo test -p waf-engine` green apart from 10 pre-existing failures
      unrelated to this diff (9 need Docker for postgres testcontainers —
      socket permission denied on this machine; 1 committed
      `configs/device-fp.yaml` parse issue). No unrelated diffs.

## Validation Log

### Session 1 — 2026-07-06

#### Verification Results

- Claims checked: 20 | Verified: 18 | Failed: 2 | Unverified: 0
- Tier: Standard (Fact Checker + Contract Verifier; 4 phases)
- Failures:
  - Phase 3 claim "no test covers whitelist-vs-canary ordering" — FAILED:
    `crates/waf-engine/src/risk/tests/canary.rs:374`
    (`whitelist_bypasses_canary`) asserts Allow + score 0 + no ban entry.
  - Phase 3 claim "no test covers canary→ban-table TTL" — FAILED:
    `crates/waf-engine/src/risk/tests/canary.rs:119` and `:177`
    (`canary_path_triggers_block_and_score_100`,
    `canary_pin_expires_after_ttl`) assert insertion and TTL expiry.
  - Root cause: the source scenario report checked
    `tests/ddos_risk_bump_acceptance.rs` / `tests/risk_scorer_extended.rs`
    but not `src/risk/tests/canary.rs` (it also cites a nonexistent test name
    `canary_path_forces_block_with_pin`).
- Notable verified contracts: reload error names the family
  (`geoip.rs:98` "GeoIP reload: new load failed for …"); loader fallback at
  `geo_config.rs:77`; `DynamicBanTable::contains(ip, now_ms)` (`ban.rs:101`);
  `minimal_xdb_bytes()` fails ip2region validation by design
  (`geoip_updater_schedule.rs:137-144`).

#### Decisions

1. Phase 3 dropped (user-confirmed): coverage pre-exists; phase marked
   completed with no work.
2. IR row (geo-rules id 4): convert `action: challenge` to the supported
   `block` (user-confirmed) — enforcement unchanged; do not delete the row.
3. xdb fixture fallback (user-confirmed): committing a small (<100 KB) binary
   fixture under `crates/waf-engine/tests/fixtures/` is acceptable if a
   handcrafted valid-bytes helper cannot satisfy ip2region validation.

### Whole-Plan Consistency Sweep

- Updated: frontmatter description, P0 scope table, phase-independence note,
  acceptance criteria, phase-03 body (closed-as-covered record), phase-04
  dependencies/diff expectations.
- Source report `plans/reports/test-scenarios-260706-1540-geoip-risk-engine-report.md`
  carries the stale RSK-SE2/RSK-C1 gap rows; a correction note was appended
  there rather than editing its dated tables.
- No unresolved contradictions.
