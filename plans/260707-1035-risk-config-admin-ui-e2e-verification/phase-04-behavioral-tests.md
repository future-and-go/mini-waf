---
phase: 4
title: "Behavioral suite (effect, >=2 values)"
status: complete
priority: P1
dependencies: [2, 3]
---

# Phase 4: Behavioral suite — setting effects across values

## Overview
Prove each observable setting actually *changes behavior*, at ≥2 values, with the
observed data-plane evidence logged. Uses the phase-1 score-raise mechanism and
the phase-2 fixture. Gated by phase-1 go/no-go; degradation path applies.

## Requirements
- Functional: behavioral assertions for `enabled`, canary (`paths`/`enabled`/
  `ban_ttl_secs`), `ttl_secs`, `decay`, `credit/clear`.
- Functional: each uses ≥2 values showing divergent behavior.
- Non-functional: observed header values / statuses logged as evidence; slow
  tests use small values (≈3-5s waits).

## Architecture
Evidence via `X-WAF-Risk-Score` / `X-WAF-Action` (header-value helper from
phase 3), status codes, and score sequences. PUT changes config, wait for
hot-reload, re-observe.

Test groups:
- **`enabled`**: on → risky request has `X-WAF-Risk-Score>0` + enforced action;
  off → no risk score/action. Evidence: header diff.
- **`canary.paths` / `canary.enabled`**: `/trap`→block, `/safe`→pass; PUT swap
  paths → behavior swaps; disabled → `/trap` passes. Evidence: status + action
  per path per config.
- **`canary.ban_ttl_secs`** (small ≈3s): hit trap from IP → same IP next request
  blocked (banned) → wait > ttl → unbanned. Evidence: blocked→allowed transition.
- **`ttl_secs`** (small ≈3s): raise score → confirm elevated → idle-wait > ttl →
  score back to baseline. Evidence: before/after score.
- **`decay`** (`min_clean_streak` small, `decay_rate` set, `max_decay` low):
  raise score → clean requests → score steps down, floors at `max_decay`;
  second run `decay_rate:0` → score constant. Evidence: score sequence.
- **`credit`/`clear`**: raise score for IP → POST credit `{amount:25}` → score
  drops by 25; POST clear → `removed:true` + score gone. Evidence: score deltas.

## Related Code Files
- Modify: `tests/e2e/run-risk-config.sh` (append behavioral groups)
- Read: phase-1 `reports/spike-findings.md` (exact score-raise request)
- Read: `crates/waf-engine/src/risk/decay.rs` (decay semantics for expected values)

## Implementation Steps
1. Add header-value evidence helper (if not added in phase 3).
2. Implement `enabled` on/off group.
3. Implement canary groups (paths swap, enabled toggle, ban_ttl expiry).
4. Implement `ttl_secs` expiry group (small ttl).
5. Implement decay group (two decay_rate values).
6. Implement credit/clear group.
<!-- Updated: Validation Session 1 - spike no-go => enable device-fp/ingest first -->
7. If phase-1 found the signal pipeline inactive: **first enable device-fp/ingest
   in `risk-e2e.toml`** so ttl/decay/credit stay behavioral (validated primary
   response). Only if that wiring is disproportionately heavy, replace those
   behavioral assertions with persistence assertions + a logged note citing
   `risk/decay.rs` unit coverage.

## Success Criteria (TDD: expected observed values first)
- [ ] `enabled` on/off behavioral diff logged.
- [ ] Canary path-swap + enable-toggle + ban-ttl expiry logged.
- [ ] `ttl_secs` expiry drop logged (or documented degradation).
- [ ] Decay step-down + `decay_rate:0` constant logged (or documented degradation).
- [ ] Credit −25 delta + clear removal logged (or documented degradation).
- [ ] Every degradation explicitly logged in suite output — never silent.

## Risk Assessment
- **Timing flakiness** (TTL/ban waits) — use small values + a couple retries on
  the transition check; log elapsed. Keep total slow-test budget < ~60s.
- **Canary pins + bans** — canary-raised actors can't test decay/credit (pinned
  + IP banned). Use the phase-1 unpinned mechanism for those groups; keep canary
  isolated to its own IP so bans don't bleed into other groups.
- **Score-raise no-go** — enable device-fp/ingest in `risk-e2e.toml` first
  (validated); persistence-only degradation only if that wiring is too heavy.
