---
title: Risk Config Admin-UI E2E Verification — Brainstorm Report
date: 2026-07-07 10:35 +07:00
status: approved
skill: brainstorm
modes: []
branch: desmond-e2e-testing
handoff: /ck:plan --tdd
---

# Risk Config Admin-UI E2E Verification — Brainstorm

## Problem Statement

Create an end-to-end test that verifies each Risk Scoring Engine configuration
setting exposed in the admin UI:

- verify each config setting persists, with concrete evidence
- verify each setting's *effect* across different values, with concrete evidence
- ship a runnable script + run guide
- produce a test-result artifact after running

UI-exposed settings (4 sections, from `web/admin-panel/src/pages/risk-scoring/index.tsx`):
General (`enabled`, `ttl_secs`, `gc_interval_secs`), Store (`backend`,
`redis.url`, `redis.key_prefix`), Decay (`min_clean_streak`, `decay_rate`,
`max_decay`), Canary (`enabled`, `ban_ttl_secs`, `paths`).

## Scout Findings (feasibility ground truth)

- **Config API real; siblings stubbed.** `crates/waf-api/src/risk_api.rs`:
  `GET/PUT /api/risk/config` round-trips `configs/risk.yaml` (deep-merge →
  validate as `RiskConfig` → write → engine hot-reload). `get_risk_metrics`
  returns hardcoded zeros; `list_risk_actors` returns `[]` (marked "STUB —
  v1 placeholder"). `credit`/`clear` real, act on live IP actor state.
- **Data plane = evidence channel.** `crates/gateway/src/waf_observability_headers.rs`
  emits `X-WAF-Risk-Score`, `X-WAF-Action`, `X-WAF-Mode`, `X-WAF-Rule-Id`.
  Risk enforcement gated by `risk_assessment` feature/mode (`engine.rs:962`;
  monitor mode downgrades block→LogOnly).
- **Harness is bash.** `tests/e2e/*.sh` + `lib.sh` (`assert_*`, JUnit/JSON/MD
  writers) + `docker-compose.e2e.yml` (postgres + httpbin + prx-waf), admin
  API `:16827`, aggregated by `render-report.sh`.
- **Risk off in main e2e stack.** `configs/e2e.toml` has no risk refs.
  `browser/fixtures/risk.yaml` forces challenge via seed=50 (template only).
- **Thresholds live in tier config**, not `risk.yaml`
  (`waf-common::tier::RiskThresholds`, consumed by `risk/threshold.rs::decide()`).

## Brutal Truths

1. **~half the risk page is un-testable e2e.** KPI row + live-actors table are
   stub-backed (zeros/empty). Any test there asserts a stub (pointless) or real
   data (always fails). Fixing needs backend implementation — separate project.
   **Decision: scope out, document loudly.**
2. **Effect observability is uneven.** Clean: canary, `enabled`, redis-key
   inspection. Slow-but-doable: decay, `ttl_secs`, `canary.ban_ttl_secs`.
   **Not black-box observable: `gc_interval_secs`** (purge cadence, no external
   signal) → persistence-only.
3. **"In the admin UI" ≠ driving the React DOM.** Testing the API contract the
   UI calls (`PUT /api/risk/config`) covers the substance robustly; effect is
   measured at the data plane regardless. **Decision: bash API + data-plane
   only, no Playwright.**

## Decisions (locked)

| Decision | Choice |
| --- | --- |
| Test layer | Bash API + data-plane only (extends existing harness) |
| Metrics/actors stubs | Scope out; document loudly in README + report |
| Store backend | Memory only (store settings = persistence-only, no live redis) |
| Slow tests | Include with small values (short TTLs, minimal decay streaks) |
| Plan handoff | `/ck:plan --tdd` |

## Approaches Evaluated

- **A — Bash API + data-plane (CHOSEN).** New `run-risk-config.sh` + risk-on
  fixture. Per setting: PUT (as UI does) → GET/file (persistence) → drive
  gateway traffic → assert `X-WAF-*` headers (effect). Pros: KISS, matches
  infra, fast, low-flake, CI-ready. Cons: no React DOM coverage.
- **B — Playwright UI-driven.** Drive the real form. Pros: literal UI + shots.
  Cons: brittle/slow, can't rescue stubs, effect still from data plane. Rejected.
- **C — Hybrid (A + thin Playwright smoke).** Best coverage-to-cost. Rejected in
  favor of A per user (no DOM coverage needed now).

## Recommended Solution

Single bash suite `tests/e2e/run-risk-config.sh` in the existing harness style.
Evidence = suite logs actual observed values (header values, status codes,
config-file bytes, score sequences) into assertion messages so the emitted
Markdown report shows *what was observed*.

### Test Matrix

| Group | Setting | Persistence | Behavioral effect (evidence) |
| --- | --- | --- | --- |
| General | `enabled` | PUT/GET/file | on → `X-WAF-Risk-Score>0` + action; off → no risk block (header diff) |
| General | `ttl_secs` | ✅ | small (≈3s): raise score → idle-wait → score back to baseline |
| General | `gc_interval_secs` | ✅ | persistence-only (no black-box signal — documented) |
| Store | `backend`/`redis.url`/`key_prefix` | ✅ | persistence-only; invalid backend → 400 (validation) |
| Decay | `decay_rate`/`min_clean_streak`/`max_decay` | ✅ | raise score → clean requests → score steps down; `decay_rate:0` → constant (score sequence) |
| Canary | `paths`/`enabled` | ✅ | `/trap`→block, `/safe`→pass; swap paths → behavior swaps; disabled → pass (status+action) |
| Canary | `ban_ttl_secs` | ✅ | small (≈3s): hit → IP banned → wait → unbanned (transition over time) |
| Credit/Clear | real endpoints | — | raise score → credit −25 → score drops; clear → removed=true |

Excluded (documented): `/api/risk/metrics`, `/api/risk/actors` (stubs).

### Required Fixtures

- E2E `configs/risk.yaml`: `emit_header: true`, memory backend, canary on,
  decay tuned for observability, short TTLs.
- Gateway config: `risk_assessment` in **enforce** mode + tier with **low risk
  thresholds** (challenge ≈30 / block ≈60).
- **Deterministic unpinned score-raise mechanism** (see Risks).

## Key Risk (drives spike-first plan)

`ttl_secs`, `decay`, and `credit/clear` behavioral tests all need a
**deterministic way to raise an unpinned, accumulated per-actor score** via the
data plane. Seed deltas re-apply every request (no decay, no expiry-drop);
canary pins to 100 + bans the IP (no decay, blocked). The clean mechanism is a
**one-shot accumulating signal** — most likely a blocklisted User-Agent
(`ua_blocklisted`, +25 once) — but requires the device-fp/ingest pipeline
active in the e2e stack.

**Mitigation:** Plan phase 1 = spike to confirm the exact signal + wire the
blocklist fixture. If no deterministic unpinned raise is achievable, those three
groups degrade to persistence-only + cite existing unit coverage in
`crates/waf-engine/src/risk/decay.rs`; canary remains primary behavioral evidence.

## Success Criteria / Validation

- Each UI setting has a persistence assertion (PUT → GET/file match).
- Each observable setting has ≥2-value behavioral assertions with logged
  observed evidence.
- `gc_interval_secs` + store fields: persistence-only, reason documented.
- Suite emits `out/risk-config/{results.json,junit.xml,summary.md}`; slots into
  `render-report.sh` aggregation.
- README documents run steps + the stub-exclusion caveat.

## Next Steps / Dependencies

- Handoff: `/ck:plan --tdd` with this report as context.
- Plan phase 1 (spike): nail the deterministic unpinned score-raise signal;
  confirm device-fp/ingest active in e2e stack.
- Dependency: e2e stack must enable `risk_assessment` (enforce) + low tier
  thresholds — new/extended gateway fixture required.

## Unresolved Questions

- Does the e2e stack (`docker-compose.e2e.yml` + `e2e.toml`) currently run the
  device-fp/ingest pipeline needed for `ua_blocklisted`? (Spike to confirm.)
- Reuse `docker-compose.e2e.yml` with an override, or a dedicated risk compose?
  (Plan to decide once the fixture footprint is known.)
