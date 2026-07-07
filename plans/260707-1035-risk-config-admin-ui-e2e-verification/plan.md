---
title: Risk Config Admin-UI E2E Verification Suite
status: complete
created: 2026-07-07 10:35 +07:00
mode: tdd
branch: desmond-e2e-testing
source_brainstorm: plans/reports/brainstorm-260707-1035-risk-config-admin-ui-e2e-verification-report.md
blockedBy: []
blocks: []
---

# Risk Config Admin-UI E2E Verification Suite

## Goal

End-to-end verification of every Risk Scoring Engine setting exposed in the
admin UI, driven through the exact API the UI calls (`/api/risk/config`) plus
gateway data-plane observation. Each setting gets a **persistence** proof
(PUT→GET→file) and, where observable, a **behavioral** proof across ≥2 values
with the actually-observed evidence logged into the result artifact.

Deliverables: `tests/e2e/run-risk-config.sh` + fixtures, README run guide,
JUnit/JSON/MD result artifacts via `lib.sh`, aggregated by `render-report.sh`.

## Locked Decisions (from brainstorm — do not re-litigate)

- Bash API + data-plane suite only. No Playwright / React DOM.
- Store: memory only → store settings are persistence-only (no live redis).
- `/api/risk/metrics` + `/api/risk/actors` are stubs → **scoped out, documented loudly**.
- Slow behavioral tests included with **small values** (short TTLs, minimal streaks).

## Key Wiring Facts (verified in codebase)

- `PUT /api/risk/config` deep-merges body over `configs/risk.yaml`, validates as
  `RiskConfig`, writes, engine hot-reloads (`crates/waf-api/src/risk_api.rs`).
- Path resolution: `resolve_path` = two levels above the main config file
  (`config_files.rs:18`). Engine watcher uses identical logic
  (`prx-waf/src/main.rs:1651`). With `e2e.toml` mounted at `/app/e2e.toml`,
  both resolve to **`/configs/risk.yaml`** → fixture must mount it **writable** there.
- Evidence channel: gateway emits `X-WAF-Risk-Score`, `X-WAF-Action`,
  `X-WAF-Mode`, `X-WAF-Rule-Id` (`gateway/src/waf_observability_headers.rs`).
- Enforcement gated by `risk_assessment` feature/mode (`engine.rs:962`; monitor
  mode downgrades block→LogOnly). Risk thresholds live in **tier config**, not
  `risk.yaml` (`waf-common::tier::RiskThresholds`).
- Current `e2e.toml` has **no** risk/tier/feature sections → they go in a
  dedicated `risk-e2e.toml` copy (never the shared `e2e.toml`; see phase 2).
- `lib.sh` API: `e2e_init`, `assert_eq/ne/contains/http_status`, `http_get`,
  `wait_health`, `pass/fail`, `e2e_finalize`, `detect_compose`. No header-value
  capture helper → suite adds a small local one (`curl -D -` + grep).

## The Critical Risk (why phase 1 is a spike)

`ttl_secs`, `decay`, and `credit/clear` behavioral tests need a **deterministic
way to raise an unpinned, accumulated per-actor score** via the data plane. Seed
deltas re-apply every request (no decay, no expiry-drop); canary pins to 100 +
bans the IP. Likely mechanism: `ua_blocklisted` (+25 once) via the device-fp /
ingest pipeline — **only if that pipeline is active in the e2e stack**. Phase 1
proves or disproves this and sets the go/no-go for those three groups.

## Phases

| # | Phase | Priority | Depends | Gate |
|---|-------|----------|---------|------|
| 1 | Spike: score-raise mechanism + stack wiring | P1 | — | Probe passes: bad-input request → `X-WAF-Risk-Score` ≥ threshold; risk enforce + thresholds wireable; PUT hot-reloads |
| 2 | Fixtures + compose wiring | P1 | 1 | Health + risk-enabled smoke (header present, challenge/block observable) |
| 3 | Persistence suite (all UI settings) | P1 | 2 | Every UI field PUT→GET→file match; invalid backend → 400 |
| 4 | Behavioral suite (effect, ≥2 values) | P1 | 2,3 | Observed evidence for each observable setting; slow ones with small values |
| 5 | Run guide + aggregation + result artifact | P2 | 3,4 | README run steps; render-report.sh includes suite; artifact produced |

## Spike No-Go Response (validated decision)

If phase 1 finds the device-fp/ingest pipeline inactive (no deterministic
unpinned score-raise), the **primary response is to enable device-fp/ingest** in
the risk-e2e config so `ttl_secs`/`decay`/`credit-clear` effects stay observable
— this aligns with the stated goal of verifying effect across values. Only if
that wiring proves disproportionately heavy do those three degrade to
**persistence-only** + cite unit coverage in
`crates/waf-engine/src/risk/decay.rs`. Canary + `enabled` remain behavioral
regardless. Any degradation is logged in suite output and README, never hidden.

## Global Success Criteria

- [ ] Every UI-exposed setting has a persistence assertion with logged evidence.
- [ ] Every observable setting has ≥2-value behavioral assertions with observed values.
- [ ] `gc_interval_secs` + store fields: persistence-only, reason logged.
- [ ] Metrics/actors exclusion documented in README + suite output.
- [ ] Suite emits `out/risk-config/{results.json,junit.xml,summary.md}`; in `render-report.sh`.
- [ ] Suite runs green locally against the compose stack; result artifact captured in `reports/`.

## TDD Discipline (--tdd)

Each phase writes the **expected observable** (assertion + expected evidence
value) before wiring the fixture that produces it. The suite IS the test; the
"red" state is a failing assertion against a not-yet-wired fixture, "green" is
the fixture producing the expected observed value.

## Links

- Brainstorm: `plans/reports/brainstorm-260707-1035-risk-config-admin-ui-e2e-verification-report.md`
- Phase files: `phase-01-*.md` … `phase-05-*.md`

## Validation Log

### Session 1 — 2026-07-07

**Verification Results (Full tier, 5 phases)**
- Claims checked: ~12. Verified: 11. Failed: 1. Unverified: 0.
- Verified: `resolve_path`→`/configs/risk.yaml` (`config_files.rs:18`), risk
  watcher wiring (`prx-waf/main.rs:1651`), header emission
  (`waf_observability_headers.rs`), `lib.sh` API, compose mounts, metrics/actors
  stubs (`risk_api.rs`), candidate signal exists (`device_fp/providers/ua_blocklist.rs`,
  `Signal::UaBlocklisted`).
- **Failed:** phase 5 assumed `render-report.sh` auto-discovers suites; it uses a
  **hardcoded array** `SUITES=(rules-engine gateway waf-api cluster)` (line 19).
  Corrected in phase 5.

**Decisions confirmed**
1. **Config isolation:** dedicated `docker-compose.risk-override.yml` +
   `risk-e2e.toml`; base stack + existing suites untouched. → phase 2.
2. **Spike no-go:** enable device-fp/ingest for real behavioral coverage;
   persistence-only degradation is last resort. → phases 1, 4, plan.
3. **Aggregation:** add `risk-config` to `render-report.sh` `SUITES` array
   (line 19). → phase 5.
4. **CI:** local-only for now + documented job stub; do not wire nightly yet. → phase 5.

### Execution — Session 2 (2026-07-07)

**Result: all 5 phases complete; suite green 35/35.** Artifact:
`reports/risk-config-e2e-run-results.md`. Spike notes: `reports/spike-findings.md`.

- **Spike GO (no degradation to persistence-only):** score-raise = crafted
  `X-Forwarded-For` anomaly (+10/req, unpinned, decays) — device-fp/ingest NOT
  needed. Canary `/canary/trap` → 403 + pin 100 + IP ban. Enforce by default.
- **Prereq lesson:** the prebuilt binary was a week stale (2026-06-30) vs the
  2026-07-06 risk-engine change; it silently disabled risk. A fresh
  `cargo build --release -p prx-waf` is mandatory (README documents this; the
  suite smoke gate fails loudly on a stale binary).
- **Deliverables:** `tests/e2e/run-risk-config.sh` + `configs/risk.yaml`,
  `configs/risk-e2e.toml`, `configs/tier-risk-e2e.toml`,
  `docker-compose.risk-override.yml`; `render-report.sh` SUITES += `risk-config`;
  README "Risk config suite" section. Base `e2e.toml`/compose untouched; distinct
  ports (26880/26827) coexist with a dev stack. `render-report.sh` auto-appends
  present-but-unlisted suites (never MISSING) — so `risk-config` aggregates
  locally without turning the nightly report red (see M2 below).
- **Two product findings (asserted as real contract, logged loudly):**
  (1) PUT `/api/risk/config` validates serde structure only, not semantics
  (invalid `store.backend` → 200 + persists; engine reload `validate()` is the
  backstop). (2) decay params (`decay_rate`/`min_clean_streak`/`max_decay`) AND
  `ttl_secs`/`gc_interval_secs` are boot-only (store caches them at construction;
  reload never rebuilds the store; no warning). Decay + ttl expiry proven
  behaviorally at boot config; `decay_rate=0` case degraded to persistence +
  `risk/decay.rs` unit citation per the plan's sanctioned degradation clause.
- **Review applied (code-reviewer = DONE_WITH_CONCERNS):** H1 — relabeled the ttl
  test as boot-only (was a phantom hot-reload proof; ttl is boot-only like decay).
  M2 — `render-report.sh` auto-appends present suites instead of hardcoding
  `risk-config` in `SUITES` (user-chosen; avoids nightly MISSING/FAIL, honors the
  "don't wire nightly" decision). Plus numeric-compare regex guards.

### Whole-Plan Consistency Sweep — Session 1
- Re-read `plan.md` + all 5 phase files after propagation.
- Reconciled: removed the stale "extend shared e2e.toml" implication (wiring
  facts + phase 2); corrected "render-report glob" → hardcoded `SUITES` array
  (phase 5); updated degradation → "enable device-fp/ingest first" (plan + phase 4).
- Grep sweep for stale terms (glob / prefer-extend / Modify e2e.toml): clean
  (only the correction marker references "glob").
- **Result: zero unresolved contradictions.** Plan eligible for implementation.
