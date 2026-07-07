---
phase: 2
title: "Fixtures + compose wiring"
status: complete
priority: P1
dependencies: [1]
---

# Phase 2: Fixtures + compose wiring

## Overview
Stand up a reproducible risk-enabled e2e stack: a writable `risk.yaml` at the
path the API/watcher resolve to, `e2e.toml` risk enforcement + low tier
thresholds, and a compose path that mounts them. Ends with a smoke proof that
risk scoring is observable.

## Requirements
- Functional: gateway emits `X-WAF-Risk-Score` and enforces a low threshold.
- Functional: `PUT /api/risk/config` writes and hot-reloads (proven in phase 1).
- Non-functional: no impact on existing suites (rules-engine/gateway/api) — new
  config is additive or a separate compose/override.

## Architecture
- **risk.yaml fixture** (`tests/e2e/configs/risk.yaml`): `enabled: true`,
  `emit_header: true`, memory backend, canary enabled with a known trap path,
  decay tuned for observability, short TTLs. Seed defaults per spike outcome.
- **Mount**: writable bind mount to **`/configs/risk.yaml`** (rw) — resolve_path
  lands there because `e2e.toml` is at `/app/e2e.toml` (verified). NOT `:ro`
  (PUT must write).
<!-- Updated: Validation Session 1 - config isolation locked to dedicated override -->
- **Config isolation (VALIDATED):** dedicated `tests/e2e/configs/risk-e2e.toml`
  (copy of `e2e.toml` + `risk_assessment` enforce + a tier with low
  `RiskThresholds`, challenge ≈30 / block ≈60) + a
  `tests/e2e/docker-compose.risk-override.yml` that layers the rw risk.yaml mount
  and swaps the config. Base `e2e.toml` + existing suites stay untouched. Do NOT
  extend the shared `e2e.toml`.

## Related Code Files
- Create: `tests/e2e/configs/risk.yaml`
- Create: `tests/e2e/configs/risk-e2e.toml` (e2e.toml + risk enforce + tier thresholds)
- Create: `tests/e2e/docker-compose.risk-override.yml` (rw risk.yaml mount + config swap)
- Read: phase-1 `reports/spike-findings.md`

## Implementation Steps
1. Author `risk.yaml` fixture from phase-1 findings (canary trap path, decay,
   TTLs, seed).
2. Add risk enforcement + tier thresholds to the TOML config.
3. Add the **writable** risk.yaml mount at `/configs/risk.yaml`.
4. Bring the stack up; assert `/health` 200, then a crafted request returns
   `X-WAF-Risk-Score` and an enforced action under threshold.
5. Confirm existing suites still pass against the (extended) stack, or that the
   override isolates risk config.

## Success Criteria (TDD: smoke assertions first)
- [ ] Stack boots; `/health` 200.
- [ ] Crafted request returns `X-WAF-Risk-Score` header with expected value.
- [ ] Enforced `X-WAF-Action` (block/challenge) under the low threshold.
- [ ] `PUT /api/risk/config` change reflected in a follow-up request (hot-reload).
- [ ] Existing e2e suites unaffected.

## Risk Assessment
- **RO filesystem write failure** — the base compose deliberately mounts config
  top-level to avoid RO errors; the risk.yaml mount must be rw at `/configs/`.
  Mitigation: verified resolve path; mount rw; smoke-test PUT.
- **Cross-suite contamination** — risk enforcement could change gateway-suite
  expectations. Mitigation: prefer an override file scoped to the risk suite.
