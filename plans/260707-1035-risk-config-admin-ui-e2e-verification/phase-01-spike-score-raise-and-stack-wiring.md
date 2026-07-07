---
phase: 1
title: "Spike: score-raise mechanism + stack wiring"
status: complete
priority: P1
dependencies: []
---

# Phase 1: Spike — score-raise mechanism + stack wiring

## Overview
Throwaway probe to de-risk the whole suite: prove (a) a deterministic way to
raise an **unpinned, accumulated** per-actor risk score via the data plane,
(b) that `risk_assessment` enforcement + tier thresholds are wireable in
`e2e.toml`, and (c) that `PUT /api/risk/config` actually writes and hot-reloads
in the container. Output is a go/no-go note, not production code.

## Requirements
- Functional: a single HTTP request pattern that raises `X-WAF-Risk-Score` to a
  known, non-pinned value, then decays over subsequent clean requests.
- Functional: confirm risk block/challenge is *enforced* (not LogOnly) with a
  low tier threshold.
- Non-functional: findings captured in `reports/` for phases 2-4 to consume.

## Architecture
Candidate score-raise mechanisms, in priority order:
1. `ua_blocklisted` (+25 once) — needs device-fp + ingest pipeline active.
2. `low_entropy_ua` / `ua_entropy` — same pipeline.
3. Seed layer (`datacenter_delta` etc.) — **re-applies every request**, so it
   sets a baseline but does NOT decay or expire-drop → unusable for ttl/decay.
4. Canary — pins to 100 + bans IP → unusable for decay/credit.

Enforcement wiring to locate: where `risk_assessment` feature mode and tier
`RiskThresholds` (allow/challenge/block) are configured in the TOML/tier config;
confirm enforce (not monitor) mode.

Hot-reload wiring to confirm: `resolve_path` → `/configs/risk.yaml` in-container
(two levels above `/app/e2e.toml`); watcher on the same path.

## Related Code Files
- Read: `crates/waf-engine/src/risk/ingest/signal_to_contributor.rs` (signal weights)
- Read: `crates/waf-engine/src/device_fp/providers/` (ua_blocklist / ua_entropy signals)
- Read: `crates/waf-engine/src/engine.rs` around `risk_assessment` gating (l.962)
- Read: `crates/waf-common/src/tier.rs` (RiskThresholds) + tier config loader
- Read: `tests/e2e/configs/e2e.toml`, `tests/e2e/docker-compose.e2e.yml`
- Create (throwaway): `plans/260707-1035-risk-config-admin-ui-e2e-verification/reports/spike-findings.md`

## Implementation Steps
1. Bring up the existing stack; add a temporary risk-on `risk.yaml` + minimal
   tier/feature wiring to `e2e.toml`; confirm `/health` + a request returns
   `X-WAF-Risk-Score`.
2. Probe each candidate mechanism: send the crafted request, capture
   `X-WAF-Risk-Score`. Record which yields a deterministic unpinned value.
3. Send N clean requests after a raise; confirm the score decays (proves the
   value is unpinned + accumulated, not re-applied seed).
4. Confirm enforce mode: with threshold below the raised score, confirm
   `X-WAF-Action: block` or `challenge` (not `LogOnly`/`none`).
5. PUT a changed `risk.yaml` value via the API; confirm the file changed
   in-container AND a subsequent request reflects the new behavior (hot-reload).
6. Write `reports/spike-findings.md`: chosen mechanism + exact request, tier/
   feature wiring snippet, hot-reload confirmation, and go/no-go for behavioral
   groups.

## Success Criteria (TDD: probe assertions)
- [ ] A documented request raises `X-WAF-Risk-Score` to a known unpinned value.
- [ ] That score decays across clean requests (not re-applied every request).
- [ ] `X-WAF-Action` shows enforced block/challenge under a low threshold.
- [ ] PUT `/api/risk/config` change is observable in data-plane behavior (hot-reload).
- [ ] `spike-findings.md` records mechanism + wiring + go/no-go.

## Risk Assessment
- **Device-fp/ingest not active in e2e** → no accumulating signal. Mitigation:
  document; trigger the degradation path (ttl/decay/credit become
  persistence-only). This is the whole reason the spike is first.
- **Enforcement stuck in monitor mode** → no block/challenge observable.
  Mitigation: find the feature-mode switch; if unavailable, `enabled` behavioral
  test relies on header presence + score value rather than the action verb.
