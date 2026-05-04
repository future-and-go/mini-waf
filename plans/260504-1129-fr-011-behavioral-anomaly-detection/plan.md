---
title: "FR-011 Behavioral Anomaly Detection"
description: "Per-actor sliding-window behavior recorder + four classifiers (burst-interval, regularity, zero-depth, missing-referer) feeding the FR-010 risk aggregator."
status: completed
priority: P1
branch: "main"
tags: [fr-011, device-fp, behavior, risk-score]
blockedBy: []
blocks: []
created: "2026-05-04T04:30:18.406Z"
createdBy: "ck:plan"
source: skill
---

# FR-011 Behavioral Anomaly Detection

## Overview

Detect bot/automation patterns via behavioral signals: burst inter-request intervals (<50 ms), robotic cadence (low CV), zero-depth single-path sessions on CRITICAL tier, and missing-Referer navigational requests. All four signals share one per-`FpKey` sliding-window state struct and emit through the existing `RiskSignalProvider` pattern (FR-010 aggregator → FR-RS-048/049 risk deltas).

**Source research:** `plans/reports/research-260504-1052-fr-011-behavioral-anomaly-detection.md`

## Scope Anchors

- **Reuse, don't reinvent:** new module under `crates/waf-engine/src/device_fp/behavior/`. Same `FpKey`, same provider trait, same arc-swap reload, same janitor pattern as FR-010.
- **v1 = node-local state.** No Redis mirroring (open question #2 in research). Risk score itself still syncs via existing identity store.
- **No new config file.** Add a `behavior:` block to existing `configs/device-fp.yaml`.
- **Hot path budget:** <5 µs total (recorder write + 4 classifier reads).

## Phases

| Phase | Name | Status |
|-------|------|--------|
| 1 | [State and Recorder](./phase-01-state-and-recorder.md) | Completed |
| 2 | [Pingora Wiring](./phase-02-pingora-wiring.md) | Completed |
| 3 | [Burst Interval Classifier](./phase-03-burst-interval-classifier.md) | Completed |
| 4 | [Remaining Classifiers](./phase-04-remaining-classifiers.md) | Completed |
| 5 | [Config and Hot Reload](./phase-05-config-and-hot-reload.md) | Completed |
| 6 | [Bench Coverage and Docs](./phase-06-bench-coverage-and-docs.md) | Completed |

## Dependencies

- FR-010 device-fingerprinting (DONE). Reuses `FpKey`, `RiskSignalProvider` trait, aggregator wiring, arc-swap reload, identity-store janitor.
- FR-RS-048 / FR-RS-049 risk deltas — defined in `plans/reports/spec-260430-1709-risk-score-requirements-and-tech-spec.md`.

## Success Criteria (plan-level)

- All four AC terms in FR-011 spec emit correct risk-signal deltas under integration tests.
- ≥90% line coverage on `device_fp/behavior/**` via `cargo llvm-cov --fail-under-lines 90`.
- p99 hot-path overhead <5 µs (Criterion bench).
- Zero panic-capable unwraps in production code (Iron Rule 1). Zero clippy warnings.
- Hot-reload of `configs/device-fp.yaml` `behavior:` block within 500 ms; malformed YAML retains last-good config.
- `docs/codebase-summary.md` updated with new module.

## Unresolved Questions (carry from research)

1. Asset-tier exclusion source — read tier from rule-engine output vs precompute path→tier in Recorder. Decide in Phase 2.
2. Cluster mode for behavioral state — v1 ships node-local; document explicitly in Phase 6.
3. `missing_referer` "first in session" definition — first request from previously-unseen `FpKey` vs WAF-issued cookie. Decide in Phase 4.
4. CV threshold (0.15) calibration — needs labeled traffic sample. Phase 6 ships default; tune post-launch.
5. `Sec-Purpose: prefetch` — full exempt vs risk-discount. Default to full exempt in Phase 4.
