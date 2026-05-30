---
title: "FR-012 Transaction Velocity & Sequence"
description: "Cross-endpoint behavioral detection: Login→OTP→Deposit timing, withdrawal velocity, rapid limit-change. Mirrors FR-011 BehaviorRecorder pattern."
status: complete
priority: P1
branch: "main"
tags: [security, fr-012, behavioral, hackathon]
blockedBy: []
blocks: []
created: "2026-05-04T09:35:51.135Z"
completedAt: "2026-05-04"
createdBy: "ck:plan"
source: skill
progress: "5/5 phases complete (100%)"
---

# FR-012 Transaction Velocity & Sequence

## Overview

Detect cross-endpoint anomalies invisible to single-request checks. Three patterns:
1. **Sequence timing** — Login→OTP→Deposit completed faster than human
2. **Withdrawal velocity** — N withdrawals / T sec
3. **Rapid limit-change** — M limit-changes / T sec

Output = `Signal` to existing `RiskAggregator`. Risk engine (FR-025/27) decides Allow/Challenge/Block.

**Source:** `plans/reports/brainstorm-260504-1632-fr-012-transaction-velocity.md` (approved 2026-05-04).

## Architecture (one-liner)

`Request → EndpointRoleTagger → SessionKey → TxSequenceRecorder (DashMap + ring buffer) → Classifiers → RiskAggregator`

Mirrors `crates/waf-engine/src/device_fp/behavior/recorder.rs` (FR-011). DRY by design.

## Phases

| Phase | Name | Status |
|-------|------|--------|
| 1 | [Config + Role Tagger + Recorder](./phase-01-config-role-tagger-recorder.md) | Complete |
| 2 | [Classifiers + Signal Emission](./phase-02-classifiers-signal-emission.md) | Complete |
| 3 | [Engine Integration](./phase-03-engine-integration.md) | Complete |
| 4 | [Tests Unit + E2E](./phase-04-tests-unit-e2e.md) | Complete |
| 5 | [Docs Update](./phase-05-docs-update.md) | Complete |

## Key Decisions (locked)

- Endpoint roles: YAML, hot-reload via `ArcSwap` + `notify`
- Identity: session cookie ?? device_fp fallback
- State scope: node-local DashMap (cluster session affinity assumed)
- Action: signal-only → RiskAggregator (no direct block)
- Pattern: Strategy (Classifier trait) + Ring buffer (16 events) + In-memory repo
- Module: `crates/waf-engine/src/checks/tx_velocity/`

## Dependencies

- **FR-004** (rate limit) — reuse cookie extraction pattern (`checks/rate_limit/check.rs:90`)
- **FR-011** (behavioral) — reuse recorder/janitor pattern (`device_fp/behavior/recorder.rs`)
- **FR-025/27** (risk scoring) — emit to `RiskAggregator` trait (`device_fp/aggregator.rs:40`)

No blocking plans. All upstream deps complete.

## Success Criteria (plan-level)

- All 3 patterns detect synthetic attack scenarios
- p99 overhead <100µs/request (bench-verified)
- Hot-reload config without restart
- Zero false positives on baseline traffic suite
- `cargo fmt && cargo clippy -D warnings && cargo test` green
- No `.unwrap()` in production code (Iron Rule #1)

## Follow-ups (post-completion)

- [Completed 2026-05-31] FR-010 fingerprint plumbing + response-side `ok` enrichment closed in
  [`260530-2325-fr012-fp-plumbing-and-ok-enrichment/plan.md`](../260530-2325-fr012-fp-plumbing-and-ok-enrichment/plan.md).
