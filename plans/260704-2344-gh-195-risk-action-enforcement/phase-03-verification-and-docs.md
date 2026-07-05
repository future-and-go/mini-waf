---
phase: 3
title: "Verification and docs"
status: completed
priority: P2
dependencies: [1, 2]
---

# Phase 3: Verification and docs

<!-- Updated: Validation Session 1 - canary ban-table + TTL binding moved into Phase 1 scope (no longer a follow-up); added monitor-mode rollout caveat; issue comment must note validation design changes -->

## Overview

Cross-cutting gate: full workspace checks, doc sync for the behavior change (risk score is now an enforcement input, not observability-only), and issue close-out notes.

## Requirements

- Functional: none (no code beyond fixes surfaced by the gate).
- Non-functional: CI-equivalent checks clean; docs match shipped behavior.

## Related Code Files

- Modify: `crates/waf-engine/CLAUDE.md` — `risk/` section: note enforcement wiring (threshold/canary/pinned → Block/Challenge via `Phase::RiskScore`, mode-gated by `risk_assessment`).
- Modify: `docs/system-architecture.md` — only if it describes the risk layer as observability-only (verify before editing).
- Verify (no edit expected): `docs/stories/` FR-025 story proof status — `scripts/bin/harness-cli` absent, so record in plan status instead.

## Implementation Steps

1. `cargo fmt --all --check`, `cargo clippy -p waf-engine --all-targets -- -D warnings`, `cargo test -p waf-engine`; broaden to `cargo test --workspace` (gateway consumes `WafDecision` — contract unchanged in shape, but verify).
2. Update `crates/waf-engine/CLAUDE.md` risk bullet (risk layer now enforces Block/Challenge via `Phase::RiskScore`, `rule_name = "cumulative_risk"`, canary wired to the DDoS ban table); fix any remaining "observability-only" phrasing (engine.rs doc comments handled in Phase 1 — grep `observability` / `until operators wire` to catch stragglers). Document the operator rollout caveat: features left in monitor mode suppress risk escalation for requests they detect (Validation S1 Q1 trade-off), and `risk_assessment` monitor mode is the rollout valve.
3. Comment on issue #195: what landed, test names per AC, note the validation-session design deltas from the original plan comment (single `cumulative_risk` rule name instead of the `ScorerReason` enum; plain-Allow-only escalation; full FR-028 canary wiring including ban table + config TTL, no longer deferred), and the explicit non-goals → production config wiring stays #196; the HTTP/3 Challenge pass-through gap (`gateway/src/http3.rs:304`) gets a follow-up note (new issue only if maintainer agrees).
4. Update this plan's status via `ck plan check`.

## Success Criteria

- [x] fmt/clippy/tests green workspace-wide.
- [x] No doc claims risk score is observability-only.
- [x] Issue #195 updated with AC→test mapping and follow-up notes.

## Risk Assessment

- Workspace test run may surface gateway assumptions that `inspect()` never returns Challenge (grep `WafAction::Challenge` handling paths — already confirmed handled in `proxy_waf_response.rs:187`, `http3.rs:304` pass-through is pre-existing). Low risk; rollback is reverting the wrapper block (single-commit scope).
