# 2026-05-26 — Scalability Hardening Plan Complete

## What Happened

High-effort architectural code review of prx-waf identified **10 findings** across 4 dimensions: p99 latency, tracing/logging, cluster mode, fault tolerance. 3 cluster findings already covered by existing plan `260524-0210-waf-cluster-mode-e2e`. Remaining **7 findings** planned as `260526-2146-scalability-hardening` using `--deep -tdd` mode.

## Findings (7 net-new)

| # | Finding | Phase | Priority |
|---|---------|-------|----------|
| F2 | Per-request `Regex::new()` in eval_one hot path | 1 | P1 |
| F3 | No circuit breaker on CrowdSec AppSec HTTP calls | 2 | P1 |
| F5 | Unbounded `tokio::spawn` per detection for DB INSERT | 3 | P1 |
| F8 | Per-request `info!()` log flooding at scale | 4 | P2 |
| F10 | Static `EnvFilter` — no runtime log level control | 4 | P2 |
| F7 | Single-attempt DB connect, no retry/health check | 5 | P2 |
| F9 | VictoriaLogs sidecar crash = permanent audit death | 6 | P2 |

## Key Decisions

1. **Invalid regex at load** — reject rule entirely (fail-closed), not silent skip
2. **Channel-full event loss** — acceptable for observability; add dropped_events counter for compliance
3. **Sidecar first spawn** — synchronous (fail-closed startup preserved); restart loop only for runtime crashes

## Red-Team Results

19 findings: 2 critical (compilation failures), 6 high, 11 medium. All integrated into plan files before handoff.

- Critical: `from_rule_with_source()` returns `Self` not `()` — plan had invalid `return;`
- Critical: Circuit breaker config fields belong to `ValkeyClientConfig`, not `AppSecConfig`
- High: `Ok(Unavailable)` must trigger `on_failure()`, TOCTOU on failure_count, SIGTERM race during backoff, `unreachable!()` violates Iron Rules

## Plan Structure

7 phases, 18h total. Phases 1/2/6 parallelizable. Phase 5 before 3 (error variant needed). Phase 3 before 4 (shared struct mutations). Phase 7 integration gate blocked by all.

Cross-plan: blocks `260524-0210-waf-cluster-mode-e2e` (Phase 3 batch writer feeds cluster event pipeline).

## Files

- Plan: `plans/260526-2146-scalability-hardening/plan.md`
- Research: `plans/reports/researcher-260526-2146-hot-path-optimization.md`, `plans/reports/researcher-260526-2146-tracing-db-resilience.md`
- Red-team: `plans/reports/red-team-260526-2146-scalability-hardening.md`

## Status

Plan complete, validated, ready for `/ck:cook`. No implementation started.
