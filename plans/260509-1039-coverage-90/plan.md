---
title: "Workspace coverage push to 90% (per-crate phased)"
description: "Per-crate phase plan to raise prx-waf workspace test line coverage toward 90%, with realistic ceilings and explicit infeasibility callouts."
status: pending
priority: P2
effort: ~10 dev-days (parallelizable across worktrees)
branch: main
tags: [coverage, testing, quality, workspace]
created: 2026-05-09
---

## Goal

Raise workspace line coverage from baseline 56.5% (weighted) toward 90%. Per-crate ceilings differ — see Targets table.

## Baseline (cargo llvm-cov, 2026-05-09)

| Crate | Lines | Missed | Line% | Realistic Target | Hard Cap (justified) |
|-------|-------|--------|-------|------------------|----------------------|
| waf-engine  | 12842 | 2046 | 84.07% | **90%** | feasible |
| gateway     | 5275  | 1393 | 73.59% | **85%** | proxy.rs/http3.rs/tunnel.rs need Pingora session — capped |
| waf-cluster | 1982  | 714  | 63.98% | **85%** | transport client/server need real QUIC peer harness |
| waf-common  | 1040  | 422  | 59.42% | **90%** | feasible (pure types) |
| waf-api     | 3527  | 2823 | 19.96% | **80%** | server.rs is axum bootstrap; handlers reachable via TestServer |
| waf-storage | 1554  | 1554 |  0.00% | **85%** | requires Postgres testcontainer fixture |
| prx-waf     | 1453  | 1368 |  5.85% | **35%** | binary entrypoint — see Phase 11 caveat |

**Weighted workspace ceiling if all targets met: ~84%** — 90% workspace not achievable without rewriting prx-waf bin (out of scope) or excluding `bin = []` entries from coverage.

## Phases

| # | File | Crate Scope | Owner Glob | Target | Status |
|---|------|-------------|-----------|--------|--------|
| 01 | [phase-01-waf-common.md](phase-01-waf-common.md) | waf-common (config, types, panel) | `crates/waf-common/**` | 90% | pending |
| 02 | [phase-02-waf-storage.md](phase-02-waf-storage.md) | waf-storage (db + repo) | `crates/waf-storage/**` | 85% | pending |
| 03 | [phase-03-waf-cluster.md](phase-03-waf-cluster.md) | waf-cluster (transport, sync, election) | `crates/waf-cluster/**` | 85% | pending |
| 04 | [phase-04-waf-api.md](phase-04-waf-api.md) | waf-api (handlers, middleware, ws) | `crates/waf-api/**` | 80% | pending |
| 05 | [phase-05-gateway.md](phase-05-gateway.md) | gateway (cache, filters, tier, ssl) | `crates/gateway/**` | 85% | pending |
| 06 | [phase-06-waf-engine-checks.md](phase-06-waf-engine-checks.md) | waf-engine `checks/` + `access/` | `crates/waf-engine/src/{checks,access}/**` + tests | 90% | pending |
| 07 | [phase-07-waf-engine-rules-engine.md](phase-07-waf-engine-rules-engine.md) | waf-engine `engine.rs`, `checker.rs`, `block_page.rs`, `rules/manager.rs`, `rules/hot_reload.rs` | listed files in src + new `tests/engine_*` | 85% | pending |
| 08 | [phase-08-waf-engine-platform.md](phase-08-waf-engine-platform.md) | waf-engine `logging/`, `plugins/`, `geoip*`, `community/`, `crowdsec/`, `relay/` gaps | listed files + new `tests/platform_*` | 88% | pending |
| 09 | [phase-09-waf-engine-risk.md](phase-09-waf-engine-risk.md) | waf-engine `risk/` (lift 91%→95%), `device_fp/` mop-up | `crates/waf-engine/src/{risk,device_fp}/**` + new `tests/risk_*` | 95% | pending |
| 10 | [phase-10-prx-waf.md](phase-10-prx-waf.md) | prx-waf binary (CLI parser + victoria_logs) | `crates/prx-waf/**` | 35% | pending |
| 11 | [phase-11-coverage-ci-gate.md](phase-11-coverage-ci-gate.md) | CI workflow: enforce per-crate floors | `.github/workflows/coverage.yml` (new) | n/a | pending |

## Dependencies

- Phase 02 (waf-storage) blocks Phase 04 (waf-api needs DB fixture).
- Phase 02 blocks Phase 07 (engine wiring uses `Database`).
- Phase 06 + 07 + 08 + 09 are within waf-engine but use disjoint file globs — parallelizable in worktrees.
- Phase 11 blocks final merge — runs after 01–10 land.

## Parallelism map

```
01 ──┐
02 ──┼─── 04 ─── 11
03 ──┤
05 ──┤
06 ──┤
07 ──┤  (needs 02 to land first)
08 ──┤
09 ──┤
10 ──┘
```

## Cross-cutting constraints (apply to every phase)

- NO mocks of internal business logic. Use real code paths; only stub external services (HTTP, file fs through tempdir, DB through testcontainers-rs).
- All new `src/` test helpers must obey Seven Iron Rules: no `.unwrap()`, no `todo!()`, no dead code.
- Tests may use `.unwrap()` / `.expect()` (test-only).
- Each new test file ≤ 200 LOC; split if needed.
- `cargo fmt --all -- --check` and `cargo check --tests` MUST pass per phase.
- New helpers must be `#[cfg(test)]`-gated when added under `src/`.

## Out-of-scope

- HTTP/3 quinn server (`gateway/src/http3.rs`): blocked on quinn test harness — covered to <30% intentionally.
- Pingora `ProxyHttp::request_filter` end-to-end: needs full Session — phase 5 covers via filter-chain decomposition only.
- `prx-waf/src/main.rs` bootstrap: 1050 lines of CLI dispatch with side effects. Phase 10 covers parser + 2 commands; rest deemed integration-test territory (e2e shell suite in `tests/`).

## Unresolved questions

- Should we exclude `prx-waf/src/main.rs` from coverage via `--ignore-filename-regex 'main\.rs$'`? Workspace ceiling jumps to 88% if so. (Recommend: yes, with CI floor 85%.)
- Postgres testcontainer image pinning: use `postgres:16-alpine` from existing docker-compose? Confirm with infra owner before Phase 02.
- waf-engine submodule baselines for `access/`, `checks/`, `community/`, `crowdsec/`, `block_page.rs`, `checker.rs` not captured (workspace summary truncated to last 100 files). Phase 06–08 owners must re-run `cargo llvm-cov -p waf-engine --summary-only` to confirm before estimating.
