# planner report — coverage-to-90 plan (260509-1042)

## Baseline (cargo llvm-cov, 2026-05-09)

| Crate | Lines | Missed | Line% |
|-------|-------|--------|-------|
| waf-engine  | 12842 | 2046 | **84.07%** |
| gateway     | 5275  | 1393 | **73.59%** |
| waf-cluster | 1982  | 714  | **63.98%** |
| waf-common  | 1040  | 422  | **59.42%** |
| waf-api     | 3527  | 2823 | **19.96%** |
| waf-storage | 1554  | 1554 | **0.00%** |
| prx-waf     | 1453  | 1368 | **5.85%** |
| **Workspace (raw)** | 27673 | 10320 | **~62.7%** weighted |

## Phase files created

- `plans/260509-1039-coverage-90/plan.md` (overview, target table, dependency graph)
- `plans/260509-1039-coverage-90/phase-01-waf-common.md` → 90%
- `plans/260509-1039-coverage-90/phase-02-waf-storage.md` → 85% (Postgres testcontainer)
- `plans/260509-1039-coverage-90/phase-03-waf-cluster.md` → 85%
- `plans/260509-1039-coverage-90/phase-04-waf-api.md` → 80% (blocked on 02)
- `plans/260509-1039-coverage-90/phase-05-gateway.md` → 85% (Pingora-coupled files capped)
- `plans/260509-1039-coverage-90/phase-06-waf-engine-checks.md` → 90% (`checks/`+`access/`)
- `plans/260509-1039-coverage-90/phase-07-waf-engine-rules-engine.md` → 85% (engine.rs/checker.rs/block_page.rs/manager.rs/hot_reload.rs; blocked on 02)
- `plans/260509-1039-coverage-90/phase-08-waf-engine-platform.md` → 88% (logging/plugins/geoip/community/crowdsec/relay)
- `plans/260509-1039-coverage-90/phase-09-waf-engine-risk.md` → 95% (risk/+device_fp/ ceiling lift)
- `plans/260509-1039-coverage-90/phase-10-prx-waf.md` → **35% only** (push-back; binary entrypoint)
- `plans/260509-1039-coverage-90/phase-11-coverage-ci-gate.md` (CI floor enforcement)

## Realistic targets per crate

| Crate | Target | Rationale |
|-------|--------|-----------|
| waf-common  | **90%** | pure types, trivial |
| waf-storage | **85%** | sqlx → testcontainer Postgres, every CRUD covered |
| waf-cluster | **85%** | transport server/client capped by QUIC harness needs |
| waf-api     | **80%** | server.rs bootstrap caps; handlers reachable via TestServer |
| gateway     | **85%** | Pingora-coupled files (proxy.rs, http3.rs, tunnel.rs, proxy_waf_response.rs, response_cache_integration.rs) excluded from gate |
| waf-engine  | **90%** | feasible across all 5 sub-phases |
| **prx-waf** | **35%** | **infeasible to reach 90%** — see push-back |

## Where 90% is genuinely infeasible

1. **prx-waf** — `main.rs` is 1050 LOC of CLI dispatch + thread/runtime spawning. The `run` subcommand never returns (Pingora blocks). `assert_cmd` covers `--help`, `migrate`, `seed-admin`, `rules`, `cluster token`, `crowdsec status` — that's ~10% of `main.rs`. Combined with `victoria_logs/` lifts crate to ~35%. Reaching 80%+ requires refactoring `main.rs` into `lib.rs::run()` + thin bin (out of scope; flagged for follow-up plan).

2. **gateway/src/proxy.rs (226 regions, 0%)**, **gateway/src/http3.rs (363 regions, 0%)**, **gateway/src/tunnel.rs (185 regions, 0%)**, **gateway/src/proxy_waf_response.rs (129 regions, 0%)**, **gateway/src/response_cache_integration.rs (183 regions, 0%)** — all require Pingora `Session` mock OR full HTTP/3 quinn harness. Gateway gate uses `--ignore-filename-regex` for these; raw line% caps at ~78%.

3. **waf-engine/src/engine.rs** can reach ~75% but not 95% — many seldom-used config branches (CrowdSec disabled, custom rules disabled, etc.) are construction-only and not behaviorally distinct enough to warrant per-branch tests.

4. **waf-engine/src/logging/vlogs_layer.rs** — `tracing_subscriber::Layer` impl with internals not fully steerable; ceiling 80%.

## Workspace ceiling

If all phase targets met **and** `prx-waf/main.rs` excluded from workspace coverage: **~88%**.
Without exclusions: **~84%**.
**90% workspace is not achievable** without the `prx-waf` refactor flagged in Phase 10.

## File ownership (no overlap; worktree-safe)

- Phase 01: `crates/waf-common/**`
- Phase 02: `crates/waf-storage/**`
- Phase 03: `crates/waf-cluster/**`
- Phase 04: `crates/waf-api/**` (depends on 02)
- Phase 05: `crates/gateway/**`
- Phase 06: `crates/waf-engine/src/{checks,access}/**` + tests `checks_*.rs` / `access_*.rs`
- Phase 07: `crates/waf-engine/src/{engine,checker,block_page}.rs` + `rules/{manager,hot_reload}.rs` + tests `engine_*.rs` / `rules_manager_*.rs` / `rules_hot_reload_*.rs` / `checker_*.rs` (depends on 02)
- Phase 08: `crates/waf-engine/src/{logging,plugins,community,crowdsec,relay}/**` + `geoip*.rs` + tests `logging_*.rs` / `plugins_*.rs` / `geoip*.rs` / `community_*.rs` / `crowdsec_*.rs` / `relay_intel_*.rs`
- Phase 09: `crates/waf-engine/src/{risk,device_fp}/**` + tests `risk_*.rs` / `device_fp_*.rs`
- Phase 10: `crates/prx-waf/**`
- Phase 11: `.github/workflows/coverage.yml`, `scripts/coverage-check.sh`

## Constraints honored across all phases

- No mocks of internal business logic (real DB via testcontainers, real WASM via wat→bytes, real HTTP via httpmock for external services only).
- Tests obey existing test patterns (e.g. `MockClock` is a clock seam, not a logic mock).
- New `src/` test helpers obey Seven Iron Rules: no `.unwrap()`, `.expect()` (test-only), no `todo!()`.
- `cargo check --tests`, `cargo fmt --all -- --check` MUST pass per phase.
- New test files ≤ 200 LOC where possible (split otherwise).

## Unresolved questions

1. **Should `prx-waf/src/main.rs` be excluded from workspace coverage** via `--ignore-filename-regex 'prx-waf/src/main\.rs$'`? If yes, workspace ceiling jumps to ~88%, gate becomes 85%. Recommend: yes, with explicit waiver in `docs/code-standards.md`.
2. **Postgres testcontainer image pinning** — confirm `postgres:16-alpine` is acceptable for CI (matches existing `docker-compose.yml`). Owner: infra/devops.
3. **waf-engine submodule baselines** for `access/`, `checks/`, `community/`, `crowdsec/`, `block_page.rs`, `checker.rs` — workspace summary tail truncated at 100 files. Phase 06–08 owners must rerun `cargo llvm-cov -p waf-engine --summary-only` before estimating effort.
4. **WASM test fixture** in Phase 08 — does `wat = "1"` build deterministic bytes across rust toolchains? Confirm before bundling.
5. **HMAC secret persistence test (Phase 09)** — does the existing `secret.rs` enforce mode 0600 on Unix? If not, the test will surface a real bug; owner should treat as a bugfix, not a test mistake.
6. **Phase 11 floors** are conservative initial values (actual minus 2-3%). After 1 month of green CI, raise to actual−1.

**Status:** DONE
**Summary:** Per-crate phase plan written: 11 phase files + plan.md. Realistic targets: waf-common 90%, waf-storage 85%, waf-cluster 85%, waf-api 80%, gateway 85% (capped), waf-engine 90%, prx-waf **35%** (infeasible higher without main.rs refactor — flagged). Workspace ceiling ~88% with main.rs exclusion, ~84% without. CI floor gate codified in Phase 11.
**Concerns/Blockers:** Phase 04 + Phase 07 + Phase 10 (cli_migrate_seed) gate on Phase 02 testcontainer fixture landing first.
