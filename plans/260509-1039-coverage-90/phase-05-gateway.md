# Phase 05 — gateway (cache, filters, tier, ssl) → 85%

## Context Links
- Baseline: `plans/260509-1039-coverage-90/plan.md`
- Crate: `crates/gateway/`
- Existing tests: 5 files (cache_hot_reload, cache_integration, relay_pipeline_handover, tier_e2e, tier_hot_reload), 41 inline modules.

## Overview
- **Priority:** P2
- **Status:** pending
- **Target:** 85% line (baseline 73.59%)
- File ownership glob: `crates/gateway/**`

## Key Insights
- Already 73.59% — strongest non-engine crate. Remaining gaps cluster around Pingora-coupled code.
- **Hard caps (do NOT chase):**
  - `proxy.rs` (226 regions, 0%) — Pingora `ProxyHttp` impl needs `Session` mock — accept low coverage; cover via decomposition (filters, ctx_builder, pipeline modules already at 90%+).
  - `http3.rs` (363 regions, 0%) — quinn server bootstrap; needs UDP harness. Accept ≤30%.
  - `tunnel.rs` (185 regions, 0%) — encrypted WS tunnel; needs paired client. Accept ≤40%.
  - `proxy_waf_response.rs` (129 regions, 0%) — Session mutation helpers; cover via integration if feasible, else accept ≤30%.
  - `response_cache_integration.rs` (183 regions, 0%) — Pingora-Session-coupled.
  - `router.rs` (92 regions, 0%) — Vhost lookup; CAN be covered with pure unit tests.
- **Real wins:**
  - `cache/backend.rs` (0%), `cache/bootstrap.rs` (0%) — wire pure-construction tests
  - `cache/stats.rs` (29%) — counters and snapshot
  - `ctx_builder/request_ctx_builder.rs` (64%) — header parsing branches
  - `lb.rs` (70%) — weighted round-robin, sticky-session, health-down
  - `ssl.rs` (22%) — ACME state machine pure parts; SslManager construct + cert rotation
  - `protocol.rs` (86%) — minor

## Requirements
- `router.rs` reaches ≥85% (pure logic, no excuse).
- `lb.rs` reaches ≥90% (algorithm + edge cases: empty pool, all-down, weight=0).
- `cache/stats.rs` ≥90% (snapshot, increment, reset).
- `cache/backend.rs` + `cache/bootstrap.rs` ≥80%.
- `ssl.rs` ≥60% (ACME state, cert parsing — exclude tokio runtime tasks).
- `ctx_builder/request_ctx_builder.rs` ≥85% (header parsing branches).
- Pingora-coupled files documented as capped; not counted against gate.

## Architecture
```
gateway/src/
├── router.rs                    ← 0% — easy win
├── lb.rs                        ← 70% → 90%
├── ssl.rs                       ← 22% → 60% (ACME pure parts)
├── ctx_builder/                 ← 64% → 85%
├── cache/
│   ├── backend.rs               ← 0% → 80%
│   ├── bootstrap.rs             ← 0% → 80%
│   ├── stats.rs                 ← 29% → 90%
│   ├── store.rs                 ← 85% → 92%
│   ├── gates/auth_gate.rs       ← 85% → 95%
│   └── (others ≥85% already)
├── filters/                     ← 92-100% (skip — already strong)
├── pipeline/                    ← 97-100% (skip)
├── policies/                    ← 94-100% (skip)
├── tiered/                      ← 79-99% — push compiled_rule.rs to 90%
├── error_page/                  ← 89% → 95%
├── protocol.rs                  ← 86% → 92%
├── proxy.rs                     ← CAPPED 0% (Pingora)
├── http3.rs                     ← CAPPED 0% (quinn)
├── tunnel.rs                    ← CAPPED 0% (paired WS)
├── proxy_waf_response.rs        ← CAPPED 0%
└── response_cache_integration.rs ← CAPPED 0%
```

## Related Code Files
**Modify (inline tests):**
- `crates/gateway/src/router.rs`
- `crates/gateway/src/lb.rs`
- `crates/gateway/src/ssl.rs`
- `crates/gateway/src/cache/backend.rs`
- `crates/gateway/src/cache/bootstrap.rs`
- `crates/gateway/src/cache/stats.rs`
- `crates/gateway/src/protocol.rs`
- `crates/gateway/src/ctx_builder/request_ctx_builder.rs`
- `crates/gateway/src/error_page/error_page_factory.rs`
- `crates/gateway/src/tiered/compiled_rule.rs`

**Create:**
- `crates/gateway/tests/router_vhost_resolution.rs` — host→backend lookup, wildcard, missing host
- `crates/gateway/tests/lb_strategies.rs` — round-robin, weighted, sticky, all-down, single-backend
- `crates/gateway/tests/cache_stats_lifecycle.rs` — counters across hit/miss/bypass/purge
- `crates/gateway/tests/ssl_manager_lifecycle.rs` — cert load, ACME order parsing (mocked HTTP via wiremock if needed for ACME directory only)

## Implementation Steps
1. `router.rs` inline: build `HostRouter` with N hosts; lookup exact, wildcard `*.example.com`, missing → None, case-insensitive host.
2. `lb.rs` inline: round-robin advances, weighted distribution after 1000 calls within ±5% expected, sticky session (cookie key) returns same backend, all-backends-down returns error, single-backend always returns same.
3. `cache/backend.rs` + `bootstrap.rs` inline: construct `MokaBackend` with various configs, `bootstrap_cache` with empty + populated YAML.
4. `cache/stats.rs` inline: every counter `incr_*` then `snapshot()` returns expected; `reset()` zeros all.
5. `ssl.rs`: extract pure helpers (cert PEM parse, expiry check, hostname validation) into testable functions; cover.
6. `ctx_builder/request_ctx_builder.rs`: feed synthetic header maps covering: empty, multi-XFF, malformed Cookie, Host with port, missing Host.
7. `tiered/compiled_rule.rs`: edge cases — overlapping rules, regex compile failures (already validated), priority tiebreak.
8. `protocol.rs`: HTTP/2 vs HTTP/1 detection paths.
9. `error_page/error_page_factory.rs`: every template variant rendered with sample data.
10. Integration tests in `tests/`: router + lb + ssl_manager construction (no Pingora Session needed).
11. Re-measure: `cargo llvm-cov -p gateway --summary-only`.

## Todo List
- [ ] `router.rs` inline tests (≥6 cases)
- [ ] `lb.rs` inline tests (≥8 cases)
- [ ] `cache/backend.rs` + `cache/bootstrap.rs` inline
- [ ] `cache/stats.rs` inline (every counter + snapshot + reset)
- [ ] `ssl.rs` pure helper extraction + tests
- [ ] `ctx_builder/request_ctx_builder.rs` header-parsing branches
- [ ] `tiered/compiled_rule.rs` edge cases
- [ ] `protocol.rs` minor branches
- [ ] `error_page_factory.rs` every variant
- [ ] `tests/router_vhost_resolution.rs`
- [ ] `tests/lb_strategies.rs`
- [ ] `tests/cache_stats_lifecycle.rs`
- [ ] `tests/ssl_manager_lifecycle.rs`
- [ ] `cargo llvm-cov -p gateway --summary-only --ignore-filename-regex 'proxy\.rs|http3\.rs|tunnel\.rs|proxy_waf_response\.rs|response_cache_integration\.rs'` ≥ 85%
- [ ] Raw line% (no exclusions) ≥ 78%

## Success Criteria
- After exclusions of capped Pingora-coupled files: ≥ 85% line.
- Without exclusions: ≥ 78% line (acknowledged ceiling per Insights).
- `cargo check --tests -p gateway` clean.

## Risk Assessment
- **Medium**: ACME tests can be flaky if hitting real LE staging. Use only PEM-parsing helpers, never end-to-end.
- **Medium**: lb weighted distribution test requires statistical tolerance — use seedable RNG.
- **Low**: cache + filters already battle-tested; minor risk.

## Security Considerations
- SSL helpers must reject malformed PEM (assertion test) — catching parser-panic regressions.
- Router must reject Host header with embedded `\r\n` (assertion test).

## Next Steps
- Phase 11 CI gate uses `--ignore-filename-regex` for the capped files; document rationale in workflow.
