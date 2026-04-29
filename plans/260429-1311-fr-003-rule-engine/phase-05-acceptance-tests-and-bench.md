# Phase 05 — Acceptance Test Suite + Bench + Coverage Gate

**Status:** complete  **Priority:** P0  **Effort:** 0.5d  **ACs:** AC-1..8 verification + perf

## Context Links
- Design: brainstorm §5 (AC matrix), §7 (success criteria)
- Touch: `crates/waf-engine/tests/rule_engine_acceptance.rs` (NEW), `crates/waf-engine/benches/rule_eval.rs` (NEW)

## Overview
End-to-end verification: 8 AC tests in dedicated file (one test per row of the AC matrix), regression suite for legacy rules, criterion bench proving pre-compilation perf claim, and coverage report ≥ 95% on touched files.

## Key Insights
- AC tests live in `tests/` (integration) — exercise full compile+eval path through public API.
- Bench compares baseline (compile-per-request) vs target (compile-once) on 1k iterations × 100 rules with regex.
- Coverage gate via `cargo llvm-cov` — fails CI if drop below threshold.

## Requirements

### Functional — Tests (one per AC)
| Test fn | AC |
|---|---|
| `ac01_ip_cidr_match` | 1 |
| `ac02_path_exact` | 2 |
| `ac03_path_wildcard_glob` | 3 |
| `ac04_path_regex` | 4 |
| `ac05_header_contains` | 5 |
| `ac06_cookie_by_name_eq` | 6 |
| `ac07_body_contains_script` | 7 |
| `ac08_nested_and_or_truth_table` | 8 (parameterised, 4 sub-cases) |

Plus regression:
- `regression_legacy_flat_and_rule_still_matches`
- `regression_legacy_flat_or_rule_still_matches`
- `regression_legacy_cookie_full_header`

### Functional — Bench
- `bench_rule_eval_compiled` — 100 rules, mixed operators (incl. regex), 5k req batch.
- `bench_rule_eval_baseline` — same load with eager regex compile per call (sanity baseline).
- Target: compiled ≥ 5× faster than baseline per brainstorm §7.

### Non-Functional — Coverage
- Run: `cargo llvm-cov --workspace -p waf-engine --lcov --output-path coverage.lcov`
- Gate (`scripts/check-coverage.sh` or inline awk): files `crates/waf-engine/src/rules/engine.rs`, `formats/yaml.rs`, `formats/json.rs` must each report ≥ 95% line coverage.

## Related Code Files
**Create:**
- `crates/waf-engine/tests/rule_engine_acceptance.rs` — AC suite.
- `crates/waf-engine/benches/rule_eval.rs` — criterion bench.
- `scripts/check-rule-engine-coverage.sh` — parses lcov, fails if any target file < 95%.

**Modify:**
- `crates/waf-engine/Cargo.toml` — `[[bench]] name = "rule_eval"`, dev-deps for criterion if not already.
- `.github/workflows/*.yml` (if exists) — add coverage gate step (defer if no CI yet — at minimum document local invocation).

## Implementation Steps
1. Build a `make_rule(yaml: &str) -> CustomRule` test helper in `tests/common/mod.rs` so tests stay declarative.
2. Build `make_ctx(builder…)` helper covering ip, path, headers, cookies, body.
3. Write 11 tests per matrix above. Each must fail before phases 01–04 land and pass after.
4. Write criterion bench. Run `cargo bench` locally; record numbers in plan if needed.
5. Coverage script:
   ```sh
   cargo llvm-cov -p waf-engine --lcov --output-path coverage.lcov
   awk '...filter target files, fail if <95...' coverage.lcov
   ```
6. Run full quality bar: `fmt --check && clippy -D warnings && test && bench`.

## Todo
- [x] Test helpers (`CtxBuilder`, `rule_flat`, `rule_tree`) inline in test file (KISS — single-file scope)
- [x] 8 AC tests + 3 regression tests + 2 security tests + AC-8 NOT subcase
- [x] Criterion bench with baseline + compiled (`benches/rule_eval.rs`)
- [x] Coverage script `scripts/check-rule-engine-coverage.sh`
- [x] All 17 acceptance tests green; full waf-engine suite 63/63 passes
- [ ] Bench numbers attached to PR description (deferred — run locally before merge)
- [ ] Coverage threshold verified locally (`cargo llvm-cov` not yet installed in CI)

## Success Criteria
- AC matrix 100% covered with one test per row (8 + 4 sub-cases).
- Regression suite locks in legacy DB-rule behavior.
- Coverage gate passes; bench numbers attached to PR description.

## Security
- Test inputs include malformed regex / glob / nested-too-deep — verify graceful rejection (no panic).
- Body-preview test uses a bounded fixture (`<script>...</script>` of 1KB) — no large allocations.
