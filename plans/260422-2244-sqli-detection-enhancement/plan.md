---
name: SQLi Detection Enhancement
date: 2026-04-22
status: active
blockedBy: []
blocks: []
brainstorm: plans/reports/brainstorm-260422-2244-sqli-detection-enhancement.md
---

# Plan — Enhance SQL Injection Detection

## Goal
Meet acceptance criteria: classic, blind, time-based, UNION-based SQLi across URL params, headers, JSON body. Enhance existing `crates/waf-engine/src/checks/sql_injection.rs` — do NOT rewrite.

## Scope
- IN: `crates/waf-engine/src/checks/sql_injection.rs` and new companion modules, `DefenseConfig` or new `SqliScanConfig`, admin reload endpoint.
- OUT: other checkers (XSS, RCE, etc.), detection engine core, proxy layer, DB schema.

## Design (from brainstorm)
1. Extend `RegexSet` with boolean-blind + error-based patterns.
2. JSON body walker triggered by `Content-Type: application/json`.
3. Header scanning (default all, configurable allow/deny, size-capped).
4. Per-parameter attribution via `form_urlencoded`.
5. Hot-reloadable `SqliScanConfig` via `ArcSwap` (same pattern as masking plan).
6. Criterion bench enforcing p99 < 500 µs.
7. Modularize into 3 files to respect 200-line cap.

## Phases
| Phase | File | Status |
|-------|------|--------|
| 01 | [phase-01-patterns-and-modularize.md](phase-01-patterns-and-modularize.md) | DONE |
| 02 | [phase-02-json-and-query-param.md](phase-02-json-and-query-param.md) | DONE |
| 03 | [phase-03-header-scan-and-config.md](phase-03-header-scan-and-config.md) | in-progress |
| 04 | [phase-04-bench-and-tests.md](phase-04-bench-and-tests.md) | todo |

## Dependencies
- `regex::RegexSet` (already)
- `serde_json` (already)
- `arc_swap` (already — `geoip.rs`)
- `url::form_urlencoded` (verify via `cargo tree -p waf-engine | grep url`)
- `criterion` dev-dep (verify; add if missing)

## Verify (definition of done)
- All acceptance criteria covered by ≥20 unit tests (matrix: 4 attack types × 3 locations)
- Integration test through engine
- `cargo bench --bench sql_injection` p99 < 500 µs
- `cargo fmt --all -- --check`, `cargo clippy --workspace --all-targets --all-features -- -D warnings`
- Zero regression: `cargo test --workspace` stays green
- OWASP CRS SQLi sample (if available under `rules/owasp-crs/`) → every labeled positive sample detected

## Non-Goals
- NoSQL, GraphQL, ML-based detection, differential-response blind detection

## Open Questions
- Global `SqliScanConfig` vs per-host override? → Recommend global v1; add per-host later if needed
- Bench hardware baseline? → Document CPU model in bench README; CI informational-only, workstation gates merge
