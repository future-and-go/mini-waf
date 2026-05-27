---
phase: 6
title: "Regression Matrix Sweep"
status: pending
priority: P2
effort: "4h"
dependencies: [2, 3, 4]
---

# Phase 6: Regression Matrix Sweep

## Overview

Final exhaustive parameterised coverage. Phase 1 pins the known bug; Phase 6 makes sure no other `pm_from_file` / `contains_any` rule in the YAML tree is also inert, and that encoding-bypass paths (URL encode, mixed case, leading whitespace) all behave consistently.

## Requirements

- For EVERY `pm_from_file` rule in `rules/owasp-crs/*.yaml`: ≥3 representative patterns from its data file → expect 403.
- For EVERY `contains_any` rule: ≥2 representative payloads → expect 403.
- Negative cases per rule: at least one path/payload NOT in data file → expect pass-through.
- Encoding bypass matrix: `%2E` for `.`, mixed case, leading whitespace, double encoding.

## Architecture

Test file: `crates/waf-engine/tests/pm_matcher_regression_matrix.rs` (new).

Use `rstest` (if already in deps) or `#[test]` per case with shared fixture. Discover rule files at compile time via `include_str!` or runtime walk; pick the latter so adding a new rule file doesn't silently skip.

```rust
fn collect_pm_from_file_rules() -> Vec<(String /*rule_id*/, String /*data_file*/)>;
fn collect_contains_any_rules() -> Vec<(String /*rule_id*/, Vec<String> /*patterns*/)>;
```

For each rule, pick 3 random patterns from its data list (deterministic seed) as the positive cases.

## Related Code Files

- **Create:**
  - `crates/waf-engine/tests/pm_matcher_regression_matrix.rs`
- **Read:**
  - All `rules/owasp-crs/*.yaml` and `rules/owasp-crs/data/*.data`

## Implementation Steps

1. Write helper `walk_rules_dir()` that returns the list of `(rule_id, operator, data_file_or_patterns)` tuples for all `pm_from_file` + `contains_any` rules.

2. Generate positive cases: for each rule, sample 3 patterns from data file (deterministic — sort lexicographically, take first/middle/last).

3. Negative cases: per rule, hand-craft 1-2 paths/payloads that look similar but should NOT match.

4. Encoding bypass cases (only for `pm_from_file` rules where field is path-like):
   - Replace `.` → `%2E`
   - Upper-case the pattern
   - Prepend whitespace `%20`
   - Double-encode (`%252E`) — expect NO match unless we explicitly handle it (we don't; documented behaviour)

5. Run full suite. Any failure here = a CRS rule that's still inert post-Phase-2 → file blocker bug, don't ship.

6. CI integration: this test runs by default. Add a tag `regression-matrix` if useful for grouping.

## Success Criteria

- [ ] Every `pm_from_file` rule under `rules/owasp-crs/` has ≥3 positive + 1 negative test pass.
- [ ] Every `contains_any` rule has ≥2 positive + 1 negative test pass.
- [ ] Encoding bypass cases (single-encode, mixed-case, whitespace) all blocked.
- [ ] Double-encoding behaviour documented and tested (pass-through is intentional; document if so).
- [ ] No new test infra dependencies added beyond what's already in `Cargo.toml`.
- [ ] `cargo fmt --all -- --check` clean.

## Risk Assessment

| Risk | Mitigation |
|------|------------|
| Test suite grows large + slows CI | All cases share fixture (one engine load); parameterise inside one `#[test]` if perf becomes an issue. |
| Walking `rules/owasp-crs` couples test to vendored CRS version | Snapshot rule-id list at top of test; warn if mismatch (CI breaks loudly when CRS upgrade adds new rules — desired). |
| `restricted-files.data` content drift | Hand-pick stable canonical patterns (`.env`, `.htpasswd`) per rule rather than full random sample. |

## Out of Scope

- Performance benchmarks (use existing `benches/rule_eval`).
- New rules — only verify what's already shipped.
- Cross-host configuration matrix (each rule tested against default host).

## Unresolved Questions

- Confirm scope with whoever owns admin UI: does the rule-status surface already have a non-binary state (loaded / failed)? Phase 3 assumes a small frontend addition is acceptable.
- Should `.data` files be permitted under user-authored `<rules_dir>/custom/data/`, or restricted to vendored CRS subtree only? Affects `resolve_data_path()` policy in Phase 2.
- Retro-audit (Phase 5): log-only, Prometheus gauge, or both? Recommendation: both — confirm with ops.
