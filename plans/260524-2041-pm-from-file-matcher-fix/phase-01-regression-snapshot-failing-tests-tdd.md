---
phase: 1
title: "Regression Snapshot & Failing Tests (TDD)"
status: pending
priority: P1
effort: "4h"
dependencies: []
---

# Phase 1: Regression Snapshot & Failing Tests (TDD)

## Overview

Write the safety net first. Two test bundles:

1. **Pinning tests** — exercise `pm_from_file` / `contains_any` against real CRS YAML rules. MUST FAIL on `main`. Become regression guards after Phase 2.
2. **Snapshot tests** — capture current `DetectSqli` / `DetectXss` behaviour from `rule_engine_acceptance.rs` so Phase 2's refactor (moving them out of `eval_specialised`) is provably non-regressive.

No production code changes in this phase. Pure test scaffolding.

## Requirements

- Pinning tests: assert `DetectionResult { rule_id: "CRS-930130", action: Block }` for `/.env`, `/.envrc`, `/.ENV`, `/%2Eenv`, `/path/with/.htpasswd`.
- Pinning tests for `contains_any`: pick one rule each from `xss.yaml` + `php-injection.yaml` against a representative payload.
- Snapshot tests: every existing `DetectSqli`/`DetectXss` test case in `rule_engine_acceptance.rs` reproduced (or asserted via a known-input → known-output table) so we can replay them after the dispatch move.
- All pinning tests MUST FAIL on `main` (proving the bug pins).
- All snapshot tests MUST PASS on `main` (proving no behavioural drift later).

## Architecture

Tests live in `crates/waf-engine/tests/pm_from_file_pinning.rs` (new file). Use the same fixture harness as `yaml_rule_loading_integration.rs` — load real YAML from `rules/owasp-crs/`, build engine, craft `RequestCtx`, assert result.

Snapshot capture: read existing assertions in `rule_engine_acceptance.rs` for `DetectSqli`/`DetectXss`, copy the input/output pairs into a parameterised test table in `crates/waf-engine/tests/sqli_xss_behavior_snapshot.rs` (new file). This isolates the contract from the existing test file so accidental edits to acceptance.rs don't silently invalidate the snapshot.

## Related Code Files

- **Create:**
  - `crates/waf-engine/tests/pm_from_file_pinning.rs`
  - `crates/waf-engine/tests/sqli_xss_behavior_snapshot.rs`
- **Read for context (no edits):**
  - `crates/waf-engine/tests/yaml_rule_loading_integration.rs` (fixture pattern)
  - `crates/waf-engine/tests/rule_engine_acceptance.rs` (source of sqli/xss assertions)
  - `rules/owasp-crs/lfi.yaml` (rules 930120, 930121, 930130, 930140)
  - `rules/owasp-crs/data/restricted-files.data` (patterns to assert match)
  - `rules/owasp-crs/xss.yaml`, `rules/owasp-crs/php-injection.yaml`

## Implementation Steps

1. Inventory current `DetectSqli`/`DetectXss` test coverage:
   ```bash
   grep -nE "DetectSqli|DetectXss|detect_sqli|detect_xss" crates/waf-engine/tests/*.rs
   ```
   List every test name + input/expected-result triplet.

2. Write `sqli_xss_behavior_snapshot.rs` with one `#[test]` per case from step 1. Each test must:
   - Build engine from a minimal in-memory YAML rule using the operator.
   - Run via the public eval path used today (NOT direct `eval_specialised` call — we need to exercise the dispatch).
   - Assert the same outcome as `acceptance.rs`.
   - `cargo test sqli_xss_behavior_snapshot` → all green on `main`.

3. Write `pm_from_file_pinning.rs`:
   - Helper `fn load_crs_rules() -> Engine` reading `rules/owasp-crs/lfi.yaml` + `xss.yaml` + `php-injection.yaml`.
   - Parameterised cases:
     - `(path="/.env", expect=Block, rule="CRS-930130")`
     - `(path="/.envrc", expect=Block, rule="CRS-930130")`
     - `(path="/.ENV", expect=Block, rule="CRS-930130")`  ← case-insensitive
     - `(path="/%2Eenv", expect=Block, rule="CRS-930130")`  ← URL-decode
     - `(path="/etc/passwd", expect=Block, rule="CRS-930120")`  ← lfi-os-files.data
     - `(path="/innocuous", expect=Pass)`  ← negative case
   - One `contains_any` case per file (xss.yaml + php-injection.yaml).
   - `cargo test pm_from_file_pinning` → all FAIL on `main`. Document this in the test file's module-level comment.

4. Add `cargo test --test pm_from_file_pinning -- --ignored` toggle? No — keep tests un-ignored so CI surfaces the failure as a deliberate red. Mark in commit message: "tests added to pin known bug; will turn green in phase 2."

5. Verify with full suite — no other tests should newly fail because of these additions:
   ```bash
   cargo test -p waf-engine
   ```
   Snapshot tests green. Pinning tests red. Everything else unchanged.

## Success Criteria

- [ ] `crates/waf-engine/tests/sqli_xss_behavior_snapshot.rs` created and ALL tests pass on `main`.
- [ ] `crates/waf-engine/tests/pm_from_file_pinning.rs` created and ALL tests FAIL on `main` for the documented reason.
- [ ] No existing test changes its pass/fail status as a side effect.
- [ ] `cargo fmt --all -- --check` clean.

## Risk Assessment

| Risk | Mitigation |
|------|------------|
| Test fixture diverges from real loader path → false-negative snapshot | Use the public engine entry point (same one production uses) instead of calling internals. |
| `restricted-files.data` content changes upstream → pinning test breaks unexpectedly | Hardcode the assertion against `.env` / `.envrc` (canonical patterns that won't move). |
| Existing acceptance tests already cover sqli/xss but only via in-process eval, not via YAML load → snapshot misses the dispatch | Snapshot tests load via YAML, not direct API. |

## Out of Scope

- No production code changes.
- No new operators added.
- No admin UI work.
