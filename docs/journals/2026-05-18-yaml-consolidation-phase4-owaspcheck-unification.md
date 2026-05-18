# Phase 4: OWASPCheck Unification

**Date:** 2026-05-18
**Scope:** YAML Format Consolidation — Phase 4 of 6
**Commit:** `a9b5b30` on `main`
**Impact:** 488 insertions, 426 deletions across 5 source files

## What Changed

Replaced OWASPCheck's independent rule pipeline (`RuleSet` → `CompiledRule` → `CompiledMatcher`) with the shared `CustomRulesEngine`. OWASP Phase-13 now evaluates through the same engine as custom Phase-12 rules.

**Before:** Two separate evaluation pipelines with duplicated compilation, field matching, URL-decode, and matcher logic.
**After:** `OWASPCheck` is a thin wrapper around `CustomRulesEngine` with paranoia-level filtering.

## Key Design Decision: `specialised_op`

Core challenge: `detect_sqli`/`detect_xss` with `field: "all"` requires scanning path + query + body + headers (minus routing headers). This multi-field scanning doesn't map to a single `ConditionField` — auto-converting to `ConditionField::Body` would silently lose coverage.

Solution: Added `specialised_op: Option<Operator>` to `CustomRule`. When set, `eval_single_rule()` bypasses the condition engine entirely and dispatches to `eval_specialised()`, which performs the multi-field libinjection scan with URL-decode bypass protection (3-pass: raw, single-decoded, recursive-decoded).

## Other Decisions

- **Legacy backward compat:** Old `RuleSet` YAML format auto-converted via `legacy_parse_ruleset()` — preserves 22 unit tests without rewriting fixtures.
- **Virtual fields:** `path_length` and `query_arg_count` have no `ConditionField` equivalent. Converted to Rhai script expressions at parse time.
- **Paranoia filtering:** `check_owasp(ctx, max_paranoia)` on `CustomRulesEngine` — eval-time filtering, no separate engine instance needed.

## Code Review Findings (Fixed)

1. **query_arg_count behavioral diff** — Rhai `split("&").len()` counts empty segments; old code filtered them. Fixed with `.filter(|s| s.len() > 0)`.
2. **Misleading loop** — `for bucket in ["*"]` replaced with direct `if let` on `self.rules.get("*")`.
3. **Non-UTF8 body simplification** — Old code tested raw `Bytes` directly then lossy string. New code converts to lossy string first. Acceptable: libinjection operates on ASCII-ish tokens, and the `detect_sqli_non_utf8_body` test confirms random binary data is correctly ignored.

## Deleted Code

`RuleSet`, `YamlRule`, `YamlValue`, `CompiledMatcher`, old `CompiledRule`, `compile_rule()`, `is_routing_header()`, `get_field()`, `detect_injection()`, `matches()` — all replaced by unified engine paths.

## Verification

- 68 tests passing: 22 OWASP unit + 17 acceptance + 29 engine
- `cargo check` zero warnings
- `cargo fmt --all -- --check` passes

## Remaining Work

- **Phase 5** (Cleanup): Remove deprecated parsers, dead Registry types
- **Phase 6** (Integration Tests): End-to-end validation of all 490+ migrated rules
