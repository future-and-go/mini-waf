---
title: "FR-003 Rule Engine Completion — Implementation"
description: "Close 4 AC gaps in custom rule engine: wildcard operator, cookie-by-name, pre-compiled matchers, nested AND/OR groups. Strategy/Composite pattern. ≥95% coverage gate."
status: pending
priority: P0
effort: 3d
branch: feat/fr-003
tags: [waf, engine, fr-003, rules, custom-rules]
created: 2026-04-29
blockedBy: []
blocks: []
---

## Source
Design (verbatim source for ACs + chosen approach B): [`../reports/brainstorm-260429-1303-fr-003-rule-engine.md`](../reports/brainstorm-260429-1303-fr-003-rule-engine.md)
Requirements: [`../../analysis/requirements.md`](../../analysis/requirements.md) §3.1 FR-003, FR-022, FR-024.

## Scope
Close FR-003 acceptance: *Match by IP, Path, Header, Payload, Cookie; regex, wildcard, exact match, AND/OR (nested).*
Refactor `crates/waf-engine/src/rules/engine.rs` to introduce a recursive condition tree (Composite pattern) with pre-compiled matchers (Strategy pattern), back-compat with existing flat-array DB rules and YAML.

**Non-goals:** Full body streaming (FR-020), risk_score_delta wiring (FR-022/026), per-route/session/fp scoping (FR-023). Wired in later plans.

## Acceptance Criteria (8 cases — see brainstorm §5)
| # | Field | Operator | Sample |
|---|---|---|---|
| 1 | ip | cidr_match | 10.0.0.0/8 |
| 2 | path | exact (eq) | /login |
| 3 | path | wildcard | /api/*/admin |
| 4 | path | regex | `^/user/\d+$` |
| 5 | header(x-foo) | contains | bar |
| 6 | cookie(session) | eq | abc |
| 7 | body | contains | `<script>` |
| 8 | nested AND/OR | — | `(ip OR cookie) AND wildcard` |

## Design Patterns Applied
- **Composite**: `CompiledNode { Leaf | And | Or | Not }` recursive tree.
- **Strategy**: `Matcher` enum dispatches per-operator evaluation; pre-compiled state held inline.
- **Builder/Adapter**: `compile_rule()` adapts `CustomRule` (raw) → `CompiledRule` (eval-ready); legacy flat `Vec<Condition>` adapted to `And([Leaf,...])`.

## Phases

| # | File | Owner | Status | ACs |
|---|------|-------|--------|-----|
| 01 | [phase-01-schema-and-compile-step.md](phase-01-schema-and-compile-step.md) | engine.rs (types only) | done | scaffold |
| 02 | [phase-02-wildcard-and-matcher-strategy.md](phase-02-wildcard-and-matcher-strategy.md) | engine.rs, Cargo.toml | done | AC-3 |
| 03 | [phase-03-cookie-by-name-and-ctx.md](phase-03-cookie-by-name-and-ctx.md) | waf-common, engine.rs | done | AC-6 |
| 04 | [phase-04-nested-condition-tree.md](phase-04-nested-condition-tree.md) | engine.rs | done | AC-8 |
| 05 | [phase-05-acceptance-tests-and-bench.md](phase-05-acceptance-tests-and-bench.md) | tests/, benches/ | pending | AC-1..8 |
| 06 | [phase-06-docs-and-sample-rules.md](phase-06-docs-and-sample-rules.md) | rules/custom/*, docs/ | done | n/a |

## Coverage Gate
- `cargo llvm-cov --workspace -p waf-engine --html` ≥ 95% line coverage on `crates/waf-engine/src/rules/engine.rs` and `formats/yaml.rs`, `formats/json.rs` (custom-rule path only).
- Coverage measured on `cargo test -p waf-engine` + `tests/rule_engine_acceptance.rs`.

## Success Criteria
1. All 8 AC tests pass; 100% AC matrix covered.
2. Coverage ≥ 95% on touched files (gate, not advisory).
3. `cargo bench rule_eval` shows pre-compiled regex eval ≥ 5× faster than baseline.
4. Existing DB rules evaluate identically (regression test on legacy flat shape).
5. Hot-reload still <1s on 1k rule file.
6. p99 added latency from rule eval ≤ 0.5ms at 5k req/s.
7. Zero clippy warnings; cargo fmt clean; no `.unwrap()` outside `#[cfg(test)]`.

## Risks
| Risk | Mitigation |
|---|---|
| Schema migration breaks existing DB rules | Adapter wraps legacy flat `Vec<Condition>` as `And([Leaf,...])` in `from_db_rule()` — no DB migration |
| Pre-compile cost on hot-reload spike | Compile errors logged + rule skipped; `swap_from` keeps old set live until new ready |
| Glob semantics surprise | Document syntax in `rules/README.md`; reject empty/`**`-only patterns |
| Regex compile failure at load | Treat as compile error → rule skipped + warn log |

## Unresolved Questions
1. `RegexSet` for batched eval across rules sharing a field? → defer; benchmark first.
2. Cookie name case-sensitivity? Default **case-sensitive** per RFC 6265.
3. Glob `*` cross `/`? Default **no** (use `**`); matches `globset` defaults.
