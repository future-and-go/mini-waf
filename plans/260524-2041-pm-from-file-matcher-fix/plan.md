---
title: "pm_from_file / contains_any Matcher Unification Fix"
description: "Fix silent-fail of pm_from_file / contains_any operators. Unify into Matcher enum, delete specialised_op dispatch path, preserve all existing sqli/xss behaviour."
status: complete
priority: P1
branch: "main"
tags: [security, waf-engine, rules, tdd, refactor]
blockedBy: []
blocks: []
created: "2026-05-24T13:45:06.578Z"
createdBy: "ck:plan"
source: skill
---

# pm_from_file / contains_any Matcher Unification Fix

## Overview

CRS-930130 (`/.env` block) is `enabled: true, action: block` but inert at runtime. Root cause: dual dispatch path — `pm_from_file` and `contains_any` get routed into `specialised_op` by the YAML parser, but `eval_specialised()` only implements `DetectSqli` / `DetectXss`, leaving the other two operators in a silent `_ => false` catch-all. Same blast radius affects every `pm_from_file` rule in `rules/owasp-crs/lfi.yaml` and every `contains_any` rule in `xss.yaml` / `php-injection.yaml`.

**Design pattern applied:** "Compile to a uniform executable artifact at load time. Make invalid states unrepresentable." The parser's only allowed output becomes a `Matcher` that is itself executable; failure to construct one rejects the rule loudly at load time.

**Regression-safety contract (per user request: "not break any part already tested"):** Phase 1 snapshots current `DetectSqli` / `DetectXss` behaviour against `rule_engine_acceptance.rs` + `custom_rule_hot_reload.rs` before any refactor. Phase 2's diff is gated on those tests staying green.

Source brainstorm: [`plans/reports/brainstorm-260524-2033-pm-from-file-matcher-fix.md`](../reports/brainstorm-260524-2033-pm-from-file-matcher-fix.md)

## Phases

| Phase | Name | Status |
|-------|------|--------|
| 1 | [Regression Snapshot & Failing Tests (TDD)](./phase-01-regression-snapshot-failing-tests-tdd.md) | Complete |
| 2 | [Unify Matchers & Delete Specialised Dispatch](./phase-02-unify-matchers-delete-specialised-dispatch.md) | Complete |
| 3 | [Load-time Validation & Loud Failure](./phase-03-load-time-validation-loud-failure.md) | Complete |
| 4 | [Hot Reload of .data Files](./phase-04-hot-reload-of-data-files.md) | Complete |
| 5 | [Observability & Retro-audit](./phase-05-observability-retro-audit.md) | Complete |
| 6 | [Regression Matrix Sweep](./phase-06-regression-matrix-sweep.md) | Complete |

## Key Dependencies

- `aho-corasick` crate (already in tree, used by `crates/waf-engine/src/checks/sensitive.rs`)
- Existing hot-reload watcher in `crates/waf-engine/src/rules/hot_reload.rs`
- Existing acceptance suite — must stay green at every phase boundary

## Success Criteria (Plan-Level)

1. `curl http://<waf>/.env` → 403 with `rule_id=CRS-930130` in audit log.
2. `/%2Eenv`, `/.ENV`, `/path/.envrc` → also 403 (URL-decode + case-insensitive).
3. `rule_engine_acceptance.rs` + `custom_rule_hot_reload.rs` stay green at every phase boundary — no `DetectSqli`/`DetectXss` behavioural drift.
4. Rule with missing `.data` file fails loudly at load (log + admin UI badge), never silently disables.
5. Editing `restricted-files.data` at runtime takes effect within one debounce window without restart.
6. `cargo fmt --all -- --check` and `cargo check` clean. No new `.unwrap()` / `.expect()` in production paths.

## Dependencies

<!-- No cross-plan dependencies detected. Recent plans 260518-yaml-format-consolidation and 260519-admin-panel-update-custom-rule touch adjacent files but are already complete. -->
