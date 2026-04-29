---
title: "FR-003 CustomRule YAML File Loader"
description: "Load FR-003 CustomRule definitions from YAML files in rules/custom/ at startup + hot-reload, alongside the existing registry-format YAML rules. Schema-discriminated, in-memory only (no DB writes)."
status: pending
priority: P2
effort: 1d
branch: feat/fr-003
tags: [waf, engine, fr-003, rules, yaml-loader, hot-reload]
created: 2026-04-29
blockedBy: []
blocks: []
---

## Source

- Follow-up to: [`../260429-1311-fr-003-rule-engine/plan.md`](../260429-1311-fr-003-rule-engine/plan.md) (FR-003 engine work — done)
- Triggering question: phase-06 unresolved Q1 — "Add a YAML loader for the FR-003 CustomRule shape so samples can live alongside `rules/custom/*.yaml` and be loaded at startup?"
- Sample wire format (JSON, to be mirrored in YAML): [`../../rules/custom/fr003-samples/`](../../rules/custom/fr003-samples/)
- Schema reference: [`../../docs/custom-rules-syntax.md`](../../docs/custom-rules-syntax.md)

## Scope

Add a file-based loader for the FR-003 `CustomRule` engine (DB/API-driven today). Loader scans `rules/custom/*.yaml`, identifies files using a top-level discriminator (`kind: custom_rule_v1`), parses them into `CustomRule` values, and feeds them into `CustomRulesEngine` at startup. Existing registry-format YAML files in the same directory remain untouched.

Re-uses existing engine compile pipeline (`compile_rule`, `from_db_rule`-style adaptation) — no changes to `engine.rs` runtime behavior.

**Non-goals:**
- DB persistence of file-loaded rules (file is source of truth).
- Conflict resolution between file rules and DB rules with the same `id` (last-loader-wins by design — file load runs after DB load on `reload_rules`).
- Editing file rules through the admin UI / API (read-only on disk).
- New JSON file loader (DB API already covers JSON wire format).

## Approach (chosen)

**B-1: Schema discriminator + new sibling parser, in-memory merge.**

| Decision | Choice | Reason |
|---|---|---|
| Discriminator | Top-level YAML key `kind: custom_rule_v1` | Explicit, grep-able, no filename gymnastics. Existing registry YAML files have no `kind` field → silently skipped by new parser, picked up by existing parser as today. |
| Co-location | Same `rules/custom/` directory | User-requested. |
| Storage | `CustomRulesEngine.load_host` (in-memory) | Reuse existing eval pipeline. No DB writes → no migration / sync risk. |
| Host scoping | YAML file declares `host_code` (defaults to `"*"` global) | Matches DB rule semantics. |
| Hot-reload | New `notify::Watcher` on `rules/custom/`, debounced 500ms | Existing registry watcher lives elsewhere; cleaner to keep separate. |
| Precedence | File rules and DB rules coexist; both evaluated; first match wins per priority | Same as multi-DB-row case today — `priority` field disambiguates. |
| Conflict on same `id` | File load replaces same-host bucket entry by `id` after DB load | Deterministic; admin can read on-disk file in repo. |

**Rejected alternatives:**

- *B-2: Subdirectory `rules/custom-engine/*.yaml`.* Cleaner isolation but the user explicitly asked for "alongside existing files." Rejected.
- *B-3: File suffix `*.engine.yaml`.* Magical and easy to typo. Rejected vs explicit `kind:` field.
- *B-4: Sync file rules into DB rows on load.* Adds bidirectional consistency burden (who wins on conflict? DB or file?), DB writes from filesystem changes feel wrong for a stateless reverse proxy. Rejected.

## Wire Format (YAML)

```yaml
kind: custom_rule_v1            # REQUIRED discriminator
host_code: "*"                  # default "*" (global)
name: "Block wildcard admin paths"
priority: 100
enabled: true
condition_op: and               # used only when match_tree absent
conditions: []                  # legacy flat shape (still supported)
match_tree:                     # FR-003 nested form (preferred)
  and:
    - { field: "ip", operator: "cidr_match", value: "10.0.0.0/8" }
    - { field: "path", operator: "wildcard", value: "/api/*/admin" }
action: block
action_status: 403
action_msg: "Forbidden"
script: null                    # optional Rhai expression
```

A file may contain a single document or a YAML stream of multiple `---`-separated rules. Both supported.

## Phases

| # | File | Owner | Status | ACs |
|---|------|-------|--------|-----|
| 01 | [phase-01-yaml-parser.md](phase-01-yaml-parser.md) | `crates/waf-engine/src/rules/formats/custom_rule_yaml.rs` | pending | parse + tests |
| 02 | [phase-02-loader-and-engine-wire.md](phase-02-loader-and-engine-wire.md) | `crates/waf-engine/src/rules/custom_file_loader.rs`, `engine.rs` | pending | startup load |
| 03 | [phase-03-hot-reload.md](phase-03-hot-reload.md) | `custom_file_loader.rs`, `lib.rs` | done | watcher |
| 04 | [phase-04-docs-and-samples.md](phase-04-docs-and-samples.md) | `rules/custom/*.yaml`, `docs/custom-rules-syntax.md` | done | docs |

## Acceptance Criteria

1. A `rules/custom/foo.yaml` file with `kind: custom_rule_v1` loads at startup and rules are evaluated by `CustomRulesEngine`.
2. An existing `rules/custom/example.yaml` (registry format, no `kind`) continues to load via the existing pipeline; new loader skips it without warnings.
3. Editing/adding/removing a `kind: custom_rule_v1` file triggers reload within 1s; rule set updates atomically (no eval gap).
4. Bad YAML / invalid schema produces a single `warn!` log line and the file is skipped — service does not crash, other rules continue to load.
5. `host_code: "*"` rules match all hosts; specific `host_code` rules scope to that host (matches existing DB semantics).
6. ≥90% line coverage on `custom_rule_yaml.rs` and `custom_file_loader.rs` (excluding watcher I/O glue).
7. Zero clippy warnings; cargo fmt clean; no `.unwrap()` outside `#[cfg(test)]`.

## Success Criteria

1. The 3 sample JSON files at `rules/custom/fr003-samples/` are converted to YAML, placed in `rules/custom/`, and load on startup with no warnings.
2. `cargo test -p waf-engine` passes including new tests.
3. Existing `rules/custom/example.yaml` and `rules/owasp-crs/*.yaml` still load and behave identically.
4. Hot-reload smoke test (touch a file, observe reload log line) succeeds within 1s.

## Risks

| Risk | Mitigation |
|---|---|
| File watcher fires N events for one save (editor temp file dance) | Debounce 500ms; coalesce paths |
| Same `id` in file and DB → ambiguous behavior | File load runs after DB load on `reload_rules`; both keep their entries (different array indices). Document that operators should not duplicate IDs across sources |
| Operator pastes registry-format file with stray `kind` field | New parser will reject due to schema mismatch and warn — existing parser will skip files with `kind` (filter). No silent loss |
| Watcher leaks file handles on reload | Use `RecommendedWatcher` with bounded channel; rebind on config reload |
| Parse-then-compile cost on large file | Reuse `compile_rule` per entry; same cost as DB load. Bench if files >1k rules |

## Unresolved Questions

1. Do we want a CLI subcommand `prx-waf rules validate <file>` that parses + compiles without booting the proxy? Useful for CI; not required by ACs. → Defer to follow-up if requested.
2. Should `host_code` accept a list (`["a", "b"]`) for multi-host scoping? Current DB schema is single-host. → Out of scope; mirror DB semantics.
3. Should file-loaded rules show up in the admin UI listing? → No (read-only on disk, not in DB). UI can be enhanced later with a "static rules" tab.
