# Phase 04 — Docs + Sample YAMLs

**Status:** done  **Priority:** P2  **Effort:** 0.1d  **ACs:** docs only

## Context Links

- Existing FR-003 schema doc: `docs/custom-rules-syntax.md`
- Existing JSON samples: `rules/custom/fr003-samples/*.json`
- Phase 01 wire format: see plan.md "Wire Format (YAML)"

## Overview

Convert the 3 JSON samples to YAML, drop them in `rules/custom/`, update the schema doc with a "File-Based Loading" section.

## Requirements

1. Three YAML files in `rules/custom/`:
   - `fr003-sample-wildcard-admin.yaml`
   - `fr003-sample-cookie-session.yaml`
   - `fr003-sample-nested-blacklist.yaml`
2. Each carries `kind: custom_rule_v1` + a YAML comment header explaining intent.
3. `docs/custom-rules-syntax.md` gains a new section:
   - "File-Based Loading" — discriminator, defaults, hot-reload behavior, conflict semantics with DB rules.
4. Existing `rules/custom/fr003-samples/` JSON dir gets a README pointer noting "for API/DB import; see *.yaml in parent dir for file-loaded equivalents."
5. Update `docs/codebase-summary.md` to mention `rules/custom/*.yaml` accepts FR-003 schema when `kind: custom_rule_v1` set.

## Todo

- [x] 3 YAML samples
- [x] Schema doc update
- [x] JSON samples README pointer
- [x] codebase-summary.md note

## Success Criteria

- `cargo run -- run` (or unit test) loads the 3 YAML files at startup with no warnings.
- `python3 -c "import yaml; yaml.safe_load(open('...'))"` returns a dict with `kind == "custom_rule_v1"` for each.

## Next Steps

→ none. Plan complete after this phase.
