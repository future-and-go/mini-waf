# Code Review: Phase 4 — Sync API Validation & Parser Cleanup

**Date:** 2026-05-18
**Reviewer:** code-reviewer
**Commit:** 98133c7 (HEAD)
**Scope:** 5 files, ~20 net LOC changed (excluding example.yaml rewrite)

---

## Overall Assessment

Clean, low-risk phase. All four issues from the plan are addressed. Cargo check/clippy/tests pass. Two non-blocking findings below — one stale error message (will confuse API consumers), one design tension worth documenting.

---

## Critical Issues

None.

---

## High Priority

### H1. Error message does not list `"builtin"` (stale string)

**File:** `crates/waf-api/src/rule_sources_api.rs:145`

```rust
return Err("source_type must be one of: local_file, local_dir, remote_url");
```

The `ALLOWED_SOURCE_TYPES` array was expanded to include `"builtin"` (line 127), but the error message on line 145 was not updated. An API consumer who sends an invalid `source_type` will see a message that omits a valid option. Worse, if someone reads the error message to learn the allowed values, they will not know `"builtin"` is valid.

**Fix:**
```rust
return Err("source_type must be one of: local_file, local_dir, remote_url, builtin");
```

### H2. No unit test covers `"builtin"` source type validation

The existing `validate_rejects_unknown_source_type` test (line 362) only checks that `"ftp_pull"` is rejected. There is no positive test that `"builtin"` is accepted. If someone later removes `"builtin"` from the array, no test catches the regression.

**Suggested test:**
```rust
#[test]
fn validate_accepts_builtin_source_type() {
    let r = req("owasp-builtin", "builtin", None, None);
    assert!(validate_request(&r).is_ok());
}
```

---

## Medium Priority

### M1. Design tension: `"builtin"` accepted by CREATE endpoint but module docs say otherwise

Lines 18-20 of the module doc explicitly state:

> Built-in sources (OWASP/bot/scanner) are NOT stored in the table — they are hardcoded in the frontend's "Built-in Sources" panel and managed via `[rules].enable_builtin_*` flags in the TOML config.

Adding `"builtin"` to `ALLOWED_SOURCE_TYPES` means users can now `POST /api/rule-sources` with `source_type: builtin` and it will be inserted into the DB. The engine's `RuleManager` creates `Builtin` sources from config flags, not from the DB. So a user-created "builtin" row in `rule_sources` table is a dead entry — it will be listed in the admin UI but never loaded.

**Options:**
1. **Accept and document.** Keep `"builtin"` in `ALLOWED_SOURCE_TYPES` for the `GET` listing path (so builtin rows returned from the DB pass frontend validation) but add a comment explaining the design. This is the lowest-risk option if the FE only needs to display builtin rows in the list.
2. **Accept for GET, reject for POST.** Add an explicit check in `create_rule_source()` that rejects `source_type: "builtin"` with a message like `"builtin sources are managed via config, not the API"`.
3. **Remove from CREATE validation.** If the FE never sends `builtin` in a POST, remove it from `ALLOWED_SOURCE_TYPES` and handle it only in the listing DTO.

The current approach (option 1 without the comment) is functional but may confuse operators who create a "builtin" source and wonder why it has no effect. At minimum, add a comment near line 127.

### M2. `legacy_map_field()` log level change may increase log volume

Changing `debug!` to `warn!` in `owasp.rs:465` is correct for consistency with the sister function. However, if any deployed YAML rules use an unrecognized `field` value that previously went unnoticed at `debug!` level, promoting it to `warn!` will surface new log entries in production. This is the desired behavior (making hidden misconfigurations visible), but operators should be aware. No action needed — just a deployment awareness note.

---

## Low Priority

None.

---

## Positive Observations

- All 7 example rules set `enabled: false` — correct guard against accidental blocking
- Multi-document YAML (`---` separator) used correctly in example.yaml
- Severity fixes are comprehensive: found and fixed all 5 occurrences across both `data-leakage*.yaml` files, not just the one originally flagged
- `custom_file_loader` tests confirm the new example format loads correctly via `custom_rule_yaml::parse`
- `parse_pattern_field_to_condition()` already fixed in Phase 3 — no redundant work

---

## Verification

| Check | Result |
|-------|--------|
| `cargo check` | Clean |
| `cargo clippy` | Zero new warnings |
| Unit tests | 1,757 pass |
| `severity: error` remaining | 0 (grep confirms) |
| `custom_rule_v1` format valid | Yes — matches parser schema |

---

## Recommended Actions

1. **[H1] Fix the stale error message** on line 145 to include `"builtin"` — 1-line change
2. **[H2] Add a unit test** for `"builtin"` source type acceptance
3. **[M1] Add a comment** near `ALLOWED_SOURCE_TYPES` explaining that `"builtin"` exists for listing consistency but builtin sources are config-managed, not API-created — or alternatively reject `"builtin"` in the POST handler

---

## Unresolved Questions

1. Does the admin UI frontend ever send `source_type: "builtin"` in a POST request, or is `"builtin"` only needed for GET/list display? This determines whether M1 needs option 2 vs option 1.
