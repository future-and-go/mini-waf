---
phase: 3
title: "Load-time Validation & Loud Failure"
status: pending
priority: P2
effort: "6h"
dependencies: [2]
---

# Phase 3: Load-time Validation & Loud Failure

## Overview

Promote rule load to a structured status so a broken rule is *visible*, never silently disabled. Failed rules surface with reason in the admin UI; startup logs emit a one-shot audit summary.

This phase exists because the original silent-fail (CRS-930130 inert for unknown duration) proved that "rule didn't load" should never look like "rule passed." Apply the same "make invalid states unrepresentable" pattern at the operations boundary.

## Requirements

- `RuleLoadStatus { Loaded(CompiledRule), Failed { rule_id, file, reason } }` replaces the current `Option<CompiledRule>` / silent-skip.
- Startup log: one structured `rule_load_summary` event with `{loaded, failed, by_reason: {...}}`.
- Per-failure structured log: `rule_load_failed{rule_id, file, reason}` at `ERROR` level.
- Admin UI rule list shows `LoadFailed` state with reason in tooltip/badge.
- TDD: failing test before code change — load a YAML rule with missing `.data` file, assert engine reports `RuleLoadStatus::Failed`, assert it is NOT in the active rule set, assert audit log captured the failure.

## Architecture

```rust
pub enum RuleLoadStatus {
    Loaded(CompiledRule),
    Failed { rule_id: String, file: PathBuf, reason: String },
}

pub struct RuleLoadReport {
    pub loaded: Vec<RuleId>,
    pub failed: Vec<RuleLoadFailure>,
}

pub struct RuleLoadFailure {
    pub rule_id: String,
    pub file: PathBuf,
    pub reason: String,
}
```

Engine exposes `engine.load_report() -> &RuleLoadReport`. Admin API surfaces it.

Reason strings are stable enum-ish (used as metric labels later in Phase 5):
- `"missing_data_file"`
- `"data_file_too_large"`
- `"too_many_patterns"`
- `"path_traversal"`
- `"invalid_regex"`
- `"invalid_cidr"`
- `"unsupported_operator"`
- `"parse_error"`

## Related Code Files

- **Modify:**
  - `crates/waf-engine/src/rules/manager.rs` (load loop returns `RuleLoadReport`)
  - `crates/waf-engine/src/rules/registry.rs` (store + expose report)
  - `crates/waf-api/src/handlers/rules.rs` (or equivalent — surface failed rules in admin API response)
  - `apps/admin-ui/src/...` (rule list component — add `LoadFailed` badge)
- **Read for context:**
  - Current admin API response shape for rule list

## Implementation Steps

1. **TDD test first** — `crates/waf-engine/tests/rule_load_status_failure.rs`:
   - Fixture: YAML with `operator: pm_from_file, value: nonexistent.data`.
   - Assert: rule excluded from active set; `load_report().failed` contains entry with `reason: "missing_data_file"`.

2. Define `RuleLoadStatus` + `RuleLoadReport` in `rules/load_status.rs` (new module).

3. Refactor `manager.rs` rule-load loop:
   - Per rule, call `try_compile() -> Result<CompiledRule>`.
   - Map `Err(e)` → `RuleLoadStatus::Failed { reason: classify_error(&e) }`.
   - `classify_error` matches on anyhow error chain / downcasts to bring back the stable reason string.

4. Emit per-failure log at load time:
   ```rust
   tracing::error!(rule_id, file = %file.display(), reason, "rule_load_failed");
   ```

5. Emit one summary log after load completes:
   ```rust
   tracing::info!(
       loaded = report.loaded.len(),
       failed = report.failed.len(),
       by_reason = ?report.reason_breakdown(),
       "rule_load_summary"
   );
   ```

6. Admin API: add `failed_rules: [{rule_id, file, reason}]` to the rule-list response payload (or new endpoint `GET /api/rules/failed`).

7. Admin UI: render failed entries with red badge. Tooltip = reason string. Keep change small — one component edit.

8. Re-run `pm_from_file_pinning` + snapshot tests + new status test. All green.

## Success Criteria

- [ ] `rule_load_status_failure.rs` test passes.
- [ ] Missing-data-file rule logs `rule_load_failed` with stable reason string.
- [ ] Startup summary log emitted exactly once per load cycle.
- [ ] Admin UI shows failed rule with reason badge (manual verify).
- [ ] All existing tests pass; `cargo fmt --all -- --check` clean.

## Risk Assessment

| Risk | Mitigation |
|------|------------|
| Reason string drift breaks Phase 5 metrics labels | Centralise reason constants in `load_status.rs`. |
| Admin API contract break for existing consumers | Add field, don't repurpose existing keys. |
| Refactor of `manager.rs` introduces regression | Existing tests in `custom_rule_hot_reload.rs` cover load path — must stay green. |

## Out of Scope

- Hot reload (Phase 4).
- Prometheus metrics (Phase 5).
- Admin UI rule editor changes (only status display).
