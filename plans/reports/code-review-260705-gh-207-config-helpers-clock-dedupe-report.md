# Code Review — GH-207 config helpers + clock dedupe (working tree vs c9742e2)

## Scope
- Files: 16 source files (10 waf-api, 6 waf-engine) + 2 new modules (`crates/waf-api/src/config_files.rs`, `crates/waf-engine/src/time.rs`) + 4 plan-status docs
- LOC: +113 / -440 (net -327)
- Focus: behavior-preserving dedupe refactor; acceptance criteria (a)-(e)
- Scout findings: all clock-path dependents and helper callers enumerated by grep; no orphaned callers found

## Overall Assessment
Clean, faithful dedupe. Extracted helpers are byte-for-byte semantically identical to the removed copies (same tmp-name scheme `with_extension("yaml.tmp")`, same mkdir→write→rename order, same serde paths, same JSON response shapes). Clock unification preserves epoch-ms semantics. No critical or high findings.

## Critical Issues
None.

## High Priority
None.

## Medium Priority
None.

## Low Priority / Informational (pre-existing, not regressions)
1. **No fsync before rename** in `write_yaml_str` (`config_files.rs:38-52`): rename is atomic for readers but not durable across a crash — a power loss just after rename can leave an empty/partial file on some filesystems. Pre-existing in all nine removed copies; out of scope for a behavior-preserving refactor, but now a single fix site. Candidate backlog item.
2. **Concurrent-writer race**: two simultaneous PUTs to the same config file share one tmp filename; last rename wins and an interleaved write can rename a mixed tmp. Pre-existing; unchanged.
3. **Time-source swap in `process_job`** (`worker.rs:96`): `chrono::Utc::now().timestamp_millis()` → `SystemClock` (`SystemTime`-based). Both are wall-clock UNIX epoch ms; drift is nil. Accepted as behavior-preserving.
4. **Remaining clock duplicates elsewhere** (mention only, per surgical-change rule): `checks/mod.rs:79-98` (`test_clock`), `checks/rate_limit/check.rs:110` and `checks/rate_limit/store/memory.rs:135` (local epoch-ms helpers). Not in scope for GH-207; possible follow-up dedupe.

## Acceptance Criteria Verification
- **(a) Behavior-preserving in 9 migrated modules** — PASS. Diff-audited each module: only helper bodies removed; handler logic, response envelopes (`{success, data, total}`), config file names, and error *statuses* unchanged. `challenge_api.rs` keeps its local `read_yaml` (malformed file → `BadRequest`), now with an explanatory doc comment. `geo_api::read_rules` rewrite over `read_yaml_opt` is equivalent for all three failure modes (missing file, parse error, missing/non-array `rules` → `vec![]`). Internal 500 text drift (`"write tmp:"`→`"write:"`, `"yaml serialize:"`→bare) is within accepted scope.
- **(b) No touchpoint regressions** — PASS.
  - No remaining local `resolve_path`/`read_yaml_opt`/`write_yaml` duplicates in waf-api (grep-verified; only `config_files.rs` defines them).
  - `per_tier.rs:31` (`super::clock::Clock`) and `per_tier.rs:154` (`super::super::clock::test_utils::MockClock`) resolve through the shim; `#[cfg(test)] pub use crate::time::test_utils;` preserves the old cfg-gating exactly.
  - Integration tests (`tests/ddos_soak.rs:34`, `tests/ddos_scenarios/mod.rs:75,163`, `tests/ddos_integration.rs:122,225,311,406`) use only `Clock`/`SystemClock` via the shim (they define their own `MockClock`), and both are re-exported unconditionally. `detector/mod.rs:17` `pub use clock::{Clock, SystemClock}` still resolves.
  - `ScoringAggregator::start` caller `tests/ddos_risk_bump_acceptance.rs:22` unaffected — `start`/`start_with_capacity` signatures unchanged; both now delegate to `start_with_clock(..., Arc::new(SystemClock))`.
  - `unix_now_ms` fully deleted (grep: zero references); replacement `SystemClock::now_ms` is logic-identical (0 on pre-epoch, saturate to `i64::MAX`).
- **(c) No public contract break** — PASS. `risk/ingest/mod.rs` declares `mod worker;` (private) and re-exports only `Job`, so the `spawn_worker`/`process_job` clock params are crate-internal. `start_purge_loop` is technically `pub` on the exported `MemoryRiskStore`, but grep confirms the single caller is `engine.rs:372` (workspace-internal crate, no external consumers) — accepted per stated scope.
- **(d) Existing patterns** — PASS. `mod config_files;` (private) sits alphabetically in `waf-api/lib.rs` (cluster < config_files < crowdsec); `pub mod time;` alphabetical in `waf-engine/lib.rs` (rules < time < validated_fetch). Module-level and item doc comments present. Clippy pedantic/nursery are workspace `warn` (root `Cargo.toml:133-134`); new code carries no obvious pedantic triggers (`map_or_else` used, `#[must_use]` on constructors, `missing_errors_doc` does not fire on the non-exported `config_files` items). Not independently re-run (see Metrics).
- **(e) No plan/issue IDs in comments or test names** — PASS. New test `lag_is_deterministic_under_mock_clock` and all new comments are ID-free. The `"65536 per plan"` comment in `aggregator_impl.rs` is pre-existing, untouched (correctly left per surgical-change rule).

## Edge Cases Checked
- Malformed-YAML handling divergence between `challenge_api` (BadRequest) and shared `read_yaml_opt` (silent default) is deliberate and now documented at the site.
- New MockClock lag test is genuinely deterministic: single shared clock stamps submit time and worker measurement; asserts exact 250 ms via `avg_lag_ms()` (getter verified at `metrics.rs:107`, correct for 1 sample). Not a phantom test — it would fail if `process_job` reverted to wall-clock.
- `ScoringAggregator` gains a `clock` field; struct had no `Debug` derive to break.

## Positive Observations (risk calibration)
- `checks/ddos/detector/clock.rs` shim keeps every legacy path compiling with zero call-site churn in 4 integration test files — the lowest-risk way to move the module.
- Clock is injected at both submit (`aggregator_impl.rs`) and measure (`worker.rs`) ends, so lag is measured against one time source — this fixes a latent chrono-vs-SystemTime mixed-source inconsistency in the old code.

## Recommended Actions
1. None blocking. Optionally file a backlog item for fsync-on-write durability in `write_yaml_str` (single site now).

## Metrics
- Tests: implementer-reported green (waf-api --lib 118; waf-engine --lib 255 + risk:: 99). Not re-run here to avoid target-dir lock contention with the in-flight workspace test run; clippy-clean claim likewise implementer-reported.
- Linting: no new suppressions, no `allow` attributes added; one pre-existing `#[allow(clippy::cast_possible_truncation)]` *removed* along with `unix_now_ms`.

## Plan Status
`plans/260705-0958-gh-207-waf-api-config-helpers-dedupe/plan.md` marks all 3 phases Completed; phases 1-2 verified against the diff. Phase 3 (RiskConfig serde verify) is a verification-only phase — its evidence is the journal + test runs, consistent with no `risk_api.rs` behavior change in this diff.

## Unresolved Questions
- None blocking. Full-workspace test result (running separately) should be confirmed green before merge.
