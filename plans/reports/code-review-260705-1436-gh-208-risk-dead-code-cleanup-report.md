# Code Review — GH-208 risk dead-code cleanup (uncommitted, fix/gh-208-risk-dead-code-cleanup)

## Scope
- 52 files, +122/−232, per plan `plans/260705-0958-gh-208-risk-dead-code-cleanup/`
- Code changes confined to: `risk/store/store_trait.rs`, `risk/scorer.rs`, `risk/store/memory.rs`, `tests/risk_scorer_extended.rs`; remaining ~48 files comment-only
- Review by reading only (controller holds target-dir lock); test evidence supplied by controller: lib risk:: 253 pass, conformance 5 pass, risk_scorer_extended 14 pass, fmt + clippy `-D warnings` clean

## Verification Results

### (a) No dangling references to deleted items — PASS
- `grep -rn RiskKeyBuilder\|with_velocity_threshold` across repo: zero hits.
- `with_seed` hits are unrelated symbols only (`XxHash64::with_seed` in gateway filters, `RandomState::with_seeds` in vendored tinyufo).
- `RiskKeyBuilder` was never re-exported from `risk/store/mod.rs` or `risk/mod.rs` (only `RiskStore`), so the deleted surface is exactly the direct path with no callers.

### (b) force_max semantic equivalence — PASS
- `state.rs:130-135` `reclamp()` is `clamped_score = raw_score.clamp(0, 100) as u8`. No configurable max bound, no pin interaction, no other clamp rule. `raw_score = 100` → `clamped_score = 100` unconditionally.
- Ordering in `memory.rs:197-203` is safe: `reclamp()` runs before `pinned_until_ms` is set, but `reclamp` does not read pin state, so ordering is irrelevant.
- Redis `FORCE_MAX_SCRIPT` untouched as planned; conformance (memory 5 pass) asserts clamped==100.

### (c) Phase-4 sweep genuinely comment-only — PASS
- Strict diff scan (`-U0`, all `+/-` lines, excluding the four phase-1..3 files): every changed line in the sweep files starts with `//`, `//!`, `///`, or block-comment continuation. Only non-comment changes outside crates/ are the plan-file `status: pending → completed` flips.
- All 10 changed attribute lines (`#[must_use]` ×7, `#[test]` ×2, `#[tokio::test]` ×1) trace to the phase-1/2 deletions.

### (d) Rewritten comments accurate — PASS (10+ files spot-checked)
- `check.rs`: "before rate-limit (`Phase::RateLimit`)" — verified `Phase::RateLimit = 11` exists in `waf-common/src/types.rs:428`; rewrite preserves the old "Phase 11" meaning in durable form.
- `per_fp.rs`: rewrite *improves* accuracy — old comment claimed "`RequestCtx` does not yet carry a `device_fp` field" (stale; the field exists and is used by tx_velocity session fallback). New text correctly narrows the gap to "`Detector::evaluate` does not yet read the device fingerprint".
- `aggregator_impl.rs`: "(65536 per plan)" / "per §3.3 of the plan" → behavior-descriptive; constant unchanged.
- `memory.rs`, `conformance.rs`, `state.rs`, `config.rs`, `canary.rs`, `decay.rs`, `seed/mod.rs`, `degrade.rs`, `worker.rs`, `sequence.rs`, `store/mod.rs`, `risk/mod.rs`: all rewrites describe current behavior correctly; no meaning lost, no new false claims.
- Plan AC grep (`Phase |phase-|FR-0|§`) over `risk/**` + `checks/ddos/**`: zero hits (each pattern run individually, all exit 1).

### (e) Public contract changes limited to intended deletions — PASS
- Deleted pub items: `RiskKeyBuilder` (+Default impl), `Scorer::with_seed`, `Scorer::with_velocity_threshold`. No workspace consumer outside the deleted tests (grep-verified across all crates incl. waf-api, gateway, prx-waf).
- No re-export list edits; `pub use` surfaces in `risk/mod.rs` / `store/mod.rs` unchanged.
- Import cleanup in `store_trait.rs` correct: `IpAddr`/`SessionId` removed from module scope, `IpAddr` re-imported inside `#[cfg(test)]` where still used. Clippy `-D warnings` clean confirms no orphans.

### (f) Test migration preserves coverage intent — PASS
- Seed test: `Scorer::new` + `set_seed(seed)` + live `score()` + `Allow` assertion retained; rename to `set_seed_then_score_allows` drops the removed-API name as planned.
- Deleted `with_velocity_threshold_constructor` was a phantom test: it ended `let _ = r;` with **zero assertions** — deleting it loses nothing. Actual `VelocityLayer` breach behavior is directly unit-tested in `risk/velocity/mod.rs:105-151` (thresholds 0/2/100/1000 incl. breach), plus pipeline-level `tx_velocity_integration.rs`.

## Findings

### Critical / High
None.

### Low (informational, no action required)
1. **Plan citation imprecision**: the plan justifies the velocity-test deletion via `tx_velocity_integration.rs:242` (the `checks/tx_velocity` subsystem), but the direct `VelocityLayer` breach coverage actually lives in `risk/velocity/mod.rs` unit tests. Conclusion (coverage preserved) holds either way; the deleted test asserted nothing.
2. **Out-of-scope residue (correctly left alone)**: `waf-common/src/types.rs:443` still carries an `FR-005` comment on `Phase::Ddos`; waf-engine crate-level CLAUDE.md also uses FR labels. Both are outside the plan's stated sweep scope (`risk/**` + `checks/ddos/**`) — noting for completeness, not requesting change (surgical-change rule).

## Acceptance Criteria
- [x] Dead items removed with dedicated tests (P1, P2); `UpdateResult` bools deliberately untouched per dropped claim
- [x] `force_max` derives via `reclamp()` (P3); semantically identical, conformance green
- [x] AC grep returns zero hits in scoped dirs (P4)
- [x] fmt/clippy/test gates green (controller-verified)

## Verdict
Behavior-preserving as claimed. No blocking or high-priority issues. Ready to land (rebase ordering vs GH-196/GH-202 per plan's soft-ordering notes remains the controller's call).

Status: DONE
Summary: All six checks pass. Deletions are clean with no dangling refs or contract leaks; force_max reclamp is provably equivalent (raw.clamp(0,100), no other bounds); phase-4 sweep is strictly comment-only and rewrites are accurate (per_fp.rs even fixes a stale claim); deleted velocity test was assertion-free. Two Low informational notes only.
