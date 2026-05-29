# Branch Divergence Audit: origin/main vs origin/release/stg

**Reviewer:** reviewer-1
**Date:** 2026-05-27
**Branches:** origin/main = c4d852ab (12 ahead), origin/release/stg = e8331bcb (22 ahead)
**Common ancestor:** af10edb5

---

## Summary

main carries cluster wire-up (5 commits, +2.4k LOC tests/src), scalability hardening (regex precompile + CrowdSec circuit breaker + DB batched audit + DB resilience), CI fixes, and clippy compliance — none ported to release/stg. release/stg carries 17 small-scope security/correctness fixes (PRs #71-#87) — none ported to main. Total diff: 121 files, +4.9k / -8.7k LOC including plan/report churn.

All 12 main-ahead commits map to FR-021/039/045 scope. All 17 release/stg-ahead fix commits map to in-scope hardening (FR-013-020, FR-036, FR-039). Branches have diverged structurally — three modules will produce non-trivial merge conflicts.

---

## Findings (Main-Ahead, Severity-Rated)

### [CRITICAL] Regex pre-compilation reverses release/stg's per-request size_limit fix

Evidence: ce449e2e changed `RuleEntry::from_rule -> Option<Self>` at `crates/waf-engine/src/rules/engine.rs:335-338`; load-time compile rejects bad regex. release/stg PR #73 (935ee36f) capped per-request `RegexBuilder::size_limit(1<<20)` at `crates/waf-engine/src/checks/tx_velocity/role_tagger.rs:39` and the eval-time arm of `engine.rs`. main's eval arm now returns BUG marker (`engine.rs:752-756` in main: `error!("BUG: regex condition reached uncompiled eval_one")`).

FR mapping: FR-021 (Hot-reload rules) line 61, FR-022 (Rule format) line 62; performance NFR p99<=5ms line 99.

Risk if merged naively: release/stg's defensive cap on `role_tagger.rs` (which has no precompile path on main either — verified main role_tagger.rs:39 still calls bare `Regex::new`) gets dropped during conflict resolution. Pre-compilation does NOT cover `role_tagger.rs`. If main merges down, the role_tagger DoS surface stays open.

Recommendation: when merging main → release/stg, keep BOTH: precompile guarantee for rule engine AND `RegexBuilder::size_limit(1<<20)` in role_tagger.rs. Treat role_tagger.rs:39 as an independent fix.

---

### [CRITICAL] release/stg lacks main's CrowdSec circuit breaker — FR-039 gap

Evidence: 6f39920a added `crates/waf-engine/src/crowdsec/circuit_breaker.rs` (218 LOC, Closed/Open/HalfOpen state). release/stg `crates/waf-engine/src/crowdsec/mod.rs` has no `pub mod circuit_breaker` declaration. Verified file absent: `git ls-tree origin/release/stg` returns nothing for `circuit_breaker`.

FR mapping: FR-039 (Circuit breaker — backend unresponsive → 503) line 79.

Risk if NOT in release/stg: AppSec endpoint outage cascades into per-request hangs. FR-039 explicitly required as P0.

Recommendation: cherry-pick 6f39920a into release/stg, OR document scope deferral. Module wires into AppSecClient via `crates/waf-engine/src/crowdsec/appsec.rs` — must port that diff together.

---

### [CRITICAL] release/stg lacks main's DbBatchWriter — FR-032 audit log throughput gap

Evidence: e7d7bf77 added `crates/waf-engine/src/logging/db_batch_writer.rs` (241 LOC, bounded MPSC 10k, batch INSERT chunked 1000, 100ms flush). release/stg `logging/mod.rs` lacks `pub mod db_batch_writer`. Per-detection `tokio::spawn` pattern in `engine.rs` survives on release/stg.

FR mapping: FR-032 (Structured audit log, SIEM-ingestible) line 72; performance NFR throughput >=5k req/s line 100.

Risk if NOT in release/stg: under attack-burst load each detection spawns a DB task — unbounded task graph → memory pressure → cascading proxy latency. Direct contradiction of FR-005 (DDoS auto-block) effectiveness.

Recommendation: port e7d7bf77 into release/stg before competition. Carries 6 file changes; engine.rs hook is the integration point.

---

### [IMPORTANT] release/stg lacks DB connection resilience — FR-039 partial coverage

Evidence: e7d7bf77 also added `retry_connect()` with exponential backoff (3 attempts), `acquire_timeout(5s)` on `PgPoolOptions`, `health_check_loop`, `StorageError::ConnectionFailed` variant at `crates/waf-storage/src/db.rs`. Verified absent on release/stg: `grep retry_connect` on release/stg db.rs returns 0 hits.

FR mapping: FR-039 (Circuit breaker / backend resilience) line 79; FR-038 (Configurable fail mode) line 78.

Risk if NOT in release/stg: PG flap during Attack Battle → indefinite acquire hang → request thread starvation.

Recommendation: same cherry-pick as DbBatchWriter (same commit). Test coverage: `crates/waf-storage/tests/` will need rebase.

---

### [IMPORTANT] main lacks ALL 17 release/stg fix wave PRs — security regression on merge

Evidence: release/stg-only commits not on main (file:line of fix verified for samples):
- PR #77 `c33c6f53` IPv4-compat IPv6 SSRF — `waf-common/src/url_validator.rs:216` (release/stg has, main missing)
- PR #78 `b2af5d63` wasmtime ResourceLimiter — `waf-engine/src/plugins/manager.rs:24,38` (release/stg has `ResourceLimiter` import; main missing)
- PR #71 `2b959537` WASM upload 16 MiB cap + name validation — `waf-api/src/plugins.rs` (release/stg only)
- PR #72 `f2e0d176` PEM field cap on cert upload
- PR #73 `935ee36f` per-request regex size_limit (also see CRITICAL #1 — see role_tagger gap)
- PR #79 `24a04da7` rule registry off-side atomic swap on hot-reload
- PR #80 `3a445e2b` late-joining peers in heartbeat sender
- PR #81 `e2adf330` lz4 snapshot 32 MiB decompress cap
- PR #82 `5b9753e2` reject stale/duplicate rule sync responses
- PR #83 `d844c120` drop PendingForwards on error paths
- PR #84 `45ebb706` h2 frame Vec growth cap in ConnCtx
- PR #85 `1d1434d6` reject non-UTF-8 body charset (new `checks/charset.rs`)
- PR #86 `b6c0fbdf` MemoryIdentityStore amortized cap eviction
- PR #87 `029828bc` case-fold Host header (router resolve/register/unregister)
- PR #78 also covers MAX_MEMORY_BYTES wasmtime limiter

FR mapping (line refs in analysis/requirements.md):
- #77 → FR-016 SSRF detection line 56
- #71/#72/#78 → FR-020 Request body abuse line 60, NFR resilience line 102
- #73 → FR-021/022 rule hot-reload + format line 61-62
- #79 → FR-021 Hot-reload rules line 61
- #80-83 → FR-045 BONUS clustering (out of scope per requirements line 90)
- #84 → FR-010 Device Fingerprinting line 50
- #85 → FR-020 Request body abuse, FR-017 Header injection line 57-60
- #86 → FR-010 / FR-025 cumulative risk line 50, 65
- #87 → FR-001 Full reverse proxy line 41

Risk if main becomes release base: 11 of 17 fixes touch P0 features. Merge direction matters — see Recommendation.

Recommendation: release/stg → main merge is the production-correct direction. main's scalability work (regex precompile + circuit breaker + DB batched audit + DB resilience) sits on TOP of the 17-PR security baseline. Reverse direction (main → release/stg) requires manual re-application of all 17 PRs since they touch overlapping code (rules/engine.rs, plugins/manager.rs, url_validator.rs).

---

### [IMPORTANT] Cluster mode wire-up (789aaa24 + ca562d7a + d5d4fe81 + 4867e3d8) is FR-045 BONUS scope

Evidence: 789aaa24 wires `NodeState-Engine bridge`, `RuleReloader`, `cluster_forward`, event batcher at `crates/waf-cluster/src/lib.rs:64-66, 130-260`. d5d4fe81 adds 1,860 LOC of integration tests across 9 files. ca562d7a fixes e2e script. 4867e3d8 adds 967 LOC of architecture docs.

FR mapping: FR-045 Auto Scaling (P1 BONUS, "Very High" difficulty) line 90; FR-043 Multi-region (P1 BONUS, "High") line 88; FR-044 Zero-downtime config sync (P1 BONUS, "High") line 89.

Risk if NOT in release/stg: zero impact on P0 score. Only relevant if team chases all three P1 cluster bonuses.

Recommendation: per scope guardrail, do NOT port cluster wire-up to release/stg unless explicit decision to chase FR-043/044/045. release/stg already has waf-cluster scaffolding (lib.rs, transport, election, sync); main adds runtime integration. Decision belongs to team lead, not reviewer.

---

### [IMPORTANT] CI infra (812f2ccd) is needed before any main-stage merge runs green

Evidence: 812f2ccd modified `.github/scripts/coverage-check.sh` to surface llvm-cov errors (set -e in $() swallowed exits). Without this fix, coverage CI silently passes even when llvm-cov panics. release/stg `coverage-check.sh` lacks the exit-code capture.

FR mapping: out-of-scope (CI infra), but aligns with rule `.claude/rules/team-coordination-rules.md` "Tests verify the FINAL code".

Risk if NOT in release/stg: false-positive coverage reports. release/stg has its own CI fix wave (bcab717b free disk + a35f525c trigger extension) so the two CI strategies will conflict on merge.

Recommendation: port 812f2ccd to release/stg in a separate `ci:` commit. Trivial conflict if any.

---

### [MODERATE] Clippy compliance commit (ed0f4004) is style-only churn

Evidence: 10 files, 58+/48- LOC. Pure clippy fixes (uninlined_format_args, doc_markdown, manual_let_else, etc.).

FR mapping: out-of-scope. NFR "Architecture & Code Quality" scoring line 160 — 15 pts weight.

Risk if NOT in release/stg: clippy strict mode (per [[pattern-clippy-strict-rust2024]]) blocks CI if release/stg ever upgrades lint config.

Recommendation: apply after security-fix merge to avoid conflict noise. Low priority.

---

### [MODERATE] tracing-subscriber registry feature drop (30f7e17c)

Evidence: 1-line `Cargo.toml` change removing redundant feature flag.

FR mapping: out-of-scope.

Risk: zero — feature already provided transitively.

Recommendation: trivial cherry-pick; can ride with clippy commit.

---

### [MODERATE] c4d852ab (skip non-rule YAML files) — already implicit in release/stg via existing constants?

Evidence: c4d852ab extends `NON_RULE_META_FILES` + adds `NON_RULE_DIRS` for `access-lists.yaml` and `threat-intel/`. Diff is `crates/waf-cluster/*` ONLY — does NOT touch waf-engine. Commit message references "rule scan" but stat shows waf-cluster integration tests + plan docs only. Title/body mismatch.

FR mapping: FR-008 Whitelist/Blacklist line 48, FR-042 IP Reputation Feed P1 BONUS line 87.

Risk: low. Title misleading — actual diff is plans + cluster test updates.

Recommendation: verify commit title accuracy before cherry-pick. If the YAML-skip logic exists elsewhere (planned for waf-engine), confirm with author. Possibly commit body refers to a different prior PR.

---

## Merge Conflict Hotspots (Ranked)

Predicted conflicts ordered by surface area when merging release/stg → main (or vice versa):

| File | main ∆ | stg ∆ | Conflict Type |
|------|--------|-------|----------------|
| `crates/waf-engine/src/rules/engine.rs` | +154/--- | +/-225 | OVERLAP — main precompiles, stg adds size_limit cap |
| `crates/waf-storage/src/db.rs` | +144/--- | --- | NON-OVERLAP — main only |
| `crates/prx-waf/src/main.rs` | +48 | +/- | OVERLAP — main wires DbBatchWriter+circuit breaker+log reload; stg modifies init |
| `crates/waf-cluster/src/lib.rs` | +87/--- | --- | NON-OVERLAP — main only (cluster wire-up) |
| `crates/waf-cluster/src/node.rs` | +77/--- | --- | NON-OVERLAP — main only |
| `crates/waf-engine/src/crowdsec/appsec.rs` | +57 | --- | NON-OVERLAP — main only |
| `crates/waf-engine/src/engine.rs` | +58 | +/- | OVERLAP — both modify hook list |
| `crates/waf-engine/src/plugins/manager.rs` | --- | +25 | NON-OVERLAP — stg only (#78) |
| `crates/waf-engine/src/checks/mod.rs` | --- | +2 | NON-OVERLAP — stg adds `pub mod charset` |
| `crates/waf-engine/src/logging/mod.rs` | --- | +2 | OVERLAP — main adds `pub mod db_batch_writer`, stg doesn't |
| `crates/waf-engine/src/crowdsec/mod.rs` | --- | +1 | OVERLAP — main adds `pub mod circuit_breaker`, stg doesn't |
| `crates/waf-engine/src/lib.rs` | --- | +11 | OVERLAP — both touch crate root |
| `crates/waf-api/src/handlers.rs` | --- | +157 | OVERLAP — main adds POST /logs/level, stg adds plugin handlers |
| `crates/waf-api/src/state.rs` | --- | +7 | OVERLAP — main adds LogLevelSetter, stg adds plugin state |
| `crates/prx-waf/src/victoria_logs/sidecar.rs` | --- | +298 | OVERLAP — main adds spawn_with_restart |
| `crates/waf-api/src/server.rs` | --- | +22 | OVERLAP — both touch router setup |
| `crates/waf-engine/src/checks/tx_velocity/role_tagger.rs` | --- | +/- | NON-OVERLAP — stg only (#73 cap) |

Plans/reports directory: 49 file churn, ignore on merge (regenerate).

---

## Equivalents Search Results

| Main commit | release/stg equivalent? |
|-------------|--------------------------|
| ce449e2e regex precompile | NO — release/stg uses lazy compile with size_limit cap (PR #73) |
| 6f39920a CrowdSec circuit breaker | NO — module absent |
| e7d7bf77 DB batched audit + resilience | NO — module absent |
| 8321114d scalability plan | N/A (plan doc only) |
| 789aaa24-d5d4fe81 cluster wire-up | PARTIAL — release/stg has scaffolding, main adds runtime |
| 812f2ccd CI llvm-cov surface | NO — different CI fix path on release/stg |
| ed0f4004 clippy | NO — separate clippy compliance trajectory |
| 30f7e17c tracing-subscriber feature | NO — trivial |
| c4d852ab YAML skip | UNCLEAR — title/diff mismatch (see MODERATE finding) |

Reverse direction:

| release/stg PR | main equivalent? |
|----------------|-------------------|
| #71 plugin upload cap | NO |
| #72 PEM cert cap | NO |
| #73 regex size_limit per-request | PARTIAL — main moves to precompile but role_tagger.rs unprotected |
| #77 SSRF IPv4-compat IPv6 | NO |
| #78 wasmtime ResourceLimiter | NO |
| #79 rule registry atomic swap | NO |
| #80-83 cluster fixes | NO |
| #84 h2 ConnCtx cap | NO |
| #85 non-UTF-8 charset reject | NO |
| #86 identity store eviction | NO |
| #87 Host case-fold | NO |

---

## Strategic Recommendation

1. **Merge direction: release/stg → main** (security baseline first, scalability on top).
2. **Pre-merge actions on release/stg:** cherry-pick e7d7bf77 (DB batched audit + resilience) and 6f39920a (CrowdSec circuit breaker) — both fill FR-039/032 P0 gaps independent of main's other work.
3. **During merge:** keep PR #73's role_tagger.rs size_limit cap (CRITICAL #1) — precompile pass does not cover that file.
4. **Defer:** cluster wire-up (789aaa24 et al) until team commits to FR-045 BONUS — not P0.
5. **CI:** apply 812f2ccd to release/stg in standalone `ci:` commit pre-merge.
6. **Clippy + tracing-subscriber:** ride after merge.

---

## Unresolved Questions

1. c4d852ab commit title mentions "non-rule YAML scan" but diff is cluster + plans only. Was the waf-engine YAML-skip logic pulled out in a separate uncommitted change?
2. Is release/stg the production deploy target, or is main? Decision drives merge direction.
3. Does the team intend to chase FR-043/044/045 BONUS? Affects whether cluster wire-up ports.
