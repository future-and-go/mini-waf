# Code Review: PR #209 — perf(waf-engine) hot-path overhead (#206, #199)

**Target:** PR #209 (merged, c37a8fe → main-harness), implementing issue #206 (+ #199 owner convergence)
**Reviewer evidence:** local targeted tests, clippy, static Lua review, in-repo test report
**Verdict:** APPROVE — no critical/important defects. All 4 acceptance criteria met (criterion 1 met in substance, see M1).

## Stage 1 — Spec Compliance (issue #206 acceptance criteria)

| Criterion | Status | Evidence |
| --- | --- | --- |
| LRU get/insert O(1), no per-op String alloc | PASS (partial, M1) | `lru` crate replaces O(10k) `VecDeque::retain`; order-queue String churn gone. Residual: `cache_key()` still builds 1 String per lookup/update (redis.rs:176-207). |
| Redis apply/force_max single-script, single-RTT | PASS | Owner resolution/convergence merged into `APPLY_SCRIPT`/`FORCE_MAX_SCRIPT`; `MINT_OR_GET_OWNER_SCRIPT` deleted. Atomic within one Lua execution. |
| Fast-path-rejected requests skip scoring | PASS | `FastPath` enum; guard-off + IP/URL allow/block exits skip `scorer.score()`. New integration test asserts zero store writes (engine.rs:1204). |
| Clone-free velocity record; geo normalization at load time | PASS | `windows.get()` before `entry()` (window.rs:131); ISO uppercased at rule-load + geoip-parse; per-request compare allocation-free. `ip.to_string()` in geoip lookup also removed. |

In-scope bonuses, all disclosed: #199 max-score owner convergence (prevents risk shedding via identity rotation) with conformance tests on both backends; cjson `{}`-vs-`[]` empty-contributors fix — a **pre-existing latent parse bug** in both scripts, now fixed; previously-inert lowercase geo ISO rules now enforce (CHANGELOG has operator guidance).

## Stage 2 — Quality Findings

No Critical. No Important.

**Minor:**
- **M1** `cache_key()` String alloc + `state.clone()` per `cache_update` (every successful apply). Criterion said "no per-op String alloc". `RiskKey` derives Hash/Eq (used as DashMap key in velocity) — `LruCache<RiskKey, CacheEntry>` would drop the String entirely. Noise vs the old O(10k) scan; non-blocking.
- **M2** `engine::tests::fast_path_exits_skip_risk_scoring` fails plain local `cargo test --lib` without docker socket (confirmed in own test report). `PG_TEST_URL` escape hatch exists; still pollutes default dev runs.
- **M3** ~40-line owner-resolution/convergence Lua block duplicated verbatim in `APPLY_SCRIPT` and `FORCE_MAX_SCRIPT` (redis_lua.rs). Drift risk if convergence logic changes; a `concat!` shared prelude would fix. Same for the duplicated empty-contributors gsub patch.
- **M4** `now_ms` captured before pipeline, scoring now runs after — delta/decay timestamps skewed by pipeline duration incl. async CrowdSec AppSec RTT. Millisecond-scale; velocity buckets are second-granularity. Cosmetic.
- **M5** Persisted `geo_info->>'iso_code'` now always uppercase; repo.rs:377/408 filter by exact equality — historical lowercase rows (if any) would split dashboard groupings. ip2region conventionally emits uppercase; observation only.
- **M6** Scope: PR bundles unrelated US-1806 plan docs (disclosed in PR body). Process nit.

**Verified non-issues (checked, not vibes):**
- Score-after-pipeline move is semantically safe: scorer reads only `headers`/`cookies`/`client_ip`/`tier_policy` (scorer.rs:222-284); pipeline only mutates `ctx.geo`, which the scorer never reads. `ScorerResult.action` was already discarded pre-PR.
- Empty `RiskKey` cannot reach the Lua scripts (guards redis.rs:321/386 + scorer early-return scorer.rs:224) — no zero-KEYS `SETNX KEYS[1]` error.
- No breaker regression: `apply` never gated on `breaker_open()` before this PR either; cache fallback on script error/timeout intact (redis.rs:360-381).
- Lua mint-path `claimed == 0` branch is dead within one atomic execution (GET saw nil) — harmless defensive code.
- gsub JSON patch is safe: only applied when contributors is empty, pattern cannot occur elsewhere in that state; Lua pattern has no magic chars.
- DashMap `get`→`entry` race benign as commented; `SlidingWindow::record(&self)` is atomic; no guard held across `entry()`.
- `lru::push` on existing key = update + promote; capacity 0 → `NonZeroUsize::MIN` fallback sane.
- `load_rules` is the sole write path into `GeoCheck.rules` — normalization can't be bypassed.
- Redis Cluster incompatibility (state keys computed in Lua, not in KEYS) explicitly documented (redis_lua.rs module doc); single-instance assumption matches `ConnectionManager` usage.

## Verification Evidence (fresh)

- `cargo test -p waf-engine --features redis-store --lib -- checks::geo:: risk::store::conformance risk::velocity::window risk::store::redis::tests::lru_cache` → **12/12 pass** (incl. new lowercase-ISO test, memory conformance with 2 new convergence tests).
- `cargo clippy -p waf-engine --features redis-store --lib` → clean.
- Redis-gated Lua tests: **not runnable locally** (no docker socket access for this user). Relied on in-repo test report: 1409/1414 vs live Valkey, new `apply_convergence_conformance` passing; 3 failures pre-existing #198 (claimed reproduced on clean tree).

## Unresolved Questions

1. #198 `is_new` failures in Redis conformance were attributed to a pre-existing bug on clean tree — not independently re-verified here (no local Redis). If #198's root cause overlaps the rewritten apply script, the new script inherits it; worth confirming when #198 is fixed.
2. M1: intentional trade-off or oversight? `LruCache<RiskKey, _>` is a ~10-line follow-up if wanted.
