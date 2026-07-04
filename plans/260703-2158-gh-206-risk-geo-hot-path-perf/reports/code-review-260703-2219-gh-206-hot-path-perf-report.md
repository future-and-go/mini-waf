# Code Review — GH-206 hot-path perf + GH-199 max-score convergence

Reviewer: code-reviewer agent | Date: 2026-07-03 | Branch: main-harness (uncommitted)

## Scope

- Files: `risk/store/redis.rs`, `risk/store/redis_lua.rs`, `risk/store/conformance.rs`, `engine.rs`, `risk/scorer.rs`, `risk/velocity/window.rs`, `geoip.rs`, `checks/geo.rs`, `waf-engine/Cargo.toml`, `Cargo.lock`
- LOC: ~579 added / 247 removed
- Blast radius checked: `RiskKey`/`index_keys` empty-key path, memory-store convergence parity, `risk_score` consumers, geo `iso_code` persistence into attack logs, velocity purge interaction, public contracts (`inspect()`, `RiskStore` trait)

## Overall Assessment

Implementation matches the plan and the Validation Session 1 decisions. All six acceptance criteria hold with evidence. No critical or high-severity defects found. Verification gates re-run locally: fmt, clippy (both feature sets), full lib suite — results match the stated 1409 passed / 4 failed (3 = pre-existing #198, 1 = docker-env).

## Acceptance Criteria — all met

1. **O(1) LRU, no per-op String alloc** — `lru::LruCache` get/push replace the old `VecDeque::retain` (O(capacity)) + `key.to_string()` per get. Note: `cache_key(key)` still builds one String per lookup — pre-existing and required for keying; the eliminated alloc is the cache-internal one, which is what #206 targeted. `redis.rs:74,109-111,198-207,270-274`.
2. **Single-RTT apply/force_max** — both are one `Script` invocation; owner resolve/converge + mutation inside one Lua execution. `MINT_OR_GET_OWNER_SCRIPT` and `resolve_or_mint_owner` deleted with no remaining references. (EVALSHA adds one extra RTT on first NOSCRIPT only.)
3. **Fast-path skips scoring** — all 5 pre-scoring exits (guard off, IP allow/block, URL allow/block) return `FastPath::Hit`; `inspect()` scores only on `Miss` (`engine.rs:677-687`). Behavioral test `fast_path_exits_skip_risk_scoring` asserts zero store writes on the whitelist path and a write on the clean path — real behavior proof, not a phantom test. Locally unexecutable (docker socket PermissionDenied, confirmed); compiles under `clippy --all-targets`; verified by code reading. Confirm CI executes it.
4. **Velocity clone-free / geo load-time normalization** — `windows.get(key)` hit path records through the read guard, no `RiskKey` clone (`SlidingWindow::record` is `&self`, atomics). Miss path falls to `entry` — the benign race serializes on the shard write lock, no lost counts; `purge_idle`'s `retain` blocks on held guards. Geo: rules uppercased in `load_rules`, `iso_code` uppercased in `parse_region`; `geo_matches` is alloc-free.
5. **#199 max-score convergence in Lua** — both scripts read all index-key owners, pick max `clamped_score` (missing state = 0), repoint all indices. Matches `store_trait` contract and memory-store behavior (`memory.rs:84-85`).
6. **Divergent-score conformance, both backends** — `test_apply_divergent_score_convergence` + `test_apply_converges_axes` in `conformance.rs`; memory runs them via `run_all` (passes), Redis via dedicated `apply_convergence_conformance` (passes against Valkey :16379). Note: `run_all` against live Redis still dies earlier at the #198 `is_new` assertion (`conformance.rs:34`), so inside `run_all` the new tests only execute for memory — the dedicated redis test is what covers the Redis side. Acceptable given #198 lands separately.

## Critical Issues

None.

## High Priority

None.

## Medium Priority

1. **Geo enforcement flip for lowercase-configured rules** (`checks/geo.rs:65-78`). Before: a rule with `iso_codes: ["cn"]` never matched (rule set held `"cn"`, geo side compared `"CN"`). Now it matches. This is the intended fix (test `lowercase_rule_iso_codes_match` documents it), but previously-inert rules will start blocking traffic after deploy. Call this out in changelog/release notes so a sudden geo-block on an existing host is traceable.
2. **`iso_code` case normalization leaks into persisted data** (`geoip.rs:165-168`). `ctx.geo` is stored into attack-log `geo_info` JSON; `waf-storage/repo.rs:377,408,1587,1882,1912` filter/group with exact `geo_info->>'iso_code' = $x`. If the xdb dataset ever emits non-uppercase codes, pre-change rows and post-change rows split under exact-match filters. No `.xdb` in-repo to verify casing. If the dataset is already uppercase (typical), this is a no-op — please confirm.

## Low Priority

3. **Tie-break parity divergence**: Lua keeps the *first* candidate in KEYS order on equal scores; memory `max_by_key` keeps the *last*. Both satisfy the max-score contract; observable only when tied-score owners differ in non-score fields. Not worth blocking; note for #198/#199 follow-ups.
4. **`fix_empty_contributors` string-patches cjson output** (`redis_lua.rs`). Safe today: applied only when `contributors` is empty, and RiskState then has no string-valued fields that could contain the literal `"contributors":{}`. Brittle if RiskState ever gains string fields. Also note this partially overlaps #198's "cjson `{}` contributors" finding — it was *necessary* here (empty-delta applies from the new conformance test would otherwise fail serde parse of `ApplyResponse`), but coordinate so the #198 fix doesn't double-patch.
5. **Unguarded `cjson.decode` on candidate states** in the convergence preamble: a corrupt state JSON now fails the whole apply (→ cache fallback + breaker increment). Same failure class existed before (old script decoded the winner's state); exposure widened from 1 to N candidates. `pcall` would degrade gracefully; not required.
6. **Cluster incompatibility documented, not new**: state keys computed inside Lua from ARGV, undeclared in KEYS. Old code already sent cross-slot multi-key EVALs, so Redis Cluster was never supported; module doc now states the single-instance assumption explicitly. Fine.
7. `NonZeroUsize::new(cache_capacity).unwrap_or(MIN)` silently clamps 0→1. Old hand-rolled cache degenerated to ~1 entry at capacity 0 anyway; no meaningful behavior change.
8. `lru_cache_eviction_recency_and_replace` tests the third-party crate's semantics rather than store logic. It pins the `push` promote/replace assumptions the store relies on — harmless, borderline redundant.

## Regression / Blast-Radius Checks (explicit list from task)

- **inspect() decision semantics**: every pipeline branch returns the same `WafDecision` as before; only `risk_score` changes (0 on the 5 fast-path exits — intentional, plan-approved). `risk_score` has no gating consumer — only the audit event reads it (`engine.rs:1115`); nothing in `prx-waf`/gateway consumes it.
- **Scoring moved pre→post pipeline**: scorer reads `client_ip`, `path`, `headers`, `cookies` — none mutated by pipeline checks; `scorer.score` remains the single production caller site. Output-equivalent for Miss branches.
- **cache_lookup fallback on Redis error**: apply error/timeout branches unchanged (cache → `RiskState::new`); `read()` untouched. `force_max` still propagates errors (as before).
- **Empty `RiskKey`**: `key.is_empty()` guards in read/apply/force_max short-circuit before script invocation, so the zero-KEYS Lua path (`SETNX KEYS[1]` on nil) is unreachable.
- **Velocity counts**: identical semantics; new-key race serializes on `entry`; `purge_idle` blocks on shard guards.
- **Geo match results**: identical for uppercase rules; lowercase rules now match (Medium #1 — intended fix). Country-name branch untouched.
- **Public contracts**: `inspect()` signature unchanged; `FastPath`, `ApplyResponse` private; `RiskStore` trait untouched. Known intentional: `ApplyResponse.owner_id` (private), `conformance::run_all` extended (test-only surface).
- **Repo patterns**: no `unwrap`/`expect` in prod paths (all in `#[cfg(test)]`); no lint suppressions added beyond pre-existing style.

## Verification Run (this review)

- `cargo fmt --check` — pass.
- `cargo clippy --workspace --all-targets --features waf-engine/redis-store -- -D warnings` — pass (exit 0).
- `cargo clippy --workspace --all-targets -- -D warnings` (default features) — pass (exit 0).
- `REDIS_TEST_URL=redis://127.0.0.1:16379 cargo test -p waf-engine --features redis-store --lib` — **1409 passed, 4 failed, 1 ignored**:
  - `engine::tests::fast_path_exits_skip_risk_scoring` — docker socket PermissionDenied (env, confirmed from panic).
  - `risk::store::redis::tests::basic_apply_and_read`, `conformance_redis::redis_apply_accumulates_score`, `conformance_redis::redis_store_passes_conformance` — all fail on `is_new` assertions = pre-existing #198 (`is_new = (state_json == nil)` visibly unchanged in the script middle).
- New tests pass: `apply_convergence_conformance` (Valkey), `memory_store_passes_conformance` (incl. new cases), `lowercase_rule_iso_codes_match`, `lru_cache_eviction_recency_and_replace`, window tests.
- Benches (Phase 5 regression guard) not run in this review — heavy; unverified.

## Commit Hygiene

Unrelated uncommitted files in the tree: `docs/stories/epics/E18-admin-api-completeness/README.md` (US-1806 row), `US-1806-*.md`, `docs/journals/2026-07-03-*.md`. Keep them out of the perf commit.

## Plan Task Status

Phases 1–4: implemented per phase files. Phase 5 (verification gate): fmt/clippy/tests green modulo documented pre-existing/env failures; bench step not evidenced. Plan front-matter still says `status: pending` — lead should update after landing (reviewer does not mutate plans).

## Recommended Actions

1. Land as-is; no blocking defects.
2. Add a changelog/release note for the lowercase-geo-rule enforcement flip (Medium #1).
3. Confirm xdb `iso_code` casing is already uppercase (Medium #2); if not, consider a note on attack-log filter behavior.
4. Confirm CI actually executes `fast_path_exits_skip_risk_scoring` (docker available) — it is the behavioral proof for criterion 3.
5. When fixing #198, account for the `fix_empty_contributors` patch already present (avoid double-patching) and align the Lua/memory tie-break if #198's rework touches convergence.
6. Run the Phase 5 benches (`tx_velocity_bench`, `risk_anomaly`, `rule_eval`, `access_lookup`) before or at landing if the plan gate is to be checked off with evidence.

## Unresolved Questions

1. Does the ip2region xdb dataset emit uppercase `iso_code` values? (Determines whether Medium #2 is a no-op.)
2. Is the geo lowercase-rule enforcement flip acceptable to ship silently, or does it need an operator-facing note?
3. Were the Phase 5 benches run anywhere? No evidence in the tree.
4. Does CI have docker for the new engine test (or a `PG_TEST_URL` secret)?
