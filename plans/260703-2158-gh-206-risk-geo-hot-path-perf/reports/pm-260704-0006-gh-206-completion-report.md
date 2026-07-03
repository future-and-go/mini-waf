# PM Completion Report — GH-206/199 hot-path perf

Plan: `plans/260703-2158-gh-206-risk-geo-hot-path-perf/` — **completed** (all 5 phases, all checkboxes, frontmatter synced).

## Acceptance Criteria Evidence

| # | Criterion | Evidence |
|---|-----------|----------|
| 1 | LRU get/insert O(1), no per-op String alloc | `lru::LruCache` at redis.rs:79; hand-rolled cache deleted; LRU unit tests pass |
| 2 | Redis apply/force_max single-script single-RTT | Exactly 2 `invoke_async` sites (redis.rs:347, 405), one per op; merged scripts in redis_lua.rs |
| 3 | Fast-path rejects skip scoring cost | `FastPath{Hit,Miss}` enum in engine.rs; scorer only on Miss; test `fast_path_exits_skip_risk_scoring` (docker-gated, runs in CI via `cargo test --workspace --all-features`) |
| 4 | Velocity clone-free; geo normalization at load | `windows.get(key)` hit path (window.rs:131); typed IP dispatch geoip.rs; load-time uppercase geo.rs; test `lowercase_rule_iso_codes_match` |
| 5 | #199 convergence = max-score owner in Lua | Convergence preamble in both Lua scripts; picks max clamped_score, repoints index keys |
| 6 | Divergent-score conformance test both backends | `test_apply_divergent_score_convergence` in conformance.rs run_all (memory) + `apply_convergence_conformance` (Valkey :16379) — both pass |

## Verification Gate Results

- `cargo fmt --check`: pass
- `cargo clippy --workspace --all-targets --features waf-engine/redis-store -- -D warnings`: pass (also without feature)
- Lib tests default features: 1390/1391 (1 fail = docker-env, local-only)
- Lib tests redis-store + `REDIS_TEST_URL=redis://127.0.0.1:16379` (Valkey): 1409/1414 — 4 fails = 1 docker-env + 3 pre-existing #198 (`is_new` vs real Redis; verified failing on clean tree via git stash)
- waf-common: 51/51
- Bench spot-check (`--quick`): tx_velocity_record_existing 265 ns, tx_velocity_record_new 2.3 µs, anomaly_layer 779 ns, velocity_layer 140 ns, scorer_score_with_l2 2.08 µs, access_lookup 77–276 ns, rule_eval_compiled_100rules_miss 15.6 µs — all sane, no regressions vs expectations

## Subagent Reports

- Code review: `reports/code-review-260703-2219-gh-206-hot-path-perf-report.md` — DONE_WITH_CONCERNS, 0 blocking. Mediums: (a) previously-inert lowercase geo rules now enforce (intended bug-fix direction; operator note needed); (b) iso_code uppercasing reaches persisted attack-log `geo_info` filters (low risk; ip2region emits uppercase)
- Tests: `reports/test-260703-2219-gh-206-hot-path-perf-report.md` — DONE, no regressions

## Environment Findings (for user)

- Local docker socket inaccessible to user `cesc` (not in docker group) — blocks ALL testcontainers integration tests locally, not just the new one. `PG_TEST_URL` override added to the new engine test mirroring `REDIS_TEST_URL` convention.
- Valkey dev service at 127.0.0.1:16379 (not 6379); Postgres at 127.0.0.1:15432.
- Pre-existing #198: Lua `is_new = (state_json == nil)` always false on real Redis (GET returns Lua `false`). 3 redis-gated tests fail on any tree. Preserved verbatim per scope; note: the cjson `fix_empty_contributors` gsub partially overlaps #198 territory — coordinate the eventual #198 fix.

## Unresolved Questions

1. Post #206/#199 issue comments now or after commit/push? (comments drafted, held for approval)
2. Operator-facing note for geo enforcement flip — changelog location?
