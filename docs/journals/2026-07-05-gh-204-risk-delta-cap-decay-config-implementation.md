# 2026-07-05 — GH-204: risk per-request delta cap + configurable decay + config validation

## What

Three fixes on branch `fix/gh-204-risk-delta-cap-decay-config` (stacked on
`fix/gh-201-redis-failmode-policy`):

1. **Per-request delta cap enforced.** `clamp_per_request_deltas` existed but was
   never called. Now wired into both entry points: `Scorer::score_with_l2` (sync
   path, after seed/anomaly/velocity/credit deltas are gathered) and the ingest
   worker's `process_job` (async path). Cap bounds one request's positive delta
   sum to 100 while preserving negative credits; the store fold's total-score
   clamp is a distinct, complementary op. Canary `force_max` stays uncapped by
   design (pin, not delta).
2. **`DecayConfig` honored by both backends.** `apply_decay`/`preview_decay` now
   take `&DecayConfig` instead of reading the `MAX_DECAY`/`MIN_CLEAN_STREAK`/
   `DECAY_RATE` consts. `MemoryRiskStore` gains `with_decay(DecayConfig)`
   (constructor injection — no `RiskStore` trait change); `RedisRiskConfig` gains
   a `decay` field fed into the Lua apply script ARGVs.
   `RedisStoreConfig::to_runtime_config(ttl, decay)` and the engine's
   `build_risk_store` thread the config through both backends. Decay settings are
   store-lifetime (no hot-reload; YAGNI). `decay_rate: 0` disables decay through
   the existing arithmetic — no special branch.
3. **`RiskConfig::validate()` wired into `from_path`.** Rejects `ttl_secs == 0`,
   `gc_interval_secs == 0` (would panic `tokio::time::interval`),
   `ingest.channel_capacity == 0` (would panic the bounded mpsc), unknown
   `store.backend`, and `decay.max_decay > 100`. `decay_rate: 0` and
   `min_clean_streak: 0` are valid. `reload.rs` is already fail-soft, so a bad
   YAML edit keeps the previous snapshot. Risk thresholds live in
   `TierPolicy.risk_thresholds` — out of scope here.

## Verified

- `cargo test -p waf-engine --lib --features redis-store "risk::"` → 273 passed.
- New tests: scorer end-to-end cap test (160 positive + −20 credit → score 80);
  conformance `test_oversized_batch_clamps_to_cap` added to `run_all` (both
  backends); `test_decay_honors_configured_rate` (rate 3) and
  `test_decay_disabled_when_rate_zero` as pub conformance fns — memory via
  `with_decay`, redis via `REDIS_TEST_URL`-gated tests; 8 validate() unit tests
  plus a `from_path` reject-without-panic test.
- `cargo clippy --workspace --all-targets` and `-p waf-engine --features
  redis-store` clean; `cargo build -p prx-waf` green.
- Full lib suite: 1449 passed; 6 `engine::tests::*` failures are the known
  docker-gated testcontainer set (no docker socket locally; CI covers).

## Gotchas

- **`StoreConfig` derived `Default` yielded `backend: ""`** — inconsistent with
  the serde default `"memory"`. Harmless before (engine only checks `== "redis"`)
  but `validate()` exposed it: `RiskConfig::default().validate()` failed. Fixed
  with a manual `Default` impl using `default_backend()`.
- The decay consts (`MAX_DECAY` etc.) remain as test/bench references and as the
  `DecayConfig` default values; runtime reads only the config.
- sed-inserting the `decay` field after `cache_capacity:` lines also matched the
  `Default for RedisRiskConfig` impl → duplicate field (E0062). Prefer targeted
  edits over blanket seds on struct-literal patterns.
- clippy `too_long_first_doc_paragraph` fires on 3-line first paragraphs — split
  doc comments with a blank `///` line.
