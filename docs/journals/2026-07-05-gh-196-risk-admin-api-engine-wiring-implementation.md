# 2026-07-05 — GH-196: risk admin API wired to the engine

## What

The risk admin API was a façade: `PUT /api/risk/config` wrote a file nothing
read, `store.backend: redis` was silently ignored, and actor clear/credit
returned `success: true` without touching any store. All four gaps closed
(plan `plans/260705-0953-gh-196-risk-admin-api-engine-wiring/`).

## How

- **Phase 1** — `Scorer<S: RiskStore + ?Sized>`; engine holds
  `ArcSwap<Scorer<dyn RiskStore>>`. `build_risk_store` constructs the store
  from `StoreConfig` (redis behind the `redis-store` feature, fail-soft
  fallback to memory with a 5s connect bound) and starts the memory purge
  loop before unsizing the Arc.
- **Phase 2** — `start_risk_watcher(&path)`: initial load through
  `replace_risk_config` (keeps canary in sync), then hot-reload via the
  generalized `RiskReloader` callback. Wired from `prx-waf` `init_async`
  next to the rate-limit/ddos/tx-velocity watchers. Backend changes at
  runtime log a warn — store swap requires restart (plan decision).
- **Phase 3** — PUT/GET round-trip `RiskConfig` through serde: read the
  file's `risk:` node, deep-merge the request body, validate with
  `serde_json::from_value::<RiskConfig>` (400 + no write on failure), write
  canonically. Deleted the hand-rolled `fe_to_yaml`/`yaml_to_fe` mappers
  that dropped `session_cookie`, `ingest.signal_weights`, `challenge`, and
  seed paths. FE form field fixed to `store.redis.key_prefix` (was
  `prefix` — never matched the serde name).
- **Phase 4** — new `RiskStore::clear` (memory: Arc-identity retain across
  all three axis maps; redis: `CLEAR_SCRIPT` Lua deleting state + index
  keys, errors propagate to the API as 5xx, LRU fallback cache dropped).
  Credit = negative-delta `apply` with new `ContributorKind::AdminCredit`
  (unit variant → round-trips the Lua path unchanged). Engine exposes
  `risk_clear_actor` / `risk_credit_actor`; handlers validate IP + amount
  (1..=100, default 25).
- **Phase 5** — conformance suite gained `clear` + AdminCredit cases (runs
  against memory locally, redis in CI via `REDIS_TEST_URL`); engine tests
  cover fallback, purge loop, watcher hot-reload, and a redis-gated
  backend-persistence case; waf-api tests prove merge preserves unmanaged
  sections and rejects invalid merged config.

## Gotchas

- `redis::aio::ConnectionManager::new` retries with backoff internally —
  an unreachable-by-drop host stalled startup (and the fallback test) for
  ~8 minutes. Bounded with `tokio::time::timeout(5s)`; test now 5s.
- cjson round-trip: contributor deltas pass through the apply script as
  opaque JSON, so AdminCredit needed zero Lua changes.
- Local docker socket unavailable: the 6 `spawn_engine` testcontainers
  tests fail locally; CI covers them.

## Verification

`cargo test --workspace --lib`: 1414 waf-engine + all other crates green
(6 docker-gated failures local-only). `cargo clippy --workspace
--all-targets --all-features` clean, also clean without `redis-store`.
`cargo fmt --check` clean. Admin-panel `tsc --noEmit` clean.
