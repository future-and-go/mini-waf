# Risk Config Admin-UI E2E — Run Results

**Date:** 2026-07-07 · **Result: 35/35 PASS** (0 fail) · elapsed 63s
**Suite:** `tests/e2e/run-risk-config.sh` · **Branch:** desmond-e2e-testing

## How it was run

```bash
cargo build --release -p prx-waf            # current binary (see finding below)
bash tests/e2e/run-risk-config.sh           # self-manages the risk override stack
bash tests/e2e/render-report.sh tests/e2e/out tests/e2e/out/aggregated
```

Stack: `docker-compose.e2e.yml` + `docker-compose.risk-override.yml` on ports
26880 (proxy) / 26827 (admin); risk enabled, memory store, tier thresholds
`allow=10 / challenge=30 / block=60`. Score-raise = crafted `X-Forwarded-For`
anomaly (+10/req, unpinned); canary trap `/canary/trap`; actor IP `172.19.0.1`.

Artifacts: `tests/e2e/out/risk-config/{results.json,junit.xml,summary.md}`;
aggregated into `tests/e2e/out/aggregated/` (render-report `SUITES` now includes
`risk-config`).

## Coverage vs. global success criteria

- Every UI-exposed setting has a **persistence** assertion (PUT→GET), evidence logged.
- Every **observable** setting has a **behavioral** assertion with observed data-plane values.
- `store.*` + `gc_interval_secs`: persistence-only, reason logged.
- Metrics/actors stubs: excluded, logged.
- Suite emits the three artifacts and is in `render-report.sh`.
- Runs green against the compose stack.

## Findings (asserted as real contract, never hidden)

1. **PUT validates structure, not semantics.** `PUT /api/risk/config` with a
   well-typed but invalid `store.backend` (`postgres`) returns **HTTP 200** and
   persists it. The engine's reload `validate()` is the only backstop (rejects
   it, keeps the prior snapshot; data plane stays healthy — verified). The plan
   assumed 400. Consider validating semantically in the API before write.
2. **Decay params, `ttl_secs`, and `gc_interval_secs` are boot-only.** The
   reload watcher swaps the config snapshot but never rebuilds the store:
   `MemoryRiskStore` caches `DecayConfig` (memory.rs) and `build_risk_store`
   captures `ttl_ms` + starts the purge loop once at construction (engine.rs).
   A PUT persists but does not take effect until restart, and — unlike
   `store.backend` — **no warning is logged**. The admin UI's decay/ttl controls
   silently no-op until restart. Decay + ttl expiry proven behaviorally at the
   boot fixture; the `decay_rate=0` (constant) case is covered by
   `crates/waf-engine/src/risk/decay.rs` unit tests + the persistence round-trip.

## Test results

| | Test | Evidence |
|---|------|----------|
| ✅ | `health.public` |  |
| ✅ | `auth.login` |  |
| ✅ | `smoke.risk-enabled` | crafted XFF raised score to 10 (risk live + enforce) |
| ✅ | `smoke.canary-enforced` | HTTP 403 action=block score=100 |
| ✅ | `persist.ttl_secs` | PUT 1234 → GET 1234 |
| ✅ | `persist.gc_interval_secs` | persistence-only (no black-box signal) |
| ✅ | `persist.enabled` / `.restore` | false → true round-trip |
| ✅ | `persist.store.backend` | persistence-only (redis) |
| ✅ | `persist.store.redis.url` | persistence-only |
| ✅ | `persist.store.redis.key_prefix` | persistence-only |
| ✅ | `persist.decay.min_clean_streak` / `decay_rate` / `max_decay` | 7 / 9 / 42 |
| ✅ | `persist.canary.enabled` / `ban_ttl_secs` / `paths` | true / 99 / ["/persist-a","/persist-b"] |
| ✅ | `persist.reject.bad-type` | ttl_secs:"nan" → HTTP 400 |
| ✅ | `persist.reject.bad-type.file-untouched` | ttl_secs stays 1234 |
| ✅ | `persist.backend.api-accepts-unvalidated` | FINDING #1: backend=postgres → HTTP 200 |
| ✅ | `persist.backend.engine-backstop` | data plane still scores after invalid backend PUT |
| ✅ | `persist.merge.challenge/ingest/seed-survives` | unmanaged sections survive PUT (deep-merge) |
| ✅ | `behave.enabled` | on: score=20 ; off: score=0 |
| ✅ | `behave.ttl_secs` | boot ttl=5s: raised=30 → after idle>ttl+gc(7s): 0 (purged) |
| ✅ | `behave.decay.step-down-to-floor` | raised=50 → non-increasing → floor max_decay=0 |
| ✅ | `behave.boot-only-settings` | FINDING #2: decay params + ttl_secs + gc_interval_secs boot-only + unit coverage |
| ✅ | `behave.credit` | score 30, credit -25 → 5 |
| ✅ | `behave.clear` | clear → removed:true, then score 0 |
| ✅ | `behave.canary.path-swap` | /canary/trap 403/block → after swap trap 404/allow, swapped 403/block |
| ✅ | `behave.canary.enabled-toggle` | disabled → /canary/swapped 404/allow (not blocked) |
| ✅ | `behave.canary.ban_ttl_secs` | post-trap clean req 403 (banned) → after ttl(3s) 200 (unbanned) |
| ✅ | `exclude.metrics-stub` | GET /api/risk/metrics v1 stub — excluded |
| ✅ | `exclude.actors-stub` | GET /api/risk/actors v1 stub — excluded |

## Unresolved questions

- Findings #1 and #2 are product behaviors the suite documents. Whether to
  **fix** them (API-side semantic validation; hot-reloadable decay or a warning)
  is a product decision, out of this suite's scope.
