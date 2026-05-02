# Brainstorm: FR-004 Rate Limiting

**Date:** 2026-05-02
**Requirement:** FR-004 — Sliding window per IP + per user-session; token bucket for burst
**Related:** FR-005 (DDoS auto-block), FR-023 (per-scope rules), FR-036/037/038 (fail-close/open per tier)

---

## 1. Acceptance Criteria (extracted)

From `analysis/requirements.md`:

| Source | Criterion |
|---|---|
| FR-004 | Sliding window per **IP** |
| FR-004 | Sliding window per **user-session** |
| FR-004 | **Token bucket** for burst |
| NFR | p99 latency overhead ≤ 5ms (rate-limit hot path is part of this budget) |
| NFR | ≥ 5,000 req/s baseline |
| Constraint | Standalone mode → in-memory; Cluster mode → Redis |
| FR-023 | Scopable: global / per-tier / per-route / per-IP / per-session |
| FR-036/037/038 | Behavior on backend-store failure configurable per tier |

---

## 2. Decisions (locked via Q&A)

| # | Decision |
|---|---|
| 1 | **Layered**: token bucket (burst) + sliding window counter (sustained). Request blocked if either trips. |
| 2 | **Session key**: configurable cookie name → fallback to existing `device_fp` (JA3/JA4) |
| 3 | **Sliding window**: counter (2 buckets + interpolation), not log-of-timestamps |
| 4 | **Cluster consistency**: best-effort. Redis authoritative; on Redis failure, fall back to local store + circuit breaker. Mirrors `device_fp/identity/redis.rs` pattern. |

---

## 3. Architecture

### 3.1 Trait + two backends (mirror existing `IdentityStore` pattern)

```
crates/waf-engine/src/checks/rate_limit/
├── mod.rs                # RateLimitCheck (impl Check)
├── store/
│   ├── mod.rs            # RateLimitStore trait
│   ├── memory.rs         # DashMap-backed (default, standalone)
│   └── redis.rs          # Redis-backed (feature = "redis-store", cluster)
├── algo/
│   ├── token_bucket.rs   # f64 tokens, last_refill: Instant
│   └── sliding_window.rs # 2-bucket counter w/ interpolation
└── key.rs                # KeyKind { Ip(IpAddr), Session(String) } + builder
```

**Reuse**: `IdentityStore` already proves the trait + `memory.rs` + `redis.rs` + circuit-breaker + Lua-script pattern works. Copy that shape exactly. Same `op_timeout`, `consecutive_fails: AtomicU32`, `breaker_threshold` config.

### 3.2 Trait

```rust
#[async_trait]
pub trait RateLimitStore: Send + Sync {
    /// Atomic: refill bucket + add 1 token consumption + window increment.
    /// Returns post-op state for decision.
    async fn check_and_consume(
        &self,
        key: &str,
        cfg: &LimitCfg,
        now_ms: i64,
    ) -> anyhow::Result<Decision>;
}

pub enum Decision { Allow, BurstExceeded, SustainedExceeded }

pub struct LimitCfg {
    pub burst_capacity: u32,    // token bucket size
    pub burst_refill_per_s: f64,
    pub window_secs: u32,       // sliding window length (e.g. 60)
    pub window_limit: u32,      // max requests per window
}
```

### 3.3 Key derivation (per request)

For each request, build **two** keys and check both:
- `ip:{host}:{client_ip}`
- `sess:{host}:{session_id}` where `session_id = cookie[cfg.session_cookie] OR device_fp_hex`

If either store call returns non-`Allow`, block (or challenge — handover to risk engine via FR-027 thresholds).

### 3.4 Sliding window counter algorithm

```
count_estimated = curr_bucket + prev_bucket * (1 - elapsed_in_curr / window_secs)
```

- 2 × u32 per key + 1 × i64 timestamp = ~16 bytes per key in memory
- Redis: `HMGET wafrl:sw:{key} c p t` → compute → `HSET` (or in Lua, atomic). ~2% accuracy error, well-known production pattern (Cloudflare engineering blog).

### 3.5 Token bucket

Existing `cc.rs` algorithm is correct — extract into `algo/token_bucket.rs`, make it backend-agnostic. State = `(tokens: f64, last_check_ms: i64)` = 16 bytes. Redis stores as HASH; refill computed in Lua.

### 3.6 One Lua script for atomic combined check (Redis backend)

Single round-trip: refill bucket → consume → update sliding window → return `(decision, tb_tokens, sw_count)`. Same approach as `OBSERVE_LUA` in `device_fp/identity/redis.rs:54`. Keeps Redis path within the 50ms `op_timeout` and contributes <1ms p99 typical.

### 3.7 Failure handling

- `op_timeout` exceeded OR Redis returns error → increment `consecutive_fails`
- `consecutive_fails >= breaker_threshold` → `breaker_open()` returns true
- `RateLimitCheck` consults breaker; if open, falls back to in-memory store
- Per FR-038: route-tier config decides whether to fail-close (CRITICAL) or fail-open (MEDIUM/CATCH-ALL) when **both** stores fail

---

## 4. Memory & Perf Budget

| Item | Per-key cost | At 100k unique keys |
|---|---|---|
| Token bucket (memory) | 16 B + DashMap overhead ≈ 80 B | ~8 MB |
| Sliding window (memory) | 16 B + overhead ≈ 80 B | ~8 MB |
| **Total in-memory** | ~160 B | **~16 MB** |
| Redis Lua RT (LAN) | — | <1 ms typical |
| Memory check | — | <10 µs typical |

Existing `cc.rs` already has TTL eviction (10 min) + max entries (100k) + auto-ban. Reuse that eviction logic for both algos.

---

## 5. Config (TOML)

```toml
[rate_limit]
enabled = true
session_cookie = "SESSIONID"  # fallback to device_fp if missing

[rate_limit.tiers.critical]
burst_capacity = 5
burst_refill_per_s = 2
window_secs = 60
window_limit = 30
fail_mode = "close"

[rate_limit.tiers.medium]
burst_capacity = 50
burst_refill_per_s = 20
window_secs = 60
window_limit = 600
fail_mode = "open"

[rate_limit.redis]   # optional; absence => standalone mode
url = "redis://..."
key_prefix = "wafrl:"
op_timeout_ms = 50
breaker_threshold = 5
```

Hot-reload (FR-021) by reusing the existing rule reload path.

---

## 6. Risks

| Risk | Mitigation |
|---|---|
| IP rotation attack inflates DashMap | Existing TTL+max-entries logic in `cc.rs:11-14` — reuse |
| Cookie spoofing to bypass session limit | Session limit is *additive* to IP limit, never replaces it — both must pass |
| Redis is the bottleneck under DDoS | Single-RT Lua + breaker fallback to memory; tested under load before submit |
| 2-bucket counter rejects legitimate edge bursts | Acceptable — token bucket is the burst layer; sliding window is sustained |
| Two stores doubling memory | Keep both algos in **one** key/value entry per scope — single DashMap, struct holds both states |

**Optimization:** combine token-bucket state + sliding-window state into one DashMap value per key. One lock, one allocation, ~32 bytes/key total instead of 160.

---

## 7. Migration Plan (high level — not the detailed plan)

1. Create `rate_limit/` module skeleton + `RateLimitStore` trait + memory impl
2. Extract token-bucket algo from `cc.rs` into `algo/`
3. Add sliding window counter algo
4. Wire `RateLimitCheck` into the engine `Check` chain; keep old `cc.rs` until parity tests pass
5. Add `RateLimitStore` conformance tests (mirror `device_fp/identity/conformance.rs`)
6. Add Redis backend behind `redis-store` feature
7. Per-tier config + fail-mode wiring
8. Delete old `cc.rs` once new check is at parity, update callsites
9. Load test: 5k req/s baseline, p99 ≤ 5ms, both standalone and Redis modes

---

## 8. Success Criteria

- ✅ Both algos pass acceptance: burst test (100 req/100ms) blocked; sustained test (>limit/min) blocked
- ✅ Per-IP and per-session tracked independently — confirmed by integration test
- ✅ p99 added latency < 1ms in standalone, < 3ms with Redis (LAN)
- ✅ Redis outage triggers breaker within 5 failures, traffic continues per tier fail-mode
- ✅ Memory stays bounded under IP-rotation attack (1M unique IPs over 10 min, RSS growth < 100 MB)
- ✅ Conformance suite passes for both `MemoryStore` and `RedisStore`
- ✅ Hot-reload changes limits without restart (FR-021)

---

## 9. Open Questions

1. **Does cluster mode imply standalone is impossible to use in cluster deployments?** Or can a node opt-in per-store (e.g. rate-limit on Redis but device_fp local)? Suggest: per-store opt-in, matches existing `device_fp` flexibility.
2. **Risk-score integration**: should rate-limit hits push +risk_score (FR-026) instead of hard-blocking, letting the risk engine decide Allow/Challenge/Block? Cleaner architecturally but slower to implement. Default: hard-block at rate-limit layer; emit event so risk engine can also react.
3. **Per-tier limits inheritance**: should per-route rules override per-tier defaults (FR-023, FR-024)? Need design call once rule engine spec is firm.
