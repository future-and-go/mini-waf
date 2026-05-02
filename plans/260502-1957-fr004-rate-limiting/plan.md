---
name: FR-004 Rate Limiting
slug: fr004-rate-limiting
status: in_progress
created: 2026-05-02
priority: P0
blockedBy: []
blocks: []
relatedReports:
  - plans/reports/brainstorm-260502-1957-rate-limiting-fr004.md
---

# FR-004 Rate Limiting — Implementation Plan

**Spec:** `analysis/requirements.md` line 44 (FR-004, P0 mandatory)
**Brainstorm:** `plans/reports/brainstorm-260502-1957-rate-limiting-fr004.md`
**Pattern reference:** `crates/waf-engine/src/device_fp/identity/` (trait + memory + redis + conformance)

## Goal

Layered rate limiting: token bucket (burst) + sliding-window counter (sustained). Per-IP and per-session keys. Trait-based store with `MemoryStore` (standalone) and `RedisStore` (cluster, behind `redis-store` feature). Best-effort Redis with circuit-breaker fallback to memory. Per-tier config with FR-038 fail-mode. Replaces existing `cc.rs`.

## Acceptance Criteria

- Sliding window per IP **and** per user-session
- Token bucket for burst
- Standalone mode → in-memory; cluster mode → Redis
- p99 added latency: <1ms standalone, <3ms Redis (LAN)
- Memory bounded under IP-rotation attack (TTL + max-entries reuse from `cc.rs`)
- Hot-reload limits without restart (FR-021)
- Conformance suite passes for both store backends

## Architecture (Summary)

```
RateLimitCheck (impl Check)
    │
    ├── KeyBuilder ──► [ip:host:client_ip, sess:host:session_id]
    │                  session_id = cookie[cfg.cookie] || device_fp_hex
    │
    ▼
RateLimitStore (trait, async)
    ├── MemoryStore (DashMap, default)  ◄── standalone
    └── RedisStore  (Lua, ConnectionManager, breaker) ◄── cluster
                       │
                       └── on breaker_open() → degrade to MemoryStore

Per key value: { token_bucket_state, sliding_window_state }   // packed, ~32B
Per Lua call: refill TB → consume → update SW → return Decision
```

## Phases

| # | File | Status | Depends |
|---|------|--------|---------|
| 1 | `phase-01-module-skeleton-and-trait.md` | done | — |
| 2 | `phase-02-algos-token-bucket-sliding-window.md` | done | 1 |
| 3 | `phase-03-memory-store.md` | done | 2 |
| 4 | `phase-04-key-builder-and-check-integration.md` | pending | 3 |
| 5 | `phase-05-conformance-suite.md` | pending | 3 |
| 6 | `phase-06-redis-store.md` | pending | 5 |
| 7 | `phase-07-config-fail-mode-hot-reload.md` | pending | 4 |
| 8 | `phase-08-replace-old-cc-and-load-test.md` | pending | 6, 7 |

## Key Files

**Create:**
- `crates/waf-engine/src/checks/rate_limit/mod.rs`
- `crates/waf-engine/src/checks/rate_limit/store/{mod,memory,redis}.rs`
- `crates/waf-engine/src/checks/rate_limit/algo/{token_bucket,sliding_window}.rs`
- `crates/waf-engine/src/checks/rate_limit/key.rs`
- `crates/waf-engine/src/checks/rate_limit/conformance.rs`

**Modify:**
- `crates/waf-engine/src/checks/mod.rs` (register new check)
- `crates/waf-engine/Cargo.toml` (add `redis-store` feature; redis already used by device_fp)
- `crates/waf-common/src/config.rs` (add `RateLimitConfig`)
- `configs/*.toml` (per-tier rate-limit blocks)

**Delete (after parity, phase 8):**
- `crates/waf-engine/src/checks/cc.rs`

## Risks

- **IP rotation DoS** → reuse `cc.rs:11-14` TTL + max-entries eviction
- **Redis adds latency** → single Lua RT, op_timeout 50ms, breaker fallback
- **Per-key state doubles** → pack TB + SW into one DashMap value entry
- **Cookie spoofing bypasses session limit** → IP limit always also applied (additive)

## Success Criteria

- ✅ All `RateLimitStore` conformance tests pass for memory + redis
- ✅ Burst test (100 req in 100ms) blocked by TB
- ✅ Sustained test (>limit/min) blocked by SW
- ✅ Per-IP and per-session counters independent (integration test)
- ✅ Redis outage → breaker opens within 5 fails → traffic continues per tier fail-mode
- ✅ 1M unique IPs over 10 min → RSS growth <100MB
- ✅ Load test: 5k req/s with p99 added latency <5ms (NFR)
- ✅ `cargo fmt --all -- --check && cargo clippy --workspace --all-targets --all-features -- -D warnings && cargo test` all green
- ✅ Old `cc.rs` deleted, no callsite regressions

## Open Questions

1. Per-store cluster opt-in (rate-limit on Redis but device_fp local)? Default: yes, per-store config independence.
2. Rate-limit hits → hard-block vs +risk_score (FR-026)? Default: hard-block at this layer; emit event for risk engine.
3. Per-route rule overrides per-tier defaults (FR-023/024)? Defer until rule engine FR-003 design firms up.
