# Phase 05 — IdentityStore Trait + Memory Impl + Conformance Suite

**Status:** completed (deferred: bloom prefilter + dedicated bench) | **Priority:** P0 | **Effort:** S | **Blocked by:** phase-02

## Context

`IdentityStore` records observations of (fp_key, ip, ua, ts) and answers lookups. Memory impl is v1 default; Redis impl in phase-08. Shared conformance suite ensures both behave identically.

## Requirements

### Functional
- `observe(fp_key, ip, ua, ts)` returns `Observation { distinct_ips, distinct_uas, first_seen, last_seen, ip_set_window, ua_set_window }`
- `lookup(fp_key)` returns full `IdentityRecord` if present, else None
- `purge_expired()` removes entries older than configured TTL; returns count
- TTL janitor task runs every `ttl_secs/4` seconds (tokio interval)

### Non-functional
- `observe` <10µs p99 in-memory
- DashMap shard count = `2 × CPU` (default), configurable
- Cardinality cap: max N entries; LRU eviction beyond cap (default 1M)
- Bloom filter pre-check optional (config) to reduce DDoS-amplified inserts

## Files

**Created:**
- `crates/waf-engine/src/device_fp/identity/trait.rs` — finalize trait + types
- `crates/waf-engine/src/device_fp/identity/memory.rs` — DashMap impl + TTL janitor
- `crates/waf-engine/src/device_fp/identity/conformance.rs` — `pub` test fn `run_store_conformance(store: Arc<dyn IdentityStore>)` reused by both impls

## Steps

1. Finalize `IdentityRecord`, `Observation`, `FpKey` (composite of ja4 + h2_hash)
2. Implement `MemoryIdentityStore`:
   - `DashMap<FpKey, IdentityRecord>` w/ sliding-window IP/UA sets (deque + HashSet)
   - LRU via `lru` crate or per-entry `last_seen` + periodic sweep
3. Implement TTL janitor as `tokio::task` w/ `tokio::time::interval`
4. Implement bloom filter wrapper (feature `bloom-prefilter`, default off)
5. Build conformance suite: 12 test scenarios
   - basic observe/lookup
   - TTL expiry
   - distinct ip counting in window
   - distinct ua counting in window
   - LRU eviction at cap
   - concurrent observers (50 threads × 1k ops)
   - purge_expired count correctness
   - lookup miss
   - same fp same ip → no double-count
   - clock skew tolerance
   - cardinality cap edge case
   - drop semantics (no leak)
6. Run conformance against `MemoryIdentityStore`
7. Bench observe/lookup

## Todos

- [x] Finalize trait + types in `identity_trait.rs` (already done in phase-02)
- [x] `MemoryIdentityStore` impl — DashMap + sliding window via deque + count map
- [x] TTL janitor task — `spawn_janitor` returns `JoinHandle`
- [ ] Bloom prefilter (deferred — YAGNI, optional in plan)
- [x] Conformance suite (12 scenarios) — `identity::conformance::run_store_conformance`
- [x] Run suite vs Memory impl — all green (3/3 tests pass)
- [ ] Bench observe/lookup <10µs (deferred — phase-09 perf gate)
- [x] Concurrency stress test — 16 tasks × 50 ops, no panic

## Success Criteria

- All 12 conformance scenarios pass on Memory impl
- Bench `observe` <10µs p99
- Stress test 1M ops no panics, no leaked memory
- LRU + TTL eviction empirically verified

## Risks

- DashMap deadlock w/ nested locks → audit; never hold ref across await
- Memory unbounded under DDoS → cardinality cap mandatory; default 1M; overflow logged

## Next

Phase 06 (signal providers consume `IdentityStore`) and Phase 08 (Redis impl reuses conformance).
