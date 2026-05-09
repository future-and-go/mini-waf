# Phase 03 — waf-cluster (transport, sync, election) → 85%

## Context Links
- Baseline: `plans/260509-1039-coverage-90/plan.md`
- Crate: `crates/waf-cluster/`
- Existing tests: 4 files in `tests/` (cluster_integration, election_test, integration_test, peer_eviction_test) + 6 inline modules.
- Design ref: `docs/cluster-design.md`

## Overview
- **Priority:** P2
- **Status:** pending
- **Target:** 85% line (baseline 63.98%)
- File ownership glob: `crates/waf-cluster/**`

## Key Insights
- `node.rs` already 98.56% — leave alone.
- Biggest gaps: `transport/server.rs` (48%), `transport/client.rs` (47%), `election/mod.rs` (49%), `sync/events.rs` (0%), `cluster_forward.rs` (0%), `discovery.rs` (0%), `lib.rs` (0% public re-exports), `sync/config.rs` (0%), `crypto/store.rs` (66%).
- Hard ceiling on transport: full QUIC dial requires real cert chain + UDP socket. Existing `integration_test.rs::two_node_heartbeat_exchange` proves the harness works — extend it.
- `lib.rs` 0% is mostly `pub use` — drives 0 lines if reachable; tests just need to import once.

## Requirements
- Transport server/client error paths covered: bad cert, peer-cert mismatch, frame oversize, deserialization failure.
- Election state machine: term advancement, vote splits, leader-step-down on heartbeat-timeout.
- Sync events: batch encode/decode, lz4 compression roundtrip, oversized batch rejection.
- Discovery: static seed list parsing + dedup + invalid addr rejection.

## Architecture
```
waf-cluster/src/
├── transport/
│   ├── server.rs       ← 297 regions, 154 missed (48%)
│   ├── client.rs       ← 260 regions, 136 missed (47%)
│   └── frame.rs        ← 92% OK
├── election/mod.rs     ← 242 regions, 123 missed (49%)
├── sync/
│   ├── rules.rs        ← 87% OK
│   ├── events.rs       ← 0%
│   └── config.rs       ← 0%
├── crypto/
│   ├── ca.rs           ← 93% OK
│   ├── node_cert.rs    ← 95% OK
│   ├── token.rs        ← 95% OK
│   └── store.rs        ← 66% (LRU, AES-GCM key store)
├── health/             ← 98% OK (skip)
├── node.rs             ← 98% OK (skip)
├── cluster_forward.rs  ← 0% (worker → main forwarding)
├── discovery.rs        ← 0%
└── lib.rs              ← 0% (re-exports)
```

## Related Code Files
**Modify (inline tests):**
- `crates/waf-cluster/src/discovery.rs`
- `crates/waf-cluster/src/sync/config.rs`
- `crates/waf-cluster/src/sync/events.rs`
- `crates/waf-cluster/src/cluster_forward.rs`
- `crates/waf-cluster/src/election/mod.rs` (extend existing)
- `crates/waf-cluster/src/transport/{server,client}.rs` (error paths)
- `crates/waf-cluster/src/crypto/store.rs` (LRU eviction, persist + reload)

**Create:**
- `crates/waf-cluster/tests/transport_error_paths.rs` — bad cert, frame oversize, peer disconnect mid-frame
- `crates/waf-cluster/tests/election_state_machine.rs` — term advance, split-vote, step-down
- `crates/waf-cluster/tests/sync_events_batching.rs` — batch encode/decode, lz4 roundtrip, oversized rejection
- `crates/waf-cluster/tests/cluster_forward_routing.rs` — worker forwards write op to main, main rejects when no leader
- `crates/waf-cluster/tests/discovery_static.rs`

## Implementation Steps
1. Read `transport/server.rs` lines 1–150; map missed branches by `cargo llvm-cov -p waf-cluster --html` (gitignored), identify error-handler arms.
2. Add `tests/transport_error_paths.rs`: extend the cert helpers from `integration_test.rs` to issue **invalid** cert (wrong CA), assert connect → `mTLS handshake error` log + connection refused.
3. Frame oversize: build a `Vec<u8>` larger than max-frame; assert client decode returns `FrameError::TooLarge`.
4. `tests/election_state_machine.rs`: drive `ElectionManager` directly (not via QUIC). Cover: vote_request newer term, vote_request stale term, leader step-down on heartbeat-timeout, candidate-with-no-majority retries.
5. `tests/sync_events_batching.rs`: build N events, batch, lz4-compress, decompress, decode → assert equal. Reject batch > MAX_BATCH_BYTES.
6. `tests/cluster_forward_routing.rs`: instantiate two `ClusterNode` with mock `Database` trait? — NO, requires real DB. Use Phase 02 `start_postgres()` fixture (re-export). Create rule on worker → assert main DB has it. **Defer this single test until Phase 02 lands** (mark `#[ignore = "requires Phase 02"]` if started in parallel).
7. `tests/discovery_static.rs`: parse seed list (good, malformed, dup, IPv6, IPv4) → expected sets.
8. `crypto/store.rs` inline: LRU evict, persist to tempdir + reload, decryption-failure path.

## Todo List
- [ ] `transport_error_paths.rs` — bad-cert + frame-oversize (≤200 LOC)
- [ ] `election_state_machine.rs` — 6 scenarios (≤200 LOC)
- [ ] `sync_events_batching.rs` — batch + lz4 + oversize (≤150 LOC)
- [ ] `discovery_static.rs` — 5 parse cases (≤80 LOC)
- [ ] `cluster_forward_routing.rs` — gated on Phase 02 (≤200 LOC)
- [ ] Inline tests in `crypto/store.rs`, `sync/events.rs`, `sync/config.rs`, `cluster_forward.rs`
- [ ] Inline `lib.rs` smoke import to register re-exports (1 test)
- [ ] `cargo llvm-cov -p waf-cluster --summary-only` ≥ 85%
- [ ] `cargo check --tests -p waf-cluster` clean

## Success Criteria
- ≥ 85% line. Per-file: `transport/*` ≥ 75%, `election/mod.rs` ≥ 80%, `sync/events.rs` ≥ 85%.
- All cluster tests deterministic — no `tokio::time::sleep > 100ms` for state assertions; use `tokio::time::pause()` where possible.

## Risk Assessment
- **Medium**: QUIC tests can be flaky on CI (UDP port reuse). Use `0` port + `local_addr()` to discover.
- **Medium**: rcgen cert generation slow in debug — use `OnceCell<TestCa>` per file.
- **Low**: lz4 / serde_json roundtrip is straightforward.

## Security Considerations
- Bad-cert tests must verify rejection — never accept a cert with wrong CA, even with a "skip-verify" flag.
- AES-GCM key store tests must use ephemeral keys (no real cluster CA in tests).

## Next Steps
- Coordinate with Phase 02 owner on `start_postgres()` re-use for `cluster_forward_routing.rs`.
