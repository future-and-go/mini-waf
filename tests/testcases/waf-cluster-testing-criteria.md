# WAF-Cluster Testing Criteria — Master-Worker Mode

> Derived from codebase: `crates/waf-cluster/tests/` · Target: `cargo test -p waf-cluster`  
> All criteria are verifiable with existing test infrastructure. PASS = all assertions hold, zero panics, no timeout.

---

## TC-01 · Election — Vote Counting & Majority

**File:** `election_test.rs` — `candidate_with_majority_wins_election`

| # | Assertion | Expected |
|---|-----------|----------|
| 1.1 | `increment_term_and_vote_for_self()` returns term = 1 | `term == 1` |
| 1.2 | Self-vote recorded immediately | `vote_count_for_term(1) == 1` |
| 1.3 | After one peer grants vote: vote count = 2 | `vote_count_for_term(1) == 2` |
| 1.4 | `is_majority(2, 2)` = true (2-node cluster) | `true` |
| 1.5 | `voter_ids_for_term(1)` contains both node IDs | set = {"candidate-1", "voter-1"} |
| 1.6 | After `promote_to_main()`, role = Main | `current_role() == NodeRole::Main` |

**PASS condition:** All 6 assertions pass, no panics.

---

## TC-02 · Election — Stale-Term Fencing (Split-Brain Prevention)

**File:** `election_test.rs` — `stale_election_result_rejected`

| # | Assertion | Expected |
|---|-----------|----------|
| 2.1 | After 5 increments, `current_term_sync() == 5` | `5` |
| 2.2 | ElectionResult with term=3 < current_term=5 → role stays Worker | `NodeRole::Worker` |
| 2.3 | Term NOT rolled back by stale result | `current_term_sync() == 5` |
| 2.4 | Valid result term=5 electing other node → step down | `NodeRole::Worker` |
| 2.5 | Valid result term=6 electing self → become Main | `NodeRole::Main` |
| 2.6 | Term advances to 6 | `current_term_sync() == 6` |

**PASS condition:** All 6 assertions pass.

---

## TC-03 · Election — Concurrent Election / Split Vote

**File:** `election_test.rs` — `concurrent_election_only_majority_wins`

| # | Assertion | Expected |
|---|-----------|----------|
| 3.1 | Both candidates start at term=1 | `term_a == term_b == 1` |
| 3.2 | A: 2 votes (self + node-3) | `vote_count_for_term(1) == 2` |
| 3.3 | B: 3 votes (self + node-4 + node-5) | `vote_count_for_term(1) == 3` |
| 3.4 | Duplicate vote from node-3 returns `false` (idempotent) | `record_vote_for_me(1, "node-3") == false` |
| 3.5 | `is_majority(2, 5)` = false — A does NOT win | `false` |
| 3.6 | `is_majority(3, 5)` = true — B wins | `true` |
| 3.7 | A receives B's ElectionResult → steps down | `NodeRole::Worker` |
| 3.8 | B processes own ElectionResult → becomes Main | `NodeRole::Main` |
| 3.9 | Both nodes converge on same term | `em_a.current_term() == em_b.current_term()` |

**PASS condition:** All 9 assertions pass. No split-brain (two mains).

---

## TC-04 · Peer Eviction — Dead Peer Removed

**File:** `peer_eviction_test.rs` — `eviction_removes_dead_peers`  
**Requires:** `#[tokio::test(start_paused = true)]`

| # | Assertion | Expected |
|---|-----------|----------|
| 4.1 | Peer added to peer list | peer list contains "dead-peer" |
| 4.2 | Heartbeats seeded at t=0, t=100ms (very old vs wall-clock) | phi accrual >> phi_dead threshold |
| 4.3 | After `advance(2s)` + `yield_now()`, peer evicted | peer list does NOT contain "dead-peer" |

**PASS condition:** Peer removed. No false eviction of healthy peers.

---

## TC-05 · Peer Eviction — Healthy Peer Retained

**File:** `peer_eviction_test.rs` — `eviction_keeps_healthy_peers`  
**Requires:** `#[tokio::test(start_paused = true)]`

| # | Assertion | Expected |
|---|-----------|----------|
| 5.1 | Fresh heartbeats: `now - 100ms`, `now` | phi << phi_dead |
| 5.2 | After `advance(2s)` + `yield_now()`, peer still in list | peer list contains "healthy-peer" |

**PASS condition:** Healthy peer not evicted.

---

## TC-06 · Peer Eviction — Tracker State Cleanup

**File:** `peer_eviction_test.rs` — `eviction_cleans_tracker_state`  
**Requires:** `#[tokio::test(start_paused = true)]`

| # | Assertion | Expected |
|---|-----------|----------|
| 6.1 | After eviction, peer removed from list | `!peer_ids.contains("stale-peer")` |
| 6.2 | `phi_for("stale-peer", now)` returns ~0.0 after eviction | `phi < f64::EPSILON` |

**PASS condition:** Tracker cleaned. Rejoining peer gets fresh state.

---

## TC-07 · Rule Sync — Full Snapshot (Brand-New Worker)

**File:** `rule_sync_e2e.rs` / `cluster_integration.rs` — `full_snapshot_sync_from_version_zero`

| # | Assertion | Expected |
|---|-----------|----------|
| 7.1 | Worker at version=0 triggers Full snapshot | `resp.sync_type == SyncType::Full` |
| 7.2 | `snapshot_lz4` payload is non-empty | `!resp.snapshot_lz4.is_empty()` |
| 7.3 | After `apply_sync_response`, worker registry contains all rules | count matches main's rule count |
| 7.4 | Worker version equals main's authoritative version | `worker_registry.version == changelog.current_version()` |

**PASS condition:** All rules present, version synchronized.

---

## TC-08 · Rule Sync — Incremental Delta

**File:** `rule_sync_e2e.rs` — `incremental_sync_returns_only_new_changes`

| # | Assertion | Expected |
|---|-----------|----------|
| 8.1 | 5 rules recorded; worker at version=2 requests sync | response type = Incremental |
| 8.2 | Delta contains exactly 3 changes (r3, r4, r5) | `resp.changes.len() == 3` |
| 8.3 | Response version = 5 | `resp.version == 5` |

**PASS condition:** No over-delivery of already-known changes.

---

## TC-09 · Rule Sync — No-Op (Worker Already Current)

**File:** `rule_sync_e2e.rs` — `noop_sync_when_worker_is_current`

| # | Assertion | Expected |
|---|-----------|----------|
| 9.1 | Worker at version=N requests sync when main at version=N | `resp.sync_type == Incremental` |
| 9.2 | No changes delivered | `resp.changes.is_empty()` |
| 9.3 | Version unchanged | `resp.version == N` |

**PASS condition:** Zero-bandwidth no-op sync path works.

---

## TC-10 · Rule Sync — Full Snapshot Fallback (Worker Too Far Behind)

**File:** `rule_sync_e2e.rs` — `full_snapshot_fallback_when_worker_too_far_behind`

| # | Assertion | Expected |
|---|-----------|----------|
| 10.1 | 15 changes into buffer of size 10 → oldest buffered = version 6 | ring buffer evicts versions 1-5 |
| 10.2 | Worker at version=1 < oldest buffered → Full snapshot | `resp.sync_type == SyncType::Full` |
| 10.3 | After apply, registry contains all 15 rules | `registry.rules.len() == 15` |
| 10.4 | Worker version = 15 | `registry.version == 15` |

**PASS condition:** Worker recovers completely via full snapshot.

---

## TC-11 · Rule Sync — Delete Propagation

**File:** `cluster_integration.rs` — `rule_created_on_main_synced_to_worker` (delete phase)

| # | Assertion | Expected |
|---|-----------|----------|
| 11.1 | `ChangeOp::Delete` delivered as incremental | `resp.sync_type == Incremental` |
| 11.2 | Exactly one change in delta | `resp.changes.len() == 1` |
| 11.3 | After apply, deleted rule absent from worker registry | `!registry.rules.contains_key("sqli-001")` |
| 11.4 | Non-deleted rules still present | `registry.rules.contains_key("xss-001")` |

**PASS condition:** Deletes propagate; other rules unaffected.

---

## TC-12 · Transport — Frame Codec Roundtrip

**File:** `transport_error_paths.rs`

| # | Assertion | Expected |
|---|-----------|----------|
| 12.1 | `Heartbeat` frame: write → read → decode yields same `sequence` | `h.sequence == 7` |
| 12.2 | Large payload (4096 bytes) roundtrip | decoded length = 4096 |
| 12.3 | Truncated length prefix (2 bytes) → error containing "frame length" | `Err` with matching message |
| 12.4 | Truncated body (declared 32, actual 5) → error | `Err` on read |
| 12.5 | Writer closed mid-write → error propagated | `res.is_err()` |

**PASS condition:** All codec paths produce correct errors or correct values.

---

## TC-13 · Transport — mTLS Security

**File:** `integration_test.rs` — `mtls_rejects_unknown_cert`  
**File:** `transport_error_paths.rs` — `client_rejects_bad_node_cert_pem`, `server_serve_rejects_bad_cert_pem`

| # | Assertion | Expected |
|---|-----------|----------|
| 13.1 | Client with cert from rogue CA cannot connect to cluster server | `Ok(Err(_))` or `Err(_)` (timeout/error) — NOT `Ok(Ok(()))` |
| 13.2 | Client with malformed PEM cert does not connect cleanly | same — must NOT return `Ok(Ok(()))` |
| 13.3 | Server with malformed PEM cert rejects `serve()` call | `res.is_err()` |
| 13.4 | `server.listen_addr()` returns configured address | addr == configured |

**PASS condition:** No unauthorized node can join the cluster.

---

## TC-14 · Transport — Heartbeat Delivery

**File:** `integration_test.rs` — `heartbeat_delivered_from_client_to_server`

| # | Assertion | Expected |
|---|-----------|----------|
| 14.1 | QUIC server starts and accepts connections | server bound, no error |
| 14.2 | Client sends `Heartbeat` message | `tx.send()` succeeds |
| 14.3 | Within 500ms, server records `last_seen_ms > 0` for client peer | `last_seen_ms > 0` |

**PASS condition:** Heartbeat travels client → server and updates peer state.

---

## TC-15 · Discovery — Static Seeds Parsing

**File:** `discovery_static.rs`

| # | Assertion | Expected |
|---|-----------|----------|
| 15.1 | Empty seed list → zero peers | `peers().is_empty()` |
| 15.2 | IPv4 + IPv6 parsed correctly | `peers().len() == 2`, one v4 + one v6 |
| 15.3 | Malformed address (no port, invalid format) → `Err` with "invalid seed address" | `res.is_err()`, message matches |
| 15.4 | Address without port → `Err` | `res.is_err()` |
| 15.5 | Duplicate seeds preserved (de-dup is caller's responsibility) | `peers().len() == 2` for two identical seeds |

**PASS condition:** All parsing edge cases handled deterministically.

---

## TC-16 · Event Aggregation — Batch Flush

**File:** `cluster_full_lifecycle.rs` — `event_aggregation_worker_to_main`

| # | Assertion | Expected |
|---|-----------|----------|
| 16.1 | 5 events sent; batch_size=5 → immediate flush | `batch.events.len() == 5` |
| 16.2 | Batch carries correct `node_id` | `batch.node_id == "worker-1"` |
| 16.3 | Each event has correct `client_ip` and `action` | per-event field check |
| 16.4 | 3 more events + channel close → partial batch flushed | `partial.events.len() == 3` |
| 16.5 | Batch arrives within 5s timeout | no timeout |

**PASS condition:** All events delivered; partial flush on close works.

---

## TC-17 · Config Sync — Version Gating

**File:** `cluster_full_lifecycle.rs` — `config_sync_version_gating`

| # | Assertion | Expected |
|---|-----------|----------|
| 17.1 | First sync: version > 0 (monotonic timestamp) | `msg_v1.version > 0` |
| 17.2 | Worker applies sync → version matches main | `worker_syncer.current_version() == msg_v1.version` |
| 17.3 | Same message applied twice → second application returns `None` (idempotent) | second `apply_sync()` returns `None` |
| 17.4 | Second sync with higher version applied → version advances | `worker_syncer.current_version() == msg_v2.version` |
| 17.5 | Stale (lower version) sync rejected | `apply_sync(stale) == None` |

**PASS condition:** No config regression; stale syncs silently dropped.

---

## TC-18 · ForwardOnly Mode — API Write Forwarding

**File:** `cluster_full_lifecycle.rs` — `forward_only_worker_forwards_write_to_main`

| # | Assertion | Expected |
|---|-----------|----------|
| 18.1 | Worker in `StorageMode::ForwardOnly` calls `forward_write()` | future resolves |
| 18.2 | Main receives `ApiForward` message with correct `method`, `path`, `request_id` | field check |
| 18.3 | Main resolves forward with status=201, body `{"id":"new-rule"}` | resolution succeeds |
| 18.4 | `forward_write()` returns `Ok(ApiForwardResponse { status: 201 })` | `resp.status == 201` |

**PASS condition:** Workers with no DB can proxy writes through main.

---

## TC-19 · Full Lifecycle Sequence

**File:** `cluster_full_lifecycle.rs` — `full_lifecycle_join_sync_events_config_election`

| Phase | Assertion | Expected |
|-------|-----------|----------|
| Join | Main + Worker added as peers | `total_nodes() == 2` for both |
| Rule sync | 3 rules synced full snapshot | `worker_registry.rules.len() == 3`, version = 3 |
| Events | 3 events batch flushed | `batch.events.len() == 3` |
| Config sync | Config applied to worker | `worker_syncer.current_version() == cfg_msg.version` |
| Election | Main removed; worker self-elects as sole node | `worker.current_role() == NodeRole::Main` |
| Term | Final term ≥ 1 | `election.current_term_sync() >= 1` |

**PASS condition:** Full 5-phase lifecycle completes without error.

---

## TC-20 · Certificate Infrastructure

**File:** `cluster_integration.rs` — `cert_generation_and_roundtrip`

| # | Assertion | Expected |
|---|-----------|----------|
| 20.1 | CA generated: cert PEM non-empty, starts with `-----BEGIN CERTIFICATE-----` | format correct |
| 20.2 | CA DER export succeeds | `cert_der().is_ok()` |
| 20.3 | Node cert signed by CA: cert PEM + key PEM non-empty | both non-empty |
| 20.4 | `cert_chain_der()` non-empty | `chain.len() > 0` |
| 20.5 | `private_key_der()` succeeds | `Ok(_)` |

**PASS condition:** PKI bootstrap works end-to-end.

---

## TC-21 · NodeState — RuleChangelog Integration

**File:** `rule_sync_e2e.rs` — `node_state_rule_changelog_integration`

| # | Assertion | Expected |
|---|-----------|----------|
| 21.1 | 2 changes recorded → `current_version() == 2` | `2` |
| 21.2 | `delta_since(1)` → Some with 1 change (r2 only) | `delta.unwrap().len() == 1` |
| 21.3 | `delta_since(0)` → None (needs full snapshot since first buffered = v1) | `None` |

**PASS condition:** Changelog version tracking is monotonic and correct.

---

## Summary: Pass Gate

```
cargo test -p waf-cluster 2>&1 | tail -5
```

**Overall PASS requires:**

- `test result: ok. N passed; 0 failed; 0 ignored`
- All 21 test cases above individually green
- No `FAILED` lines in output
- No test exceeds 5s (integration tests use explicit `tokio::time::timeout`)
- `cargo clippy -p waf-cluster -- -D warnings` → zero warnings

**Minimum test count (current codebase):** 20+ tests across 7 test files.  
**Target coverage:** ≥ 90% line coverage on `src/election/`, `src/sync/`, `src/health/`.

---

## Quick Run Commands

```bash
# Run all cluster tests
cargo test -p waf-cluster

# Run specific test suite
cargo test -p waf-cluster --test election_test
cargo test -p waf-cluster --test peer_eviction_test
cargo test -p waf-cluster --test rule_sync_e2e
cargo test -p waf-cluster --test cluster_full_lifecycle
cargo test -p waf-cluster --test transport_error_paths
cargo test -p waf-cluster --test integration_test
cargo test -p waf-cluster --test discovery_static

# Run with output (see assertion messages on failure)
cargo test -p waf-cluster -- --nocapture

# E2E Docker test (requires Docker)
./tests/e2e-cluster.sh
```
