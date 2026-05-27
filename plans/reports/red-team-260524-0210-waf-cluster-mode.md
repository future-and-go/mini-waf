# Red-Team Review: WAF Cluster Mode E2E Integration Plan

**Date:** 2026-05-24  
**Reviewer:** code-reviewer (hostile red-team mode)  
**Plan:** `plans/260524-0210-waf-cluster-mode-e2e/`  
**Verdict:** PASS_WITH_CONCERNS

---

## Phase 1: Transport Dispatch Completion

1. **Incorrect message count.** Plan claims "6 of 13 handled." Actual: server dispatches 4 explicitly (Heartbeat, JoinRequest, ElectionVote, ElectionResult); client dispatches 4 (Heartbeat, JoinResponse, ElectionVote, ElectionResult). The gap is 9 per side, not 7. Undercounting the gap means underestimating effort.

2. **Single-stream architecture blocks Phase 6.** Client opens one `open_bi()` (client.rs:120) and uses `tokio::select!` between send/recv loops. `dispatch_incoming` has no access to `PendingForwards` -- responses to `ApiForward` cannot be routed back to `forward_write()` callers. This requires a structural refactor the plan does not acknowledge.

3. **No malformed-frame / mid-stream disconnect test.** Plan tests round-trip serialization but not graceful degradation when `read_frame` fails mid-parse.

## Phase 2: NodeState-Engine Bridge

1. **`on_rules_updated` reentrancy risk.** Clone-then-await pattern is correct, but plan should document that `on_rules_updated` must never re-acquire NodeState locks. No such constraint is stated.

2. **Missing `RuleRegistry` on worker.** Plan adds `rule_reloader` but Phase 3 needs a mutable `RuleRegistry` on workers. NodeState has no such field. This is a hidden dependency gap -- Phase 3 cannot compile without it.

3. **BLOCKING: `WafEngine::reload_rules()` reads from DB.** Worker nodes use `ForwardOnly` storage (no PostgreSQL). `WafEngine::on_rules_updated()` delegates to `reload_rules()` which reads from the database. On workers, this will fail. Worker engine needs a different reload path (from in-memory RuleRegistry, not DB).

## Phase 3: Rule Sync End-to-End

1. **TOCTOU between DB write and changelog record.** API handler calls `waf_storage::create_rule()` then `RuleChangelog::record_change()`. If a sync request arrives between these two calls, the incremental response misses the rule. RwLock on changelog alone does not prevent this.

2. **BLOCKING: No `RuleRegistry` field on `NodeState`.** `apply_sync_response()` (sync/rules.rs:178) takes `&mut RuleRegistry`. NodeState has no RuleRegistry. Plan adds RuleChangelog but not RuleRegistry. This is a compilation blocker.

3. **Response routing gap.** `run_rule_sync_loop` sends RuleSyncRequest via mpsc, but the response arrives in `dispatch_incoming` which has no access to the worker's RuleRegistry or RuleReloader. Threading these through requires refactoring the client recv path.

## Phase 4: Event Log Aggregation

1. **N+1 DB inserts.** `handle_event_batch` inserts events in a loop: 100 events = 100 DB round-trips. No batch insert proposed. Under sustained attack this becomes the bottleneck.

2. **Silent event loss window.** QUIC disconnect loses all buffered events (VecDeque + mpsc channel). With batch_size=100 and flush_interval=5s, thousands of security events can be silently dropped. No WAL or retry queue even for v1.

3. **Double-counting not fully addressed.** SecurityEvent already has `node_id`, but the plan doesn't specify how the storage/query layer distinguishes local vs. forwarded events. Main's own WAF events + forwarded events will appear identical in queries without an explicit `source` field.

## Phase 5: Config Sync

1. **No config validation on worker.** Deserialized TOML is merged directly into live config with no schema validation or rollback. Malformed config from main crashes all workers simultaneously.

2. **"Trigger subsystem reloads" is undefined.** Plan says workers should reload affected subsystems but does not specify which ones or how. Proxy, cache, rate limits each have different reload mechanisms. This is hidden scope creep.

3. **No fencing on ConfigSync sender.** ConfigSync has no `term` field. A stale-term main can push config after being deposed. Workers have no way to reject it.

## Phase 6: Write Forwarding Integration

1. **BLOCKING: JWT secret not synchronized.** `ApiForward` replays the original Authorization header on the main's API. If worker and main have different JWT signing secrets (highly likely without explicit sync), every forwarded request fails auth. Plan never addresses JWT/session secret distribution.

2. **Auth bypass via localhost replay.** `replay_request()` sends to `127.0.0.1:API_PORT`. Main sees the connection from loopback, bypassing IP-based access controls and rate limits. Original client IP in headers is not authoritative for the TCP connection.

3. **No frame size limit.** `frame::read_frame` has no visible max-size guard. A malicious worker can send a multi-GB ApiForward body, exhausting main's memory. The plan mentions "1MB max" as a pitfall but proposes no enforcement.

## Phase 7: Integration and E2E Tests

1. **E2E test endpoints don't exist.** `e2e-cluster.sh` calls `/api/v1/rules` (line 157, 173) -- no such endpoint exists. `rules_api.rs` exposes `get_rule_registry`, `toggle_rule`, `reload_rule_registry`, `import_rules`. The JSON shape assumed in the test (`{"id":"...","pattern":"..."}`) likely does not match the actual API.

2. **QUIC in CI.** In-process tests require UDP sockets. CI environments (GitHub Actions containers) may restrict raw UDP. Plan mentions port 0 but not CI sandbox constraints.

3. **No split-brain test.** Tests cover failover but never simulate network partition where two nodes both believe they are main. `fencing_check()` exists but has zero test coverage for the dual-main scenario. This is the highest-risk failure mode in any cluster.

## Cross-Phase Issues

| Issue | Severity | Phases Affected |
|-------|----------|-----------------|
| JoinRequest `token` never validated (server.rs:202 ignores it, lib.rs:148 sends empty) | Medium | All |
| No `term` field on RuleSyncReq/Resp, ConfigSync, EventBatch, ApiForward -- stale main can serve responses after election | High | 3, 4, 5, 6 |
| `broadcast()` silently drops on backpressure (`try_send` ignores `Full`) -- workers miss critical messages | Medium | 5, election |
| `RuleRegistry` not on NodeState -- compilation blocker for Phase 3 | Critical | 2, 3 |
| Worker `reload_rules()` hits non-existent DB -- runtime crash | Critical | 2, 3 |

---

## VERDICT: PASS_WITH_CONCERNS

Plan correctly identifies real gaps and phase ordering is sound, but has three blocking issues that must be resolved before implementation begins: (1) workers' `WafEngine::reload_rules()` attempts DB reads that will fail on ForwardOnly nodes, (2) write forwarding has no JWT secret synchronization so all forwarded auth will fail, and (3) `RuleRegistry` is absent from `NodeState`, making Phase 3 uncompilable as designed.
