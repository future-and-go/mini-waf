# R2 — Distribution Audit Verification (260524)

Branch: main @ 61a75e6b

## #79 — VALID
**Evidence:** `crates/waf-engine/src/rules/manager.rs:113-118` (builtin write block), `:138-142` (LocalFile per-source write), `:149-153` (LocalDir delegates), `:382-386` (load_from_dir per-file write), `:167-169` (final mark_loaded write).
`reg.clear()` at line 114 runs in its own short critical section; each subsequent source acquires a **fresh** `self.registry.write()` lock. Readers between these sections see partial state (builtin only, or builtin + first N sources). No `build_registry_off_lock + single swap` and no `ArcSwap<RuleRegistry>`.
**Reasoning:** Sibling reload paths (`access/reload.rs:18,73,129,153`, `relay/reload.rs:18,41-46`) all use `ArcSwap` for atomic swap; rules manager is the outlier. `reload()` at `:181-204` just calls `load_all`, inheriting the gap.
**OPEN_GAP:** None additional — the manager is the single offender, all rule-evaluation reads go through `self.registry.read()`.

## #80 — VALID
**Evidence:** `crates/waf-cluster/src/health/mod.rs:23-27` (signature: `peer_senders: Vec<Sender>` captured by value at spawn), `:57-73` (iteration over the captured `&peer_senders` only — no refresh, no read of `node_state.peer_channels`).
Caller: `crates/waf-cluster/src/lib.rs:127` builds `peer_senders` from `self.config.seeds` only; `:184` spawns task with the moved Vec. Late joiners only end up in `NodeState.peer_channels` via `add_peer_channel` (`node.rs:223`), which heartbeat never reads.
**Reasoning:** `node.rs:230-239 broadcast()` does read `peer_channels.lock()` fresh — confirms the field is the live source-of-truth for everything except this loop. Election (`election/mod.rs:293,310`) uses `node_state.broadcast`, so only heartbeat is frozen.
**OPEN_GAP:** None additional in cluster code; behavior matches issue description exactly.

## #81 — VALID
**Evidence:** `crates/waf-cluster/src/sync/rules.rs:108` — `lz4_flex::decompress_size_prepended(data)` with no MAX_SNAPSHOT_BYTES guard. `:160-167 apply_full_snapshot` calls `restore_snapshot` directly on `response.snapshot_lz4`. `:188` calls it on attacker-controlled payload from the wire (`apply_sync_response` → `SyncType::Full`).
No upstream bounds check on the snapshot blob in `apply_sync_response` (`:178-195`). The 4-byte prefix decides the output `Vec` capacity inside lz4_flex.
**Reasoning:** mTLS authenticates the peer identity but not payload semantics — a compromised/buggy main node ships the bomb. lz4_flex's `decompress_size_prepended` reads the u32 LE prefix and `Vec::with_capacity(prefix)` immediately; even before decompression succeeds, allocator commits.
**OPEN_GAP:** `crates/waf-cluster/src/sync/rules.rs:205-207 decompress_snapshot` (pub fn) has identical lack-of-cap. Currently only used by test (`tests/sync_events_batching.rs:170,177`) but is `pub` API — any future caller inherits the same flaw. Add cap to the shared low-level decompress helper, not just `restore_snapshot`.

## #82 — VALID
**Evidence:** `crates/waf-cluster/src/sync/rules.rs:178-195 apply_sync_response` — no version comparison before dispatch. Both arms run, then line 193 `registry.version = response.version` unconditionally. `Full` snapshot path also calls `registry.clear()` (`:162`) before insert, so stale Full forcibly wipes newer state.
`crates/waf-cluster/src/protocol.rs:127-132 RuleChange` has only `op`, `rule_id`, `rule_json` — no `seq` / monotonic id.
**Reasoning:** Out-of-order delivery (retransmit / multi-stream reorder / post-failover stale main) is realistic; QUIC streams give per-stream ordering, not cross-stream / cross-session. Worker has no defense.
**OPEN_GAP:** `crates/waf-cluster/src/sync/config.rs:25-33 ConfigSyncer::apply_sync` exhibits the same pattern — line 31 `self.current_version = sync.version` unconditional. Config-version regression has the same blast radius (silent rollback of node config). Apply the same guard pattern there.

## Summary table
| Issue | Verdict       | Action                                                                                                  |
|-------|---------------|---------------------------------------------------------------------------------------------------------|
| #79   | VALID         | Build `RuleRegistry` off-lock, single write swap (or migrate to `ArcSwap<RuleRegistry>` like siblings). |
| #80   | VALID         | Drop frozen `peer_senders` param; iterate `node_state.peer_channels.lock()` each tick (or reuse `broadcast`). |
| #81   | VALID + GAP   | Add `MAX_SNAPSHOT_BYTES` cap on size prefix in `restore_snapshot` AND `decompress_snapshot`.            |
| #82   | VALID + GAP   | Add `if response.version <= registry.version { return Ok(()) }` guard; extend same check to `ConfigSyncer::apply_sync`. |

## Unresolved questions
- None blocking. Suggest the implementer also decide whether `RuleChange` should gain `seq: u64` (issue #82 fix-sketch mentions this) — it is defensive depth beyond the strict version-regression guard; user-confirm before adding to wire schema.
