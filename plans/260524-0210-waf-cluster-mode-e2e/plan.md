---
title: "WAF Cluster Mode End-to-End Integration"
description: "Wire the existing waf-cluster crate into the full runtime: transport dispatch, rule sync, event forwarding, config sync, write forwarding, and E2E tests."
status: completed
priority: P1
branch: "main"
tags: [cluster, integration, tdd]
blockedBy: []
blocks: []
created: "2026-05-23T19:30:56.785Z"
createdBy: "ck:plan"
source: skill
---

# WAF Cluster Mode End-to-End Integration

## Overview

The `waf-cluster` crate (~3800 LOC) has working primitives: QUIC mTLS transport, Raft-lite election, phi-accrual health detection, and certificate management. However, **7 of 13 message types are silently ignored** in transport dispatch, and the cluster is disconnected from `WafEngine` (no rule reload callbacks), the API layer (no write forwarding), and the event pipeline (no log aggregation).

This plan wires everything end-to-end with TDD — tests first, then implementation.

### Current State (Gap Audit)

| Component | Status | Gap |
|-----------|--------|-----|
| Transport dispatch | PARTIAL | 7/13 msg types hit catch-all (RuleSyncReq/Resp, ConfigSync, EventBatch, StatsBatch, ApiForward, NodeLeave) |
| NodeState ↔ Engine | MISSING | No reference to WafEngine/RuleReloader — can't trigger rule reloads |
| Rule sync | STUB | Helpers exist (RuleChangelog, handle_sync_request), no dispatch, no periodic sender, no API integration |
| Event forwarding | STUB | EventBatcher works, no handlers, no event sources, no persistence on main |
| Config sync | STUB | Version counter only, no serialization, no broadcast |
| Write forwarding | STUB | PendingForwards helpers complete, API layer never calls them |
| E2E tests | BROKEN | Rule sync test calls non-existent `/api/v1/rules` endpoint |

### Architecture (Unchanged)

```
Main Node (control plane)
├── PostgreSQL storage (authoritative)
├── RuleRegistry + RuleChangelog
├── Admin API (read-write)
└── QUIC server: handles sync requests, receives events

Worker Nodes (data plane)
├── In-memory RuleRegistry (synced from main)
├── Admin API (read-only, writes forwarded)
├── EventBatcher → forwards to main
└── QUIC client: periodic sync, event flush
```

### Key Design Decisions

1. **No new dependencies** — all message types already defined in `protocol.rs`
2. **Engine bridge via callback** — `Arc<dyn RuleReloader>` injected into NodeState
3. **Workers remain stateless** — in-memory cache only, no local DB required
4. **Backward compatible** — `cluster.enabled = false` (default) = zero behavior change

### Validation Decisions (User)

- **Rule sync model**: Pull (periodic poll) — workers poll main every `rules_interval_secs`
- **Auth forwarding**: Both worker AND main validate JWT independently — requires JWT secret sync via config sync (Phase 5 → Phase 6 dependency)
- **Event durability**: Drop during downtime (at-most-once) — no buffer/replay for v1
- **Rate limiting**: Use current source code logic (local per-node) — defer distributed rate limiting

### Red-Team Critical Fixes Applied

1. **Worker reload path** (Phase 2): Added `reload_from_registry()` to `RuleReloader` trait so workers reload from in-memory registry, not DB
2. **RuleRegistry on NodeState** (Phase 2): Added `rule_registry` field for Phase 3 sync to target
3. **JWT secret sync** (Phase 5→6): JWT secret distributed via config sync; all nodes validate auth independently
4. **Term fencing** (Phase 5): ConfigSync messages include election `term` to reject stale-main broadcasts
5. **Batch DB inserts** (Phase 4): Events inserted in batch, not N individual round-trips
6. **Source tagging** (Phase 4): `source_node_id` field on forwarded events prevents double-counting
7. **Frame size limit** (Phase 6): 1MB max payload enforced on ApiForward messages

## Phases

| Phase | Name | Status | Effort | Priority |
|-------|------|--------|--------|----------|
| 1 | [Transport Dispatch Completion](./phase-01-transport-dispatch-completion.md) | Done | 4h | P1 |
| 2 | [NodeState-Engine Bridge](./phase-02-nodestate-engine-bridge.md) | Done | 2h | P1 |
| 3 | [Rule Sync End-to-End](./phase-03-rule-sync-end-to-end.md) | Done | 6h | P1 |
| 4 | [Event Log Aggregation](./phase-04-event-log-aggregation.md) | Done | 4h | P2 |
| 5 | [Config Sync](./phase-05-config-sync.md) | Done | 3h | P2 |
| 6 | [Write Forwarding Integration](./phase-06-write-forwarding-integration.md) | Done | 4h | P2 |
| 7 | [Integration and E2E Tests](./phase-07-integration-and-e2e-tests.md) | Done | 4h | P1 |

**Total estimated effort: ~27h**

## Dependencies

- Phase 1 blocks Phases 3, 4, 5, 6 (dispatch must handle messages before sync can work)
- Phase 2 blocks Phase 3 (engine bridge + RuleRegistry needed for rule sync)
- Phase 5 blocks Phase 6 (JWT secret sync needed for write forwarding auth)
- Phases 3, 4 are independent of each other (can parallelize after 1+2)
- Phase 7 depends on all prior phases

```
Phase 1 (dispatch) ──┬──→ Phase 3 (rule sync) ──────→ Phase 7
Phase 2 (bridge)  ───┘                                    ↑
Phase 1 ──→ Phase 4 (events) ─────────────────────────────┤
Phase 1 ──→ Phase 5 (config sync) ──→ Phase 6 (write fwd) ┘
```
