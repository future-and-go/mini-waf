---
phase: 7
title: "Integration and E2E Tests"
status: completed
priority: P1
effort: "4h"
dependencies: [1, 2, 3, 4, 5, 6]
---

# Phase 7: Integration and E2E Tests

## Overview

Fix the broken `tests/e2e-cluster.sh` (calls non-existent `/api/v1/rules` endpoint) and add comprehensive integration tests covering the full cluster lifecycle: node join, rule sync propagation, event forwarding, config sync, write forwarding, leader election, and failover.

## Requirements

- Functional: E2E test suite passes against 3-node Docker cluster
- Functional: Unit tests cover all sync paths, edge cases, and error paths
- Non-functional: Tests complete within 60s (not counting Docker startup)

## Related Code Files

- Modify: `tests/e2e-cluster.sh` — fix broken rule sync test
- Create: `crates/waf-cluster/tests/cluster_full_lifecycle.rs` — integration test
- Modify: existing test files as needed for coverage

## TDD: Test Categories

### Category 1: Unit Tests (cargo test -p waf-cluster)

Already covered by phases 1-6. Verify all pass together:

- [ ] Transport dispatch coverage (phase 1)
- [ ] Engine bridge mock (phase 2)
- [ ] Rule sync e2e (phase 3)
- [ ] Event forwarding (phase 4)
- [ ] Config sync (phase 5)
- [ ] Write forwarding (phase 6)

### Category 2: Integration Test (in-process, 2-node)

`crates/waf-cluster/tests/cluster_full_lifecycle.rs`:

1. **Node join flow**:
   - Start main node (auto_generate certs)
   - Start worker node pointing to main as seed
   - Assert worker receives JoinResponse with certs
   - Assert main's peer list includes worker

2. **Rule sync propagation**:
   - Main records 3 rule changes
   - Wait `rules_interval_secs` + buffer
   - Assert worker's `rules_version` matches main's
   - Assert mock `RuleReloader` called on worker

3. **Event aggregation**:
   - Worker pushes 5 SecurityEvents
   - Wait for batch flush
   - Assert main received EventBatch with 5 events

4. **Election after main death**:
   - Stop main's heartbeat sender
   - Wait for phi-accrual to declare main dead
   - Assert worker transitions to Candidate → Main
   - Assert new main's term > old term

5. **Config sync**:
   - Main updates config version
   - Assert workers receive ConfigSync within interval

### Category 3: E2E Shell Tests (Docker)

Fix `tests/e2e-cluster.sh`:

1. **Fix rule sync test**: Replace `/api/v1/rules` with correct endpoint (`/api/rules/custom` or the actual CRUD path)

2. **Add test cases**:
   - Create rule on main via API → verify rule appears on worker via API
   - POST write request to worker API → verify forwarded to main and succeeds
   - Stop main container → verify worker elects self as new main
   - Restart stopped main → verify it rejoins as worker

3. **Health check assertions**:
   - All 3 nodes report healthy after startup
   - Cluster status shows correct roles and term

## Implementation Steps

1. **Fix e2e-cluster.sh rule sync test**:
   - Read actual API routes from `waf-api/src/server.rs`
   - Replace `/api/v1/rules` with correct endpoint
   - Test: create rule on main, poll worker until rule appears

2. **Write `cluster_full_lifecycle.rs`**:
   - Use `auto_generate = true` certs for in-process test
   - Start two ClusterNodes on localhost with different ports
   - Run through join → sync → event → failover scenarios
   - Use `tokio::time::timeout` to bound each step

3. **Add write forwarding e2e test**:
   - POST to worker's API
   - Assert 200/201 response (forwarded from main)
   - Assert data visible on main

4. **Verify all tests pass**:
   - `cargo test -p waf-cluster` — unit + integration
   - `./tests/e2e-cluster.sh` — Docker E2E (if Docker available)

## Success Criteria

- [ ] `cargo test -p waf-cluster` — all tests pass (0 failures)
- [ ] `cargo test --workspace` — no regressions in other crates
- [ ] `tests/e2e-cluster.sh` — all test cases pass against Docker cluster
- [ ] Test coverage: join, sync, events, election, failover, write forwarding
- [ ] No flaky tests (deterministic timeouts with generous margins)
- [ ] `cargo check --workspace` passes with zero warnings

## Risk Assessment

- Medium risk: in-process 2-node tests may have port conflicts → use port 0 (OS-assigned)
- Pitfall: timing-dependent tests (election, sync) → use generous timeouts (5-10s)
- Pitfall: Docker not available in CI → skip Docker tests with `#[ignore]` or env check
