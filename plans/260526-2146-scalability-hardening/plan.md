---
title: "Scalability Hardening: P99 Latency, Tracing, DB Resilience"
description: "Fix 7 scalability findings: regex pre-compile, circuit breaker, batch audit writer, smart tracing, DB resilience, sidecar restart"
status: done
priority: P1
effort: "18h"
branch: "main"
tags: [scalability, p99, tracing, resilience, tdd]
blockedBy: []
blocks: [260524-0210-waf-cluster-mode-e2e]
created: "2026-05-26"
createdBy: "ck:plan"
source: skill
---

# Scalability Hardening: P99 Latency, Tracing, DB Resilience

## Overview

Seven architectural findings from code review targeting p99 5ms latency, smart tracing/logging, and fault tolerance. Three cluster findings (#1 sync dead code, #4 split-brain, #6 ForwardOnly dead code) handled by cluster plan — OUT OF SCOPE here.

## Phases

| Phase | Name | Priority | Effort | Status |
|-------|------|----------|--------|--------|
| 1 | [Regex Pre-Compilation Guarantee](./phase-01-regex-pre-compilation-guarantee.md) | P1 | 2h | Done |
| 2 | [CrowdSec AppSec Circuit Breaker](./phase-02-crowdsec-appsec-circuit-breaker.md) | P1 | 3h | Done |
| 3 | [Batched Audit Log Writer](./phase-03-batched-audit-log-writer.md) | P1 | 3h | Done |
| 4 | [Smart Tracing and Log Sampling](./phase-04-smart-tracing-and-log-sampling.md) | P2 | 3h | Done |
| 5 | [DB Connection Resilience](./phase-05-db-connection-resilience.md) | P2 | 2h | Done |
| 6 | [VictoriaLogs Sidecar Auto-Restart](./phase-06-victorialogs-sidecar-auto-restart.md) | P2 | 2h | Done |
| 7 | [Integration Validation](./phase-07-integration-validation.md) | P2 | 3h | Done |

## Dependency Graph

```
Phase 1 (regex)  ──┐
Phase 2 (CB)     ──┤
Phase 3 (batch)  ──┤
Phase 4 (tracing)──┼──→ Phase 7 (integration)
Phase 5 (DB)     ──┤
Phase 6 (sidecar)──┘

Phases 1, 2, 6: fully independent, parallelizable
Phase 5 before Phase 3 (error variant must exist before batch writer)
Phase 3 before Phase 4 (both touch initialization structs — RED-TEAM)
Phase 7: blocked by all of 1–6
```

## Cross-Plan Dependencies

- **This plan's Phase 3** (batched DB writer) feeds into cluster plan's Phase 4 (event log aggregation). Cluster event forwarding can reuse the batch writer channel.
- **blockedBy**: none
- **blocks**: `260524-0210-waf-cluster-mode-e2e` (Phase 3 output improves cluster event pipeline)

## File Ownership

| Phase | Owned Files |
|-------|------------|
| 1 | `crates/waf-engine/src/rules/engine.rs` |
| 2 | `crates/waf-engine/src/crowdsec/appsec.rs`, `crowdsec/circuit_breaker.rs` (new) |
| 3 | `crates/waf-engine/src/engine.rs`, `logging/db_batch_writer.rs` (new) |
| 4 | `crates/prx-waf/src/main.rs`, `crates/gateway/src/proxy.rs`, `crates/waf-api/src/state.rs` |
| 5 | `crates/waf-storage/src/db.rs`, `crates/waf-storage/src/error.rs` |
| 6 | `crates/prx-waf/src/victoria_logs/sidecar.rs` |

No overlap — each phase touches distinct files.

## Research Reports

- [Hot-Path Optimization](../reports/researcher-260526-2146-hot-path-optimization.md)
- [Tracing & DB Resilience](../reports/researcher-260526-2146-tracing-db-resilience.md)
