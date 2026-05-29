---
title: "WAF Control Interface §2 — Interop Contract Compliance"
description: "Implement 4 /__waf_control/* endpoints with ModeRegistry, benchmark-secret auth, per-feature/policy mode toggle, synchronous state reset, and cache flush"
status: completed
priority: P1
effort: "3-4d"
branch: "main"
tags: [interop, contract, benchmark, control-plane, tdd]
blockedBy: []
blocks: []
created: "2026-05-28T15:11:10.644Z"
createdBy: "ck:plan"
source: skill
---

# WAF Control Interface §2 — Interop Contract Compliance

## Overview

Implement the 4 mandatory `/__waf_control/*` endpoints required by interop contract v2.3 §2. The benchmarker uses these to discover WAF capabilities, reset runtime state between test runs, toggle enforce/log_only per feature/policy, and flush cache. Without these, all benchmark orchestration is blocked.

**Contract:** `analysis/docs/EN_waf_interop_contract_v2.3.md` §2.1–2.7
**Gap report:** `plans/reports/contract-gap-analysis-260527-1133-waf-interop-v23-report.md` §2
**Parent plan:** `plans/260527-1157-waf-interop-v23-critical-compliance/plan.md` Phase 4

## Design Principles

1. **Additive only** — no changes to existing API routes, JWT auth, or detection pipeline
2. **Lock-free hot path** — ModeRegistry uses ArcSwap; proxy reads are 1-2ns atomic loads
3. **TDD** — each phase writes tests first, implements second, validates third
4. **Encapsulated reset** — WafEngine exposes `reset_runtime_state()` rather than leaking internals
5. **Constant-time auth** — benchmark secret comparison prevents timing attacks

## Architecture

```
┌────────────────────────────────────────────────────────────────┐
│                        waf-api (Axum)                          │
│  ┌──────────────────────────────────────────────────────────┐  │
│  │  /__waf_control/* route group                            │  │
│  │  └─ benchmark_secret_guard middleware (from_fn)          │  │
│  │     ├─ GET  /capabilities  → FeatureCatalog + ModeReg   │  │
│  │     ├─ POST /reset_state   → Engine.reset + Cache.flush  │  │
│  │     ├─ POST /set_profile   → ModeRegistry.apply          │  │
│  │     └─ POST /flush_cache   → ResponseCache.flush         │  │
│  └──────────────────────────────────────────────────────────┘  │
│                                                                │
│  Existing routes: /api/* (JWT), /health (public), /ws/*        │
└───────────────┬────────────────────────────────────────────────┘
                │
┌───────────────▼────────────────────────────────────────────────┐
│                      waf-engine                                │
│  ┌─────────────────────┐  ┌─────────────────────────────────┐  │
│  │  ModeRegistry        │  │  reset_runtime_state()          │  │
│  │  (ArcSwap<ModeState>)│  │  ├─ rl_store.clear_all()       │  │
│  │  ├─ default_mode     │  │  ├─ ddos_ban_table.clear()     │  │
│  │  ├─ feature_overrides│  │  ├─ ddos_counter.clear_all()   │  │
│  │  └─ policy_overrides │  │  ├─ tx_store.clear_all()       │  │
│  │                      │  │  ├─ risk_store.reset_all()     │  │
│  │  resolve(feat, pol)  │  │  └─ identity_store.clear_all() │  │
│  │  → InteropMode       │  │                                 │  │
│  └─────────────────────┘  └─────────────────────────────────┘  │
│                                                                │
│  ┌─────────────────────┐                                       │
│  │  FeatureCatalog      │  Static mapping: detection phases    │
│  │  → features/policies │  → contract feature names            │
│  └─────────────────────┘                                       │
└────────────────────────────────────────────────────────────────┘
```

## Phases

| Phase | Name | Status | Priority | Effort | Dependencies |
|-------|------|--------|----------|--------|--------------|
| 1 | [ModeRegistry Core](./phase-01-moderegistry-core.md) | **Complete** | P1 | 4-6h | None |
| 2 | [Benchmark Auth Middleware](./phase-02-benchmark-auth-middleware.md) | **Complete** | P1 | 2-3h | None |
| 3 | [Capabilities Endpoint](./phase-03-capabilities-endpoint.md) | **Complete** | P1 | 3-4h | Phase 1 |
| 4 | [Reset State Endpoint](./phase-04-reset-state-endpoint.md) | **Complete** | P1 | 4-6h | Phase 2 |
| 5 | [Set Profile Endpoint](./phase-05-set-profile-endpoint.md) | **Complete** | P1 | 4-6h | Phases 1, 2 |
| 6 | [Flush Cache Endpoint](./phase-06-flush-cache-endpoint.md) | **Complete** | P2 | 1-2h | Phase 2 |
| 7 | [Integration Testing](./phase-07-integration-testing.md) | **Complete** | P1 | 3-4h | Phases 1-6 |

**Total estimated effort:** 3-4 days

## Parallelism

- Phase 1 (ModeRegistry) and Phase 2 (Auth Middleware) can run in **parallel** (independent modules)
- Phase 4 (Reset State) and Phase 6 (Flush Cache) can run in **parallel** after Phase 2
- Phase 3 (Capabilities) needs Phase 1 (reads ModeRegistry snapshot)
- Phase 5 (Set Profile) needs both Phase 1 (writes ModeRegistry) and Phase 2 (auth)
- Phase 7 (Integration) is the final gate

## Dependencies

### Cross-Plan

- **Parent plan** `260527-1157-waf-interop-v23-critical-compliance` Phase 1 (Core Type System Refactor) — adds `InteropMode` enum and `WafDecision.mode` field. This plan can proceed independently using a local `InteropMode` enum in the interop module; when Phase 1 of the parent lands, swap to the shared type.
- **Parent plan** Phase 2 (Observability Headers) — `X-WAF-Mode` header injection depends on ModeRegistry from this plan. This plan should land first.

### Internal

- `arc-swap` — already in workspace `Cargo.toml`
- `subtle` — for constant-time comparison (already transitive dep via `rustls`)
- No new external dependencies required

## Research Reports

- Architecture patterns: `plans/reports/researcher-260528-2206-waf-control-interface-architecture-patterns-report.md`
- Contract compliance: `plans/reports/researcher-260528-2206-waf-control-contract-compliance-analysis-report.md`

## Key Design Decisions

| Decision | Choice | Rationale |
|----------|--------|-----------|
| Mode state storage | ArcSwap (not RwLock) | 1-2ns reads from hot path; writes are rare control-plane ops |
| Auth mechanism | Header guard middleware (`from_fn`) | Contract requires `X-Benchmark-Secret`; scoped to route group |
| Feature catalog | Static `const` mapping | Detection phases don't change at runtime; zero allocation |
| Reset approach | `WafEngine::reset_runtime_state()` | Encapsulates all internal stores; callers don't need to know internals |
| Unsupported features | Lenient (200 + `unsupported` array) | Benchmarker can send superset requests without 400 errors |
| Config field | `[interop]` section in TOML | Clean namespace; `benchmark_secret` + `audit_log_path` + `enabled` |
| Secret comparison | Constant-time via `subtle::ConstantTimeEq` | Prevents timing side-channel on secret value |

## Risk Assessment

| Risk | Impact | Mitigation |
|------|--------|------------|
| ModeRegistry adds latency to hot path | Low | ArcSwap load is ~1-2ns; HashMap lookup O(1) amortized |
| Reset state misses a subsystem | High | Scout report enumerates all 15 state components; add `clear_all()` to each trait |
| Feature catalog becomes stale | Medium | Static const; new detectors must register in catalog |
| Concurrent set_profile race | Medium | ArcSwap atomic swap; in-flight requests see old or new, never partial |
| Control endpoints attacked during benchmark | Low | Benchmark secret + admin IP binding + rate limiting |
| Stores lack `clear_all()` methods | Medium | Phase 4 adds `clear_all()` to RateLimitStore, CounterStore, IdentityStore traits |
