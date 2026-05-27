---
title: "Red-Team Review: Scalability Hardening Plan"
date: 2026-05-26
plan: 260526-2146-scalability-hardening
---

# Red-Team Findings Summary

| # | Phase | Severity | Issue | Status |
|---|-------|----------|-------|--------|
| 1 | P1 | CRITICAL | `from_rule_with_source()` returns `Self`, not `()` — `return;` won't compile | FIXING |
| 2 | P2 | CRITICAL | CB config fields belong to `ValkeyClientConfig`, not `AppSecConfig` | FIXING |
| 3 | P2 | HIGH | `Ok(Unavailable)` should trigger `on_failure()`, not `on_success()` | FIXING |
| 4 | P3 | HIGH | `TrySendError::Closed` unhandled (dead batch writer) | FIXING |
| 5 | P4 | HIGH | `reload::Layer` ordering affects global vs per-layer filtering | FIXING |
| 6 | P5 | HIGH | `unreachable!()` violates Iron Rules | FIXING |
| 7 | P6 | HIGH | Startup behavior change: fail-closed → fail-open | FIXING |
| 8 | P6 | HIGH | SIGTERM race during backoff sleep | FIXING |
| 9 | P1 | MEDIUM | CidrMatch has same per-request parsing issue | FIXING |
| 10 | P1 | MEDIUM | `debug_assert!(false)` panics in test builds | FIXING |
| 11 | P2 | MEDIUM | Mutex+AtomicU32 TOCTOU race | FIXING |
| 12 | P2 | MEDIUM | threshold=0 edge case | FIXING |
| 13 | P3 | MEDIUM | Batch INSERT unique constraint kills whole batch | FIXING |
| 14 | P3 | MEDIUM | Dropped events compliance doc needed | FIXING |
| 15 | P4 | MEDIUM | AppState construction pattern | FIXING |
| 16 | P5 | MEDIUM | StorageError enum exhaustive match breakage | FIXING |
| 17 | P6 | MEDIUM | Max restart count + backoff reset needed | FIXING |
| 18 | P7 | MEDIUM | grep for unwrap is flawed + 1h estimate too low | FIXING |
| 19 | ALL | MEDIUM | Phases 3+4 not truly independent (shared structs) | FIXING |
