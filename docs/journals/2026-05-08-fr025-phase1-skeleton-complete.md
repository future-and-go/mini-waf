# FR-025 Phase 1: Risk Scoring Skeleton Complete

**Date**: 2026-05-08 10:22  
**Severity**: Info  
**Component**: waf-engine/risk  
**Status**: Resolved

## What Happened

FR-025 Phase 1 skeleton shipped: 1.5K LOC across 14 new files in `waf-engine/risk`, establishing the core risk scoring infrastructure. Triple-index pattern (IP, fingerprint, session) wired into pipeline at Phase::RiskScore = 20.

## Technical Foundation

- **RiskStore trait**: async apply/read/force_max/purge_expired/reset_all contract
- **MemoryRiskStore**: in-memory Arc<RwLock<RiskState>> backend (Phase 7 will add Redis)
- **Triple-index merge**: on collision, take max-score (defensive posture)
- **Pure core**: fold (apply deltas), decay (linear with floor), decide (threshold)
- **Config hot-reload**: ArcSwap + notify watcher mirrors device_fp pattern
- **Pipeline integration**: WafAction::Challenge variant, X-WAF-Risk-Score header support

## Known TOCTOU Hole

Two concurrent first-requests for same actor can lose deltas. Mitigation documented for Phase 7 Redis backend (MULTI/EXEC atomic ops). Acceptable for MVP—MemoryRiskStore is single-process only.

## Test Coverage

- 49 risk module tests passing
- 770 workspace tests clean
- Clippy: zero warnings

**Next**: Phase 2 will wire IP detector into Detector trait, enabling per-IP risk contribution.
