---
title: "C2 ModeRegistry Engine Wiring — Per-Feature Mode Enforcement"
description: "Wire ModeRegistry into WafEngine so set_profile toggles enforce/log_only per-feature/policy (contract §2.5)"
status: pending
priority: P0
branch: "main"
tags: [interop, contract, benchmark, c2, tdd]
blockedBy: []
blocks: [260527-1157-waf-interop-v23-critical-compliance]
created: "2026-06-03T06:31:12.738Z"
createdBy: "ck:plan"
source: skill
---

# C2 ModeRegistry Engine Wiring — Per-Feature Mode Enforcement

## Overview

Contract §2.5 requires `set_profile` to toggle enforce/log_only per-feature and per-policy. The ModeRegistry exists, the API updates it correctly, but the engine never calls `resolve()` — it only checks the binary `host_config.log_only_mode` flag. This makes `set_profile` a no-op.

**Strategy:** Wire the existing `ModeRegistry` (lock-free ArcSwap, 3-tier resolution: policy→feature→default) into the engine's decision path. Create a Phase→feature identity mapping so each detection resolves its own mode. Gateway already reads `decision.mode` correctly — zero gateway changes needed.

## Design

```
set_profile API ──→ ModeRegistry.set_*()  ──→  ArcSwap<ModeState>
                                                      │
Engine.inspect_pipeline()                              │
  └── checker fires ──→ DetectionResult.phase          │
        └── phase_feature_identity(phase) → (feature, policy)
              └── mode_registry.resolve(feature, policy) ←────┘
                    └── effective_mode = max(registry_mode, host_config.log_only_mode)
                          └── decision.mode = effective_mode
                                └── WafDecisionMeta.mode ──→ X-WAF-Mode header ✅
```

**Mode resolution rule:** `LogOnly` from either source wins (conservative). `host_config.log_only_mode` acts as a per-host floor; ModeRegistry provides per-feature granularity.

```rust
let registry_mode = mode_registry.resolve(feature, policy);
if registry_mode == InteropMode::LogOnly || ctx.host_config.log_only_mode {
    decision.mode = InteropMode::LogOnly;
}
```

**Mode change is eventually consistent** — after `set_profile()` writes via ArcSwap, in-flight requests may use the previous mode. Next request sees the update.

**Key decisions:**
1. **Mapping via Phase enum** — central `phase_feature_identity(Phase) → (&str, Option<&str>)` function. No Check trait changes. Phase enum covers all 24 detection types.
2. **OnceLock + Clone pattern** — `mode_registry: OnceLock<ModeRegistry>`. ModeRegistry is `#[derive(Clone)]` wrapping `Arc<ArcSwap<ModeState>>` — cloning is O(1) and both engine + AppState share the same underlying ArcSwap. No `Arc<ModeRegistry>` needed. **No AppState signature change.**
3. **Gateway unchanged** — already reads `decision.mode` for enforcement gating + X-WAF-Mode header.
4. **5 mode-setting sites** — `make_block_decision()` (10 callers), IP/URL blacklist (2 direct `WafDecision::block()` sites), rate-limit special case (line 720), custom rules (line 778). All updated with `apply_mode()` helper.
5. **Two-step migration** — keep `log_only_mode` check in `make_block_decision` as safety net while adding `apply_mode()` everywhere, then remove the redundant check in a follow-up commit.

## Phases

| Phase | Name | Status | Effort | Dep |
|-------|------|--------|--------|-----|
| 1 | [TDD Feature Identity Map](./phase-01-tdd-feature-identity-map.md) | Pending | 1h | — |
| 2 | [TDD Engine ModeRegistry Wiring](./phase-02-tdd-engine-moderegistry-wiring.md) | Pending | 2h | 1 |
| 3 | [Integration Verification](./phase-03-integration-verification.md) | Pending | 1h | 2 |

## Files Involved

| File | Action | Purpose |
|------|--------|---------|
| `crates/waf-engine/src/interop/checker_feature_map.rs` | Create | Phase→(feature, policy) mapping |
| `crates/waf-engine/src/interop/mod.rs` | Modify | Re-export new module |
| `crates/waf-engine/src/engine.rs` | Modify | Add mode_registry, apply_mode(), update 3 mode-setting sites |
| `crates/waf-api/src/state.rs` | Unchanged | ModeRegistry is Clone — no signature change needed |
| `crates/prx-waf/src/main.rs` | Modify | After AppState built, call `engine.set_mode_registry(state.mode_registry.clone())` |
| `crates/waf-engine/tests/checker_feature_map.rs` | Create | Mapping unit tests |
| `crates/waf-engine/tests/engine_mode_registry.rs` | Create | TDD mode resolution tests |

## Dependencies

- **Depends on:** C1 audit enrichment (done — `AuditEvent.mode` field exists)
- **Blocks:** `260527-1157-waf-interop-v23-critical-compliance`

## Research Reports

- `plans/reports/researcher-260603-1324-waf-engine-detection-pipeline-report.md`
- `plans/reports/researcher-260603-1325-mode-registry-interop-audit-report.md`
- `plans/reports/researcher-260603-1330-gateway-waf-decision-flow-report.md`
