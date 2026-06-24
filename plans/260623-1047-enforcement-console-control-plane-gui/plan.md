---
title: "Enforcement Console — Control-Plane GUI (E10)"
description: "Operator GUI for the WAF control plane: capability catalog, mode dial, runtime ops, governance map, plus the backend JWT proxy and waf_mode persistence the spec assumed."
status: done
priority: P2
branch: "main-harness"
tags: [control-plane, admin-panel, enforcement, interop-v2.3, E10]
blockedBy: []
blocks: []
created: "2026-06-23T03:52:04.118Z"
createdBy: "ck:plan"
source: skill
status_note: "All phases done (2026-06-24). Backend testcontainer suite pending re-run under Docker."
---

# Enforcement Console — Control-Plane GUI (E10)

## Overview

Implement the control-plane GUI defined in
`docs/stories/epics/E10-control-plane/WAF_ControlPlane_GUI_Design.md` against the
existing `web/admin-panel` (React 18 + Refine 5/6 + antd 5). The GUI exposes the
WAF mode dial (enforce ↔ log_only) over six surfaces: Enforcement Console (S1),
Capability Catalog (S2), Runtime Operations (S3), Global Mode Pill (S4),
X-WAF-Mode correlation (S5), Governance Plane Map (S6).

### Grounding (verified against the codebase, 2026-06-23)

Two BLOCKERs the spec flagged as conditional are **confirmed absent**, so this
plan necessarily includes backend work — it is not frontend-only:

- **BLOCKER 1 — proxy routes missing.** `/api/enforcement/*` JWT routes do not
  exist. The secret-gated `/__waf_control/{capabilities,set_profile,reset_state,flush_cache}`
  routes exist in `crates/waf-api/src/interop_control.rs` with exact JSON shapes.
  Phase 1 adds JWT-guarded mirrors so the browser never holds `X-Benchmark-Secret`.
- **BLOCKER 2 — waf_mode not persisted.** `X-WAF-Mode` is computed for the
  response header (`crates/gateway/src/waf_observability_headers.rs`) but the
  `security_events` table/model carries no mode column. Phase 2 persists it and
  exposes it on the events API so S5 (Phase 6) has real data.

Verified FE conventions to reuse (no new libraries): `httpClient` Bearer flow
(`src/utils/axios.ts`), `useCustom`/`useCustomMutation`, `data-provider` `unwrap`
envelope, `nav-items.ts` sections, App.tsx resource+route, i18n locales `en/vi/zh`,
`security-events/detail.tsx` `Descriptions`, dashboard recent-events columns.
Note: `useAppTheme()` returns an antd `ThemeConfig` — components read colors via
`theme.useToken()`, not from `useAppTheme` directly.

Backend facts the FE must mirror: `InteropMode` serializes as `"enforce"` /
`"log_only"`; precedence is **policy override > feature override > default**
(`crates/waf-engine/src/interop/mode_registry.rs`); the 17-feature catalog comes
from `FeatureCatalog::all()` (`crates/waf-engine/src/interop/feature_catalog.rs`);
`set_profile`/`reset_state`/`flush_cache` responses also include `ts_ms` (the
spec's TS types omit it — add it).

## Phases

| Phase | Name | Status | Priority | Depends on |
|-------|------|--------|----------|-----------|
| 1 | [Backend Enforcement Proxy Routes](./phase-01-backend-enforcement-proxy-routes.md) | In Review | P1 | — |
| 2 | [Backend WAF-Mode Persistence](./phase-02-backend-waf-mode-persistence.md) | Done | P2 | — |
| 3 | [Frontend Foundation](./phase-03-frontend-foundation.md) | Done | P1 | 1 |
| 4 | [Enforcement Console and Capability Catalog](./phase-04-enforcement-console-and-capability-catalog.md) | Done | P1 | 3 |
| 5 | [Runtime Ops, Plane Map and Mode Pill](./phase-05-runtime-ops-plane-map-and-mode-pill.md) | Done | P2 | 3, 4 |
| 6 | [X-WAF-Mode Correlation](./phase-06-x-waf-mode-correlation.md) | Done | P2 | 2, 3 |
| 7 | [Cross-cutting and Acceptance](./phase-07-cross-cutting-and-acceptance.md) | Done | P2 | 4, 5, 6 |

Phase 2 is independent of the FE and can run in parallel with Phases 1/3/4.
Phase 6 is the only FE phase that depends on a backend phase (2).

## Acceptance criteria (plan-level)

Mirrors the spec §10 checklist; full verification lives in Phase 7:

- No `X-Benchmark-Secret` in the frontend bundle (grep the build).
- Catalog renders all 17 features + policies; effective mode = policy>feature>default.
- Feature/policy toggles call correctly-scoped `set-profile`; siblings unaffected.
- `unsupported[]` surfaced after every apply; never swallowed; clears on clean apply.
- `ddos_protection.per_tier` shown with the known-gap warning; not hidden.
- Default-mode change confirmed and clears overrides (`scope:"all"`).
- Reset shows `audit_log_preserved: true`; flush handles not-supported gracefully.
- Mode pill reflects live default mode + override count; links to console.
- X-WAF-Mode visible in event detail + live feed (backed by Phase 2, not inferred).
- Governance plane map renders; footer note present; deep-links work.
- interop-disabled backend → informative `Result`, no crash.
- All strings i18n (en/vi/zh); theme tokens only; `tsc --noEmit` clean; `cargo test` green.

## Dependencies

No cross-plan blockers detected. Related prior plans (read-only context):
`260527-1157-waf-interop-v23-critical-compliance` (interop v2.3 contract),
`260515-1714-fr030-dashboard-backend` (events/stats API),
`260526-1626-admin-panel-gap-requirement` (admin-panel conventions).

## Open questions

> **Resolved (Phase 1, 2026-06-23) — interop-disabled response.** When
> `interop_config.enabled = false`, `/api/enforcement/*` returns
> `404 {ok:false, error:"interop disabled"}`, mirroring the secret plane's 404.
> The FE Result branch treats 404 as "control plane disabled". Implemented in
> `crates/waf-api/src/enforcement.rs`.

1. **Flush-cache semantics.** Current `/__waf_control/flush_cache` returns
   `{ok, action, ts_ms}` with no `supported` field. The spec's FE wants a
   not-supported `Alert`. Decide in Phase 1: either keep flush as always-ok (drop
   the FE not-supported branch) or have the proxy return `supported:false` when
   no cache subsystem is active. Default assumed: keep always-ok, FE treats
   missing `supported` as supported. Confirm with backend owner.
2. **Mode-dial vs host log_only flag.** Scout CONCERN: the `X-WAF-Mode` header
   fallback derives from `host_config.log_only_mode`, while the dial drives
   `ModeRegistry`. Phase 2 must persist the *effective decision mode*
   (`decision.mode`), not the host flag, so console state and event records agree.
