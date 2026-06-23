---
phase: 3
title: "Frontend Foundation"
status: pending
priority: P1
dependencies: [1]
effort: "M"
---

# Phase 3: Frontend Foundation

## Overview

Scaffold the FE plumbing every console surface needs: API types, the
`enforcementProvider`, nav section + resource + route, the shared `ModeTag`
component, and the i18n key skeleton across `en/vi/zh`. No business UI yet — this
phase makes the route reachable and the data layer typed.

## Requirements

- Functional: `/enforcement` route renders a placeholder page reachable from a new
  `nav.control` section; `enforcementProvider` can fetch capabilities via the
  Phase 1 routes; shared `ModeTag` renders enforce/log_only consistently.
- Non-functional: types match the Phase 1 contract 1:1 (including `ts_ms`); all new
  strings go through `t()` with keys present in all three locales.

## Architecture

`enforcementProvider` is a thin wrapper over the verified `httpClient`
(`src/utils/axios.ts`, Bearer auto-injected) exposing typed methods for the four
proxy routes — a single place to flip to `/__waf_control` if ever needed. UI
hooks use Refine's `useCustom`/`useCustomMutation` pointed at `/api/enforcement/*`
(matching the dashboard/cluster patterns), so the provider is primarily the typed
URL/shape contract; do not invent a new fetch abstraction.

Data envelope: `useCustom` returns `response.data` as-is from `httpClient`. The
proxy returns the raw control-plane object (`{ ok, features, active }`), NOT the
`{ data: ... }` admin envelope. Type the hook as
`useCustom<CapabilitiesResponse>` and read `query.data?.data` accordingly — verify
the exact unwrap by testing one live call; document the resolved access path here
once confirmed so Phase 4 uses it consistently.

## Related Code Files

- Create: `web/admin-panel/src/providers/enforcement-provider.ts` — typed wrappers
  for capabilities / set-profile / reset-state / flush-cache.
- Create: `web/admin-panel/src/components/mode-tag.tsx` — shared tag:
  `enforce → <Tag color="success">`, `log_only → <Tag color="warning">`.
- Modify: `web/admin-panel/src/types/api.ts` — add `InteropMode`,
  `CapabilityInfo`, `CapabilitiesResponse`, `SetProfileBody`,
  `SetProfileResponse` (incl. `ts_ms`), `ResetStateResponse`,
  `FlushCacheResponse`. (Event `waf_mode` type added in Phase 6.)
- Modify: `web/admin-panel/src/utils/nav-items.ts` — add `nav.control` section +
  `{ key:"enforcement", i18nKey:"nav.enforcement", path:"/enforcement", icon: ControlOutlined, section:"nav.control" }`,
  placed after `nav.overview`, before `nav.protection`.
- Modify: `web/admin-panel/src/App.tsx` — register Refine resource
  `{ name:"enforcement", list:"/enforcement" }` and
  `<Route path="/enforcement" element={<EnforcementConsolePage/>}/>` (before the
  catch-all `*` route).
- Create: `web/admin-panel/src/pages/enforcement/index.tsx` — placeholder page
  (filled in Phase 4); enough to satisfy the route import.
- Modify: `web/admin-panel/src/i18n/locales/{en,vi,zh}.json` — add `nav.control`,
  `nav.enforcement`, and the `enforcement.*` key skeleton (title, defaultMode,
  applyAll, refresh, lastSync, etc.). `en` is the source of truth; vi/zh mirrored.

## Types to add (match Phase 1 shapes)

```ts
export type InteropMode = "enforce" | "log_only";
export interface CapabilityInfo { supported: boolean; toggleable: boolean; policies: string[]; }
export interface CapabilitiesResponse {
  ok: boolean;
  features: Record<string, CapabilityInfo>;
  active: { default_mode: InteropMode; overrides: Record<string, InteropMode> };
}
export interface SetProfileBody {
  scope: "all" | "features" | "policies";
  mode: InteropMode; features?: string[]; feature?: string; policies?: string[];
}
export interface SetProfileResponse {
  ok: boolean; action: "set_profile"; applied: unknown;
  unsupported: string[];
  active: { default_mode: InteropMode; overrides: Record<string, InteropMode> };
  ts_ms: number;
}
export interface ResetStateResponse { ok: boolean; action: "reset_state"; audit_log_preserved: boolean; ts_ms: number; }
export interface FlushCacheResponse { ok: boolean; action?: "flush_cache"; supported?: boolean; ts_ms?: number; }
```

## Implementation Steps

1. Add the types to `types/api.ts` following its existing style.
2. Create `enforcement-provider.ts` over `httpClient` with the four typed methods.
3. Create `mode-tag.tsx`.
4. Add the nav section + item (`ControlOutlined` from `@ant-design/icons`).
5. Register resource + route in `App.tsx`; add placeholder `enforcement/index.tsx`.
6. Add i18n keys to `en/vi/zh`. Provide real vi/zh translations, not English
   placeholders (header language selector exposes all three).
7. Run dev build; confirm `/enforcement` loads, nav entry appears, `tsc --noEmit`
   clean. Make one live `capabilities` call to confirm the data-access path and
   record it in Architecture.

## Success Criteria

- [ ] `/enforcement` reachable from the new `nav.control` section; placeholder renders.
- [ ] `enforcementProvider.getCapabilities()` returns typed data from Phase 1 route.
- [ ] `ModeTag` renders enforce (success) / log_only (warning).
- [ ] No `X-Benchmark-Secret` anywhere in FE source.
- [ ] `tsc --noEmit` clean; i18n keys present in all three locales.

## Risk Assessment

- **Envelope mismatch** (`{data}` vs raw). Mitigated by the step-7 live check and
  recording the resolved access path before Phase 4 depends on it.
- **Locale drift** (missing vi/zh keys → raw key shown). Mitigated by adding keys
  to all three files in the same change and a Phase 7 i18n completeness check.

Rollback: all additions are new files or additive entries; revert nav/route/types.
