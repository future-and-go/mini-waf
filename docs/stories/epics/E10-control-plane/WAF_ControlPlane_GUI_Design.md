# PRX-WAF — Control-Plane GUI: Detailed Design Spec

> **Source of truth:** `docs/product/waf-control-plane.md` (interop contract v2.3 §2). Hackathon rubric is **out of scope** for this document.
> **Goal:** Detailed, enterprise-grade design for every GUI surface that exposes the control plane, ready for an AI agent to implement against the existing `web/admin-panel` (React 18 + Refine 5 + antd 5).
> **Grounding:** Reuses verified conventions — `dataProvider`/`useCustom`, `httpClient` Bearer flow, `navItems` sections, `useAppTheme`, i18next, `RiskBandPreview`/`KpiCard` patterns. No new libraries.

---

## 0. Security decision (locked)

**Transport: backend-proxy via JWT-guarded `/api/enforcement/*`. The browser never holds `X-Benchmark-Secret`.**

The GUI talks to a thin `enforcementProvider` (new, `src/providers/enforcement-provider.ts`) that calls operator-authenticated admin routes. The backend (`waf-api`, same process that owns `ModeRegistry` + `interop_config`) services them against the same registry `/__waf_control/*` uses.

```
Browser ──JWT──▶ /api/enforcement/*  ──in-process──▶ ModeRegistry ◀── /__waf_control/* (secret-gated, benchmarker)
```

Required new backend routes (raise as `// BLOCKER` if absent — do not embed the secret instead):

| GUI action | Proxy route (JWT) | Mirrors control-plane |
| --- | --- | --- |
| Read catalog + active modes | `GET /api/enforcement/capabilities` | `GET /__waf_control/capabilities` |
| Set mode (scoped) | `POST /api/enforcement/set-profile` | `POST /__waf_control/set_profile` |
| Reset runtime state | `POST /api/enforcement/reset-state` | `POST /__waf_control/reset_state` |
| Flush cache | `POST /api/enforcement/flush-cache` | `POST /__waf_control/flush_cache` |

Response shapes are identical to the control-plane contract (so the FE types match the doc 1:1). All must return through the standard `{data}` / `{ok,...}` envelope the `unwrap` helper handles.

---

## 1. Surface inventory (scope = all control-plane surfaces)

| # | Surface | Type | Where |
| --- | --- | --- | --- |
| S1 | **Enforcement Console** | New page + resource | new nav section `nav.control` |
| S2 | **Capability Catalog** (17 features × policies) | Section in S1 | inside Enforcement Console |
| S3 | **Runtime Operations** (reset_state / flush_cache) | Section in S1 | inside Enforcement Console |
| S4 | **Global Mode Pill** | Header widget | `app-layout.tsx` header |
| S5 | **X-WAF-Mode correlation** | Column + field | live feed + `security-events/detail` |
| S6 | **Governance Plane Map** | Section in S1 | inside Enforcement Console |

Nav: add a new section `nav.control` (placed right after `nav.overview`, before `nav.protection`) with one item:
```ts
// nav-items.ts
{ key: "enforcement", i18nKey: "nav.enforcement", path: "/enforcement", icon: ControlOutlined, section: "nav.control" },
```
Register Refine resource `{ name: "enforcement", list: "/enforcement" }` + `<Route path="/enforcement" element={<EnforcementConsolePage/>}/>`.

---

## 2. S1 — Enforcement Console (page layout)

Route `/enforcement`. Single scrollable page, max-width 1200px, antd `Space direction="vertical" size={16}`. Four stacked blocks: **header strip → Capability Catalog → Governance Plane Map → Runtime Operations**.

ASCII wireframe:

```
┌─ Enforcement Console ───────────────────────────────────────────────────┐
│  Default mode: ◉ ENFORCE   ○ LOG_ONLY        [ Apply to all ▾ ]  ↻ Refresh│
│  Last sync 3s ago · X-WAF-Mode reflects the policy of the final action    │
├───────────────────────────────────────────────────────────────────────── │
│  CAPABILITY CATALOG                              search [_________] ⌕      │
│  ┌─ filter: All · Enforce · Log-only · Overridden ──────────────────────┐ │
│  │ ▸ access_control          [enforce ▾]   4 policies   ●Config ●Admin   │ │
│  │ ▸ injection_control       [enforce ▾]   3 policies   ●Config          │ │
│  │ ▾ ddos_protection         [log_only▾]   2 policies   ●Config          │ │
│  │     per_ip_burst          [log_only▾]            bound ✓              │ │
│  │     per_tier              [enforce ▾]   ⚠ advertised · not bound      │ │
│  │ ▸ rate_limiting           [enforce ▾]   2 policies                    │ │
│  │ … (17 features total)                                                 │ │
│  └────────────────────────────────────────────────────────────────────┘ │
│  ⚠ 2 items unsupported in last apply: foo.bar, baz  (dismiss)             │
├───────────────────────────────────────────────────────────────────────── │
│  GOVERNANCE PLANES         (where each capability is actually governed)    │
│  Config ▸ enable flags, thresholds, bands   Admin ▸ rules/lists   Control ▸ │
│  enforce↔log_only only.  [ matrix table ]                                  │
├───────────────────────────────────────────────────────────────────────── │
│  RUNTIME OPERATIONS                                                        │
│  [ Reset runtime state ]   [ Flush cache ]      audit log: preserved ✓     │
└────────────────────────────────────────────────────────────────────────── ┘
```

### Header strip (component `<DefaultModeControl>`)
- `Segmented` (antd) with `ENFORCE` / `LOG_ONLY`, bound to `active.default_mode` from capabilities.
- Changing it → `Modal.confirm` ("Set default mode for ALL features and policies to X? This clears per-feature overrides.") → `set-profile {scope:"all", mode}`. (Matches doc §2.5: `scope:"all"` resets overrides.)
- Right side: "Apply to all" dropdown (enforce / log_only) as a shortcut, `↻ Refresh`, and a relative "last sync" timestamp (use `useCustom` `dataUpdatedAt`).
- Sub-caption explains `X-WAF-Mode` semantics (doc §2.7) so operators trust the correlation column in S5.

Data hook:
```ts
const caps = useCustom<CapabilitiesResponse>({
  url: "/api/enforcement/capabilities", method: "get",
  queryOptions: { staleTime: 3_000, refetchInterval: 10_000 },
});
```

---

## 3. S2 — Capability Catalog

The centerpiece. Renders the **fixed 17-feature catalog** (doc "Capability catalog"). Each feature is an expandable row; policies are child rows. Every row carries an enforce/log_only control.

### Data model (types in `src/types/api.ts`)
```ts
export type InteropMode = "enforce" | "log_only";

export interface CapabilityInfo {
  supported: boolean;       // always true in current catalog
  toggleable: boolean;      // always true
  policies: string[];
}
export interface CapabilitiesResponse {
  ok: boolean;
  features: Record<string, CapabilityInfo>;
  active: { default_mode: InteropMode; overrides: Record<string, InteropMode> };
}
export interface SetProfileBody {
  scope: "all" | "features" | "policies";
  mode: InteropMode;
  features?: string[];
  feature?: string;
  policies?: string[];
}
export interface SetProfileResponse {
  ok: boolean;
  applied: unknown;
  unsupported: string[];
  active: { default_mode: InteropMode; overrides: Record<string, InteropMode> };
}
```

### Effective-mode resolution (must mirror backend `ModeRegistry`)
Display the *effective* mode per row using the doc's precedence — **policy override > feature override > default**:
```ts
const effective = (feat: string, pol?: string): InteropMode => {
  const o = caps.active.overrides;
  if (pol && o[`${feat}.${pol}`]) return o[`${feat}.${pol}`];
  if (o[feat]) return o[feat];
  return caps.active.default_mode;
};
```
A row whose effective mode comes from an override shows a small `Tag` "overridden" so operators see it differs from default.

### Row interactions
- **Feature mode select** → `set-profile {scope:"features", mode, features:[feat]}`. (doc §2.5: only listed features change.)
- **Policy mode select** → `set-profile {scope:"policies", mode, feature, policies:[pol]}`. (siblings unchanged.)
- Use `useCustomMutation`; on success, refetch capabilities (authoritative `active` comes back in the response — apply it optimistically, then reconcile on refetch).
- **`unsupported[]` handling (doc decision 0008):** after every mutation, if `unsupported.length > 0`, show a dismissible `Alert type="warning"` listing them. Never swallow. Keep it visible until dismissed or next successful apply with empty `unsupported`.

### Known-gap labeling (doc "Known gap")
`ddos_protection.per_tier` is advertised but **not bound to any detection phase**. Render its policy row with a `Tooltip` + `⚠` tag: *"Advertised & toggleable, but no detection phase binds to it — set_profile returns ok but has no hot-path effect."* Do **not** hide it (catalog is static and must show all 17).

### Plane badges per feature
Small colored dots next to each feature indicating which planes govern it (Config / Admin / Control) — see S6 matrix for the mapping. Purely informational; links to the relevant config/admin page on click (deep-link via `useGo`).

### Catalog controls
- `Input.Search` (debounce 300ms) filters by feature/policy name.
- `Segmented` quick-filter: All / Enforce / Log-only / Overridden.
- `Table` with `expandable` (feature → policies) OR a custom `Collapse`. Prefer antd `Table` with `expandedRowRender` for dense, enterprise feel; virtual not needed (17 rows).

ASCII (expanded feature):
```
▾ custom_rules            [enforce ▾]   ●Admin ●Config
    yaml_rules            [enforce ▾]
    rhai_scripts          [log_only▾]   overridden
    wasm_plugins          [enforce ▾]
```

---

## 4. S3 — Runtime Operations

Two guarded actions, antd `Card title="Runtime operations"`.

### Reset runtime state
- Button (danger, `ReloadOutlined`) → `Modal.confirm`:
  > "Reset runtime state? Clears risk state, rate-limit counters, cache, challenge/session state, and temporary enforcement state. The audit log is preserved (append-only)."
- → `POST /api/enforcement/reset-state`. On success show `message.success` and render the returned `audit_log_preserved: true` + `ts_ms` (formatted via dayjs) as a confirmation line. (doc §2.4.)
- Disable button while pending; the operation is synchronous/atomic server-side — don't poll, just await.

### Flush cache
- Button (`ClearOutlined`) → `POST /api/enforcement/flush-cache`.
- If backend returns "not supported" (doc §2.6 allows this), show an `Alert type="info"` "Caching not implemented — nothing to flush." instead of an error.

Response types:
```ts
export interface ResetStateResponse { ok: boolean; action: "reset_state"; audit_log_preserved: boolean; ts_ms: number; }
export interface FlushCacheResponse { ok: boolean; supported?: boolean; }
```

---

## 5. S4 — Global Mode Pill (header)

A persistent indicator so operators always know the live default mode without opening the console.

- Component `<ModePill>` in `app-layout.tsx` header, left of the language selector.
- Reads `active.default_mode` (shared `useCustom` cache key — same query as console, so no double fetch).
- `ENFORCE` → solid success `Tag` with shield icon; `LOG_ONLY` → amber `Tag` with eye icon.
- If any overrides exist, append a subtle `Badge count={n}` "n overrides" → click navigates to `/enforcement`.
- Click the pill → `/enforcement`. No mode-flip from the header (avoid accidental global change from a always-visible control); flipping lives in the console behind a confirm.

```
… [🛡 ENFORCE · 3 overrides]   [🌐 English ▾]  [🎨]  [👤 admin ▾]
```

---

## 6. S5 — X-WAF-Mode correlation

Doc §2.7: every proxied response carries `X-WAF-Mode` reflecting the mode of the policy that produced the final `X-WAF-Action`. Surface it so operators can tell whether a block was real (enforce) or shadow (log_only).

### In security-events detail (`pages/security-events/detail.tsx`)
Add a field to the event descriptor:
- `Descriptions.Item label="Enforcement mode"` → `<Tag>` enforce/log_only.
- Pair it visually with the existing action field: e.g. "Action: block · Mode: log_only" reads as "would have blocked, but only logged."
- **BLOCKER check:** confirm the event payload / `security_events` row carries the mode. If not, backend must add `waf_mode` to the event record. Mark `// BLOCKER:` if missing — do not infer mode client-side (it's per-policy, FE can't compute it reliably).

### In live feed / recent-events table
Add a compact "Mode" column (small tag). Keep it narrow; only show when value present. Reuse the same `<ModeTag>` component as the detail page and the pill for visual consistency.

`<ModeTag>` (shared, `src/components/mode-tag.tsx`):
```
enforce  → <Tag color="success">enforce</Tag>
log_only → <Tag color="warning">log_only</Tag>
```

---

## 7. S6 — Governance Plane Map

Doc "Configuration boundary": the control plane is a *mode dial, not a config manager*. This read-only matrix teaches operators where each capability is actually governed, preventing the "I toggled it but nothing happened" confusion (especially `per_tier`).

antd `Table`, columns: Capability · Config plane · Admin plane · Control plane. Cells show ✓ + a deep-link where the plane offers a page.

```
Capability          Config (startup/.toml)        Admin (API/UI)            Control (set_profile)
access_control      —                              ✓ IP/URL lists → /ip-rules ✓ enforce/log_only
injection_control   ✓ enable flags                 —                          ✓ enforce/log_only
ddos_protection     ✓ ddos.tiers.*.threshold       —                          ✓ (per_tier inert ⚠)
geo_protection      ✓ GeoIP ipv4/ipv6 path         ✓ country rules → /geo-…   ✓ enforce/log_only
risk_assessment     ✓ risk bands                   —                          ✓ enforce/log_only
…
```

Footer note (verbatim intent from doc): *"A detector disabled in config produces no verdict — toggling its mode here has no effect. Enabling/tuning a capability is always a Config or Admin operation, never a Control one."*

The Config/Admin columns are static metadata (hard-code the mapping in `src/utils/governance-map.ts` from the doc's catalog + boundary table). The Control column is always ✓ (all 17 are toggleable).

---

## 8. Cross-cutting: states, i18n, theme

- **Loading:** `Skeleton`/`Spin` on first capabilities load; keep last good data on refetch (React-Query `keepPreviousData`).
- **Error:** capabilities fetch fail → page-level `Alert type="error"` with retry; if backend reports interop disabled (`enabled:false` ⇒ 404), show `Result status="info"` "Control plane is disabled in config (`interop.enabled = false`)." Don't crash.
- **Empty unsupported:** never render the warning when `unsupported` is empty.
- **i18n:** all strings via `t()`; add keys under `nav.control`, `enforcement.*` to `en.json` first, mirror to other locales (at least `vi`, `zh` which the header selector exposes). Key examples: `enforcement.title`, `enforcement.defaultMode`, `enforcement.applyAll`, `enforcement.unsupportedWarning`, `enforcement.resetConfirm`, `enforcement.perTierGap`, `enforcement.planeMap`.
- **Theme:** colors via `useAppTheme` tokens; reuse action color convention — enforce = success green `#52c41a`, log_only = warning amber `#fa8c16`. No hardcoded hex outside the shared `ModeTag`.
- **A11y:** keyboard-operable selects, visible focus, confirm modals trap focus (antd defaults). The mode pill has an `aria-label` describing current mode.

---

## 9. File touch map (for implementation)

| File | Change |
| --- | --- |
| `src/providers/enforcement-provider.ts` | **new** — thin wrapper over `httpClient` for the 4 proxy routes; single place to flip to `/__waf_control` fallback if ever needed |
| `src/types/api.ts` | add `InteropMode`, `CapabilitiesResponse`, `SetProfileBody/Response`, `ResetStateResponse`, `FlushCacheResponse`, event `waf_mode` |
| `src/utils/nav-items.ts` | add `nav.control` section + `enforcement` item (`ControlOutlined`) |
| `src/utils/governance-map.ts` | **new** — static Config/Admin/Control mapping per capability |
| `src/components/mode-tag.tsx` | **new** — shared enforce/log_only tag |
| `src/components/mode-pill.tsx` | **new** — header pill (S4) |
| `src/pages/enforcement/index.tsx` | **new** — console page (S1–S3, S6) |
| `src/pages/enforcement/capability-catalog.tsx` | **new** — catalog table (S2) |
| `src/pages/enforcement/plane-map.tsx` | **new** — governance matrix (S6) |
| `src/layouts/app-layout.tsx` | mount `<ModePill>` in header |
| `src/pages/security-events/detail.tsx` | add Enforcement-mode field (S5) |
| `src/pages/dashboard/index.tsx` | add Mode column to recent-events (S5) |
| `App.tsx` | register `enforcement` resource + route |
| `src/i18n/locales/*.json` | add `nav.control`, `enforcement.*` keys |

---

## 10. Acceptance checklist

- [ ] No `X-Benchmark-Secret` anywhere in the frontend bundle (grep the build).
- [ ] Capabilities renders all 17 features with their policies; effective mode uses policy>feature>default.
- [ ] Feature/policy toggles call the correctly-scoped `set-profile`; siblings unaffected.
- [ ] `unsupported[]` surfaced after every apply; never swallowed; clears on clean apply.
- [ ] `ddos_protection.per_tier` shown with the known-gap warning; not hidden.
- [ ] Default-mode change is confirmed and clears overrides (scope:"all").
- [ ] Reset shows `audit_log_preserved: true`; flush handles not-supported gracefully.
- [ ] Mode pill reflects live default mode + override count; links to console.
- [ ] X-WAF-Mode visible in event detail and live feed (or `// BLOCKER` filed if payload lacks it).
- [ ] Governance plane map renders; footer note present; deep-links work.
- [ ] interop-disabled backend → informative Result, no crash.
- [ ] All strings i18n; theme tokens only; `tsc --noEmit` clean.
