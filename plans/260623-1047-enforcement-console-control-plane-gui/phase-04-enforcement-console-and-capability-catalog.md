---
phase: 4
title: "Enforcement Console and Capability Catalog"
status: pending
priority: P1
dependencies: [3]
effort: "L"
---

# Phase 4: Enforcement Console and Capability Catalog

## Overview

Build the console page shell (S1) and its centerpiece, the Capability Catalog (S2):
the 17-feature table with effective-mode resolution, per-feature/per-policy mode
toggles, the default-mode dial, `unsupported[]` handling, and the
`ddos_protection.per_tier` known-gap warning.

## Requirements

- Functional:
  - Single scrollable page at `/enforcement`, max-width 1200px,
    `Space direction="vertical" size={16}`, header strip on top.
  - Header `<DefaultModeControl>`: antd `Segmented` ENFORCE/LOG_ONLY bound to
    `active.default_mode`; changing it → `Modal.confirm` → `set-profile {scope:"all", mode}`
    (clears overrides). "Apply to all" dropdown shortcut, `↻ Refresh`, relative
    "last sync" from `useCustom` `dataUpdatedAt`. Sub-caption explains X-WAF-Mode.
  - Catalog renders all 17 features (expandable rows) and their policies (child
    rows), each with an enforce/log_only control.
  - Effective mode per row = **policy override > feature override > default**;
    overridden rows show an "overridden" `Tag`.
  - Feature toggle → `set-profile {scope:"features", mode, features:[feat]}`.
    Policy toggle → `set-profile {scope:"policies", mode, feature, policies:[pol]}`.
  - After every mutation: if `unsupported.length>0`, show dismissible
    `Alert type="warning"` listing them; keep visible until dismissed or next
    clean apply. Apply returned `active` optimistically, then refetch.
  - `ddos_protection.per_tier`: render with `⚠` tag + `Tooltip` known-gap text;
    never hide it.
  - Search (`Input.Search`, 300ms debounce) over feature/policy names; `Segmented`
    quick-filter All / Enforce / Log-only / Overridden.
- Non-functional: theme colors via `theme.useToken()` + `ModeTag`; no hardcoded
  hex outside `ModeTag`; all strings i18n; keyboard-operable selects, focus-trapped
  confirms (antd defaults).

## Architecture

Single capabilities query shared by the whole console (and the pill in Phase 5)
via a stable `useCustom` queryKey so there is no double fetch:

```ts
const caps = useCustom<CapabilitiesResponse>({
  url: "/api/enforcement/capabilities", method: "get",
  queryOptions: { staleTime: 3_000, refetchInterval: 10_000, queryKey: ["enforcement-capabilities"] },
});
```

Effective-mode resolver mirrors `mode_registry.rs`:
```ts
const effective = (feat: string, pol?: string): InteropMode => {
  const o = active.overrides;
  if (pol && o[`${feat}.${pol}`]) return o[`${feat}.${pol}`];
  if (o[feat]) return o[feat];
  return active.default_mode;
};
```

Catalog uses antd `Table` with `expandedRowRender` (feature → policies); 17 rows,
no virtualization needed. Mutations use `useCustomMutation`; `onSuccess` applies
the response's `active` to the query cache, then `caps.query.refetch()`.

Decompose to respect the 200-LOC guideline: `index.tsx` (page shell + header
strip + caps hook + state), `capability-catalog.tsx` (table + rows + filters +
toggles + unsupported alert + `per_tier` gap). Per-feature plane badges are
**deferred to Phase 5**, which creates `governance-map.ts`; adding them here would
introduce a forward dependency on a module that does not yet exist. Phase 5 wires
the badges into the catalog once the map is the single source of truth (badges are
"purely informational" per the spec, so the catalog is fully functional without
them in this phase).

## Related Code Files

- Modify: `web/admin-panel/src/pages/enforcement/index.tsx` — page shell,
  `<DefaultModeControl>`, shared caps hook, error/loading states (Phase 7 refines).
- Create: `web/admin-panel/src/pages/enforcement/capability-catalog.tsx` — catalog
  table, effective-mode, toggles, unsupported alert, per_tier gap, filters/search.
- Reference: `web/admin-panel/src/components/mode-tag.tsx` (Phase 3),
  `web/admin-panel/src/providers/enforcement-provider.ts` (Phase 3),
  dashboard `useCustom` usage (`src/pages/dashboard/index.tsx:99`) as the pattern,
  cluster `useCustomMutation` usage (`src/pages/cluster/tokens.tsx:28`).
- i18n: extend `enforcement.*` keys (catalog labels, confirm text, unsupported
  warning, perTierGap) in `en/vi/zh`.

## Implementation Steps

1. Build `index.tsx` shell + `<DefaultModeControl>` (Segmented + confirm modal +
   apply-all dropdown + refresh + last-sync). Wire the shared caps hook.
2. Build `capability-catalog.tsx`: render features from `caps.data.features`
   (all 17), expandable policy rows, per-row `ModeTag` + mode select.
3. Implement `effective()` and the "overridden" tag.
4. Wire feature/policy toggle mutations with correct scopes; optimistic `active`
   apply + refetch.
5. Implement `unsupported[]` alert (dismissible, persistent until clean apply).
6. Add `per_tier` known-gap `⚠`/Tooltip; ensure it is rendered, not filtered out.
7. Add search (debounced) + quick-filter Segmented.
8. Verify against backend: toggle a feature, confirm only that feature's override
   changes in the next `capabilities` snapshot (siblings untouched).
9. `tsc --noEmit`; manual click-through.

## Success Criteria

- [ ] All 17 features + their policies render; counts/labels correct.
- [ ] Effective mode uses policy>feature>default; overridden rows tagged.
- [ ] Feature toggle uses `scope:"features"`; policy toggle uses `scope:"policies"`;
      backend snapshot confirms siblings unaffected.
- [ ] Default-mode change is confirmed and clears overrides (`scope:"all"`).
- [ ] `unsupported[]` surfaced after apply; persists until dismissed/clean apply;
      never rendered when empty.
- [ ] `per_tier` shown with known-gap warning, not hidden.
- [ ] Search + quick-filter work; `tsc --noEmit` clean.

## Risk Assessment

- **Optimistic/refetch race** double-toggling a row. Mitigated by disabling the
  row control while its mutation is pending and reconciling on refetch.
- **Override key format mismatch** (`feature.policy`) vs backend. Mitigated by
  mirroring the exact `${feat}.${pol}` key and the effective-mode test in Phase 7.
- **File bloat >200 LOC.** Mitigated by the index/catalog split; extract a
  `feature-row` helper if catalog still exceeds the budget.

Rollback: catalog is self-contained under `pages/enforcement/`; revert the two
files and the route still renders the Phase 3 placeholder.
