# D2 — Enforcement Plane Map: drive from capabilities

**G.1 row:** 16 · **Req IDs:** E14-enforcement-modes, E10 (US-1003
capabilities) · **Lane:** tiny

> Companion: spec §D2. Follows [`ARCHITECTURE.md`](../../../ARCHITECTURE.md)
> and [`CONTEXT_RULES.md`](../../../CONTEXT_RULES.md).

---

## 1. Codebase audit (current state)

**Frontend** (`web/admin-panel/src/pages/enforcement/plane-map.tsx`):
- Renders `dataSource={GOVERNANCE_MAP}` (line 64), a static 17-row table from
  `utils/governance-map.ts` (e.g. `{ feature, config, adminPath }`).
- The **Control Plane** column is hardcoded `yes` for every row
  (`plane-map.tsx:52-56`).
- The plane map does **not** call `/api/enforcement/capabilities`.

**Backend reality:**
- `GET /api/enforcement/capabilities` exists (`enforcement.rs:30`), returning
  `CapabilitiesResponse { ok, features, active }` (`types/api.ts:386-390`). It is
  already consumed by the parent enforcement page
  (`use-enforcement-capabilities.ts`), `DefaultModeControl`, `CapabilityCatalog`,
  `RuntimeOperations` — but not by `PlaneMap`.

## 2. Gap

The plane map presents a static governance table with an always-green control
plane as if it were live runtime state.

## 3. Assumptions (explicit)

- A-1: The capabilities response can be joined to `GOVERNANCE_MAP` rows by
  `feature` key (verify the feature naming matches; if not, add a small mapping).
- A-2: The honest minimum is **either** drive the control-plane / data-plane
  cells from `capabilities.features/active` **or** clearly mark the table
  "reference". This plan recommends **drive from capabilities** (data already
  fetched by the parent page; reuse the hook).
- A-3: No backend change is needed.

## 4. Scope

**In scope:** consume `useEnforcementCapabilities()` in `plane-map.tsx`; replace
the hardcoded control-plane `yes` with the real per-feature state; fall back to a
"reference" tag for features absent from the capabilities response.

**Out of scope:** new endpoints; changing the capabilities contract; the
`GOVERNANCE_MAP` static metadata (feature names, admin paths stay).

## 5. Phased plan (independently testable & reversible)

### Phase 1 — Join capabilities into the table (FE-only)
- Use the existing hook; compute each row's control-plane/data-plane state from
  `capabilities`; render a neutral "reference" marker where a feature has no
  capability entry instead of green.
- **Success:** a feature reported inactive by `/api/enforcement/capabilities`
  shows non-green; features missing from the response show "reference"; no row is
  unconditionally green.
- **Reversible:** one-file revert to static `GOVERNANCE_MAP` rendering.

## 6. Edge cases & failure modes

- Capabilities request fails/loading → show a skeleton/"unknown", not green.
- Feature key mismatch between map and API → mark "reference" (don't guess green).
- Empty `features` → entire table renders as "reference".

## 7. Security

- Read-only, behind `require_auth`. No new surface.

## 8. Observability

- None new (reuses an existing endpoint/hook).

## 9. Production-readiness gaps

- Accuracy depends on `GOVERNANCE_MAP` feature keys staying in sync with the
  capabilities contract; document this coupling so the static map doesn't rot.

## 10. Harness intake

- **Lane:** tiny (FE display correctness). Record an intake row.
- **Validation:** FE manual proof (toggle a capability / inspect a known-inactive
  feature → cell reflects it); `pnpm build`.
