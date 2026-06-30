# D1 — Dashboard: Detection Engines panel from live state

**G.1 row:** 15 · **Req IDs:** FR-030 (attack visualization), FR-031 (hot
config) · **Lane:** tiny (relabel) → normal (derive from real config)

> Companion: spec §D1. Follows [`ARCHITECTURE.md`](../../../ARCHITECTURE.md)
> and [`CONTEXT_RULES.md`](../../../CONTEXT_RULES.md).

---

## 1. Codebase audit (current state)

**Frontend** (`web/admin-panel/src/pages/dashboard/index.tsx`):
- `ENGINES` is a hardcoded array (lines 49-64): `libinjection, OWASP CRS, …,
  ModSecurity`, each `enabled: true`, rendered at lines 556-563.
- The dashboard already fetches live data: `GET /api/stats/overview`,
  `/api/stats/timeseries?hours=24`, `/api/rules/registry`
  (`{ enabled, disabled, rules[] }`), `/api/hosts`, `/api/panel-config`,
  `/api/stats/endpoints`, plus the `/ws/events` WebSocket.

**Backend reality:**
- No endpoint reports per-engine enabled state directly. The closest live
  signals are `/api/rules/registry` (rule sources + enabled counts) and
  `/api/panel-config` (feature toggles), plus `/api/enforcement/capabilities`
  (`{ ok, features, active }`).

## 2. Gap

The panel always shows every engine green regardless of actual config — a
cosmetic correctness issue (FR-030/031 imply the dashboard reflects real state).

## 3. Assumptions (explicit)

- A-1: The honest minimum is to **either** derive `enabled` from data already
  fetched (`/api/rules/registry` source presence + `/api/panel-config`) **or**
  relabel the panel as "Capabilities (static)". This plan recommends **derive
  from existing endpoints** (no new backend).
- A-2: A clean mapping `engine → registry source / panel-config flag` exists or
  can be defined; where no signal exists, the engine is labeled "static" rather
  than fabricated as enabled.
- A-3: No new backend endpoint is added in the recommended path.

## 4. Scope

**In scope:** compute each engine's `enabled` from `/api/rules/registry` +
`/api/panel-config`; where unknown, mark "reference/static".

**Out of scope:** a dedicated `/api/detection-engines` endpoint (possible future,
flagged); changing rule registry shape; engine internals.

## 5. Phased plan (independently testable & reversible)

### Phase 1 — Map engines to live signals (FE-only)
- Define a `engineEnabled(name, registry, panelConfig)` pure helper; replace the
  hardcoded `enabled:true` with its result; keep description text.
- For engines with no signal, render a neutral "static" tag instead of green.
- **Success:** disabling a rule source / toggle in config flips the matching
  engine indicator on next dashboard load; engines without signals show
  "static", not green.
- **Reversible:** one-file revert to the static array.

### Phase 2 (optional, normal) — backend `GET /api/detection-engines`
- If product wants authoritative per-engine state, add an endpoint deriving from
  the engine registry; FE consumes it.
- **Success:** endpoint returns `[{ name, enabled, source }]` matching engine
  config; integration test.

## 6. Edge cases & failure modes

- Registry/panel-config request fails → show "unknown" state, not green; don't
  block the rest of the dashboard.
- Unmapped engine name → default to "static" label.
- Partial data (registry loaded, panel-config not) → degrade gracefully.

## 7. Security

- Read-only, behind `require_auth`; no new mutation or surface in Phase 1.

## 8. Observability

- No new server logs (uses existing endpoints). Phase 2 adds a canonical log line.

## 9. Production-readiness gaps

- Without Phase 2, the "enabled" inference is heuristic (derived), not
  authoritative — document that the indicator approximates config state.

## 10. Harness intake

- **Lane:** tiny (Phase 1, FE display correctness) → normal (Phase 2 new
  endpoint). Record an intake row; Phase 2 needs a short story.
- **Validation:** FE manual proof (toggle a source → indicator changes);
  `pnpm build`.
