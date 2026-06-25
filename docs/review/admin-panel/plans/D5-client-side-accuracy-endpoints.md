# D5 — Server-side accuracy endpoints (replace client-side approximations)

**G.1 rows:** 20, 21, 22 (+ spec §D "client-side approximations") ·
**Req IDs:** FR-003 (rule engine), FR-021/022, FR-030, FR-025, FR-027, FR-034 ·
**Lane:** normal

> Companion: spec §D "Client-side approximations". Three independent,
> optional accuracy upgrades. Each is its own sub-plan and can ship alone.
> Follows [`ARCHITECTURE.md`](../../../ARCHITECTURE.md) (query side, parse-first)
> and [`CONTEXT_RULES.md`](../../../CONTEXT_RULES.md).

---

## 1. Codebase audit (current state)

- **Create-Rule-from-Event preview** (`security-events/CreateRuleFromEventModal.tsx`):
  `matchesRule` (lines 117-133) is a **browser-side simulation** (IP + method +
  path exact/`starts_with`) over events fetched via
  `GET /api/security-events?...&page_size=1000`. No `/api/custom-rules/test`
  endpoint exists.
- **Rule Analytics "Top Blocked URIs"** (`rule-analytics/index.tsx:271-285`):
  client-side grouping of **only the first 100** events from
  `GET /api/security-events?action=block&page=1&page_size=100`. The real
  aggregation endpoint `GET /api/stats/endpoints` exists
  (`stats.rs:211-214`, `EndpointsQuery { host_code?, action?, hours? }`) but is
  **used on the Dashboard, not here**, and doesn't group by URI for blocked-only.
- **Risk Scoring distribution chart** (`risk-scoring/index.tsx:88-98`):
  client-side 10-bin histogram over **the current page** of
  `GET /api/risk/actors?limit=50`. `GET /api/risk/metrics` returns
  `{ actor_count, avg_score, p95_score, scored_last_hour, blocked_last_hour,
  challenged_last_hour }` — **no `distribution` field**.

## 2. Gap

Each chart/count is approximate because aggregation happens client-side over a
bounded sample, so totals under-count and previews don't match engine semantics.

## 3. Assumptions (explicit)

- A-1: These are **accuracy enhancements**, not correctness bugs — the pages
  work; the numbers are approximate. They are independently optional.
- A-2: Server-side aggregation reuses existing DB query paths (`HeatmapFilter`,
  risk store) — no new tables.
- A-3: `/api/custom-rules/test` must reuse the **real engine evaluation** path,
  not re-implement matching, to be meaningfully better than the JS sim. Confirm
  a reusable evaluation entrypoint exists before committing (think-before-coding).

## 4. Scope

**In scope:** three endpoints (rule dry-run; blocked-URI aggregation; risk
histogram) + the FE swaps to consume them.

**Out of scope:** the optional regex test boxes for Bot/Sensitive/Custom rules
(noted in spec §D table) unless requested; new analytics beyond these three;
changing event retention.

## 5. Phased plan (each sub-item independently testable & reversible)

### Sub-plan A — `POST /api/custom-rules/test` (dry-run)
- Accept a candidate rule + a lookback window; evaluate it against recent events
  using the engine's rule-evaluation core; return `{ match_count, sample[] }`.
- FE: replace `matchesRule` usage with this call; keep the modal UX.
- **Success:** for a known rule + seeded events, server `match_count` equals an
  independently computed expected count and differs from (is more accurate than)
  the old JS sim; integration test.
- **Reversible:** endpoint additive; FE can fall back to the JS sim.

### Sub-plan B — `GET /api/stats/endpoints?action=block` grouped by URI
- Extend `stats_endpoints` to support URI grouping for blocked-only (it already
  takes `action` + `hours`); return top URIs with full counts.
- FE Rule-Analytics: replace the 100-event client grouping with this call.
- **Success:** "Top Blocked URIs" totals match a DB count over the full window
  (not capped at 100); integration test; old client grouping removed (`rg`).
- **Reversible:** new query mode is additive; FE revertible.

### Sub-plan C — `distribution` on `GET /api/risk/metrics`
- Add a server-computed 10-bin histogram (`distribution: [{ range, count }]`)
  over all scored actors.
- FE Risk-Scoring: render `metrics.distribution` instead of binning the current
  page.
- **Success:** the histogram reflects all actors (not just the 50 on screen);
  integration test asserts bin sums equal `actor_count`.
- **Reversible:** new field is additive/optional; FE falls back to client bins.

## 6. Edge cases & failure modes

- A: candidate rule with invalid regex/condition → 400 (compile at boundary),
  never run a broken rule against the store.
- A: huge lookback → cap window + sample size; document limits.
- B: no blocked events → empty list, not error; respect `hours` bounds.
- C: zero actors → all-zero bins, `actor_count=0`; avoid div-by-zero on averages.
- All: large result sets → cap returned `sample`/top-N; return counts, not full
  dumps.

## 7. Security

- All behind `require_auth`. Dry-run must be **read-only** (no rule persisted,
  no state mutated) — it's a query, not a command (ARCHITECTURE command/query).
- Parse candidate rules at the boundary into typed DTOs; reject malformed input
  before evaluation.
- Don't leak full event payloads beyond what the events API already exposes.

## 8. Observability

- Canonical per-request JSON log per endpoint (`action="custom-rules.test"` etc.).
- Dry-run is read-only → no audit record; B/C are reads → no audit.

## 9. Production-readiness gaps

- Client-side approximations silently under-count at scale; until these land,
  document that the affected widgets are sample-based estimates.
- Heavy aggregation on large event tables needs appropriate indexes — verify
  query plans before shipping B at production data volumes.

## 10. Harness intake

- **Lane:** normal (new query contracts; reuse existing data paths). Each
  sub-plan is its own story-sized slice.
- **Story:** `docs/stories/epics/` under the cited FRs; from
  `docs/templates/story.md`. Resolve A-3 (engine eval entrypoint) in design notes.
- **Validation:** integration tests asserting server aggregates match
  independently-computed expected values; FE manual. `harness-cli story update`.
