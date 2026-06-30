# D3 — Settings: Threat Intel feeds API

**G.1 row:** 17 · **Req IDs:** FR-042 (IP reputation feed: Tor + bad ASN,
periodic refresh), FR-008 (threat-intel blacklist) · **Lane:** normal

> Companion: spec §D3. Follows [`ARCHITECTURE.md`](../../../ARCHITECTURE.md)
> (parse-first, query side, observability) and
> [`CONTEXT_RULES.md`](../../../CONTEXT_RULES.md).

---

## 1. Codebase audit (current state)

**Frontend** (`web/admin-panel/src/pages/settings/index.tsx`):
- The Threat-Intel "feeds" table (`feedRows`, lines 203-219) is **synthesized**
  from `GET /api/rules/registry` by grouping `rule.source` → `{ name, count,
  enabled }`. It is **not** a feeds API.
- `GET /api/threat-intel/status` returns `ReputationStatus { tor_count?,
  asn_count? }` (lines 187-192, 821-844).
- "Refresh feeds" button calls `POST /api/rules/reload` (lines 235-242).
- Fallback text when empty/errored: "No live API available. Check startup logs"
  (lines 864-869).

**Backend reality:**
- Only `GET /api/threat-intel/status` exists (`stats.rs`, stub-ish). No feed
  list/refresh metadata endpoint. FR-042 feeds (Tor exit list + bad ASN) are
  loaded at startup from files (`configs/seed/tor-exits.example.txt`,
  `configs/seed/asn-classes.example.csv`) and refreshed periodically; the loader
  owns the real `last_refresh`/`count`/`source` per feed.

## 2. Gap

There is no authoritative `GET /api/threat-intel/feeds` returning per-feed
name/source/last-refresh/count, so the GUI fakes a table from rule sources and
shows a "no live API" fallback.

## 3. Assumptions (explicit)

- A-1: The reputation/feed subsystem holds (or can expose) per-feed metadata:
  `name, source (path/url), last_refresh_ms, entry_count, enabled`. **Confirm the
  exact loader location before coding** (likely the reputation/community-reporter
  subsystem; the API audit found `community_reporter`/`crowdsec` fields on
  `AppState` but not a feed-metadata accessor) — this is a "think before coding"
  checkpoint.
- A-2: If per-feed metadata is not yet tracked, scope shrinks to exposing what
  `threat_intel_status` already has (`tor_count`, `asn_count`, last refresh) as a
  proper typed feeds list, and add metadata tracking as a follow-up.
- A-3: Refresh remains the existing mechanism (startup + periodic); the GUI's
  "refresh" may either trigger a manual reload (if supported) or be relabeled.

## 4. Scope

**In scope:** add `GET /api/threat-intel/feeds` returning a typed list; replace
the synthesized FE table with it; remove the "no live API" fallback.

**Out of scope:** implementing new feed sources; changing the refresh cadence;
adding feed-source CRUD (add/remove feeds) unless product asks; CrowdSec feeds
(separate pages exist).

## 5. Phased plan (independently testable & reversible)

### Phase 1 — Backend feeds accessor (engine/reputation)
- Locate/extend the reputation subsystem to expose `feeds() -> Vec<FeedMeta>`
  (`name, source, last_refresh_ms, entry_count, enabled`). If only counts exist
  today (A-2), surface those first.
- **Success:** a unit test asserts the accessor reflects the loaded feeds (seed
  files) with correct counts.
- **Reversible:** additive accessor; no behavior change.

### Phase 2 — `GET /api/threat-intel/feeds`
- New handler (extend `stats.rs` threat-intel section) reading the accessor via
  `AppState`; route before `server.rs:313`.
- **Success:** endpoint returns the real feeds with non-zero counts when seeds
  are present; empty list (not 500) when none loaded; integration test.
- **Reversible:** remove handler + route.

### Phase 3 — FE consumes the real API
- Replace `feedRows` synthesis with `useCustom("/api/threat-intel/feeds")`;
  remove the "no live API available" fallback; keep the refresh button mapped to
  the supported reload action (or relabel).
- **Success:** the feeds table shows real `name/source/last-refresh/count`; no
  synthesis from `/api/rules/registry` remains (`rg` the page).
- **Reversible:** one-file revert.

## 6. Edge cases & failure modes

- No feeds configured → empty table with a clear "no feeds configured" state
  (distinct from "API missing").
- Stale `last_refresh` (refresh failing) → surface the age; don't hide failures.
- Very large feeds (counts only, never dump entries) → return metadata, not the
  IP/ASN lists.
- Endpoint error → table shows an error state, not a fabricated list.

## 7. Security

- Behind `require_auth`. Return **metadata only** — never the raw reputation
  lists (could leak detection coverage); cap any string fields.
- Parse feed file contents at the loader boundary (parse-first); a malformed feed
  file must fail-soft (skip the feed, log) and never crash startup.

## 8. Observability

- Canonical per-request JSON log on the new endpoint.
- Feed loader should already log refresh outcomes; ensure `last_refresh_ms` and
  success/failure are observable (operational logs, not audit).

## 9. Production-readiness gaps

- Periodic refresh health (last success, failure streaks) is what operators need;
  if only counts exist today, this plan delivers visibility but not alerting —
  flag alerting as out of scope.
- Feed provenance/integrity (signed feeds) is not addressed.

## 10. Harness intake

- **Lane:** normal (new public contract + threat-intel/security data → stronger
  validation; metadata-only keeps it below high-risk).
- **Story:** `docs/stories/epics/` under FR-042; from `docs/templates/story.md`.
  Resolve A-1 (loader location) in design notes.
- **Validation:** unit (accessor), integration (endpoint with seed files), FE
  manual. Record with `harness-cli story update`.
