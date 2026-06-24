---
phase: 6
title: "X-WAF-Mode Correlation"
status: done
priority: P2
dependencies: [2, 3]
effort: "S"
---

# Phase 6: X-WAF-Mode Correlation (S5)

## Overview

Surface the persisted enforcement mode on the security-events surfaces so
operators can tell a real block (enforce) from a shadow block (log_only). Depends
on Phase 2 (the `waf_mode` field on events) and Phase 3 (`ModeTag`).

## Requirements

- Functional:
  - Event detail (`security-events/detail.tsx`): add a
    `Descriptions.Item label="Enforcement mode"` rendering `<ModeTag>` from the
    event's `waf_mode`. Place it next to the existing action field so it reads
    "Action: block · Mode: log_only".
  - Live feed / recent-events table (`dashboard/index.tsx` recent columns): add a
    compact "Mode" column using the same `<ModeTag>`; only show when value present;
    keep narrow.
- Non-functional: reuse the shared `<ModeTag>` (visual consistency with pill +
  catalog); strings i18n; do NOT infer mode client-side — read the field.

## Architecture

Phase 2 makes `waf_mode` part of the `security_events` API payload. The FE event
type gains the field and both surfaces render it via `ModeTag`. No new fetch — the
existing events/dashboard queries already return the rows; only the type and the
render change.

## Related Code Files

- Modify: `web/admin-panel/src/types/api.ts` — add `waf_mode?: InteropMode` to the
  security-event type used by detail + recent-events (keep optional for safety
  against pre-Phase-2 rows / mixed deploys).
- Modify: `web/admin-panel/src/pages/security-events/detail.tsx` — add the
  Enforcement-mode `Descriptions.Item` (Descriptions block ~lines 282–341).
- Modify: `web/admin-panel/src/pages/dashboard/index.tsx` — add a "Mode" column to
  the recent-events `ColumnsType` (~lines 263–314); conditional render when present.
- Reference: `web/admin-panel/src/components/mode-tag.tsx` (Phase 3).
- i18n: `enforcement.mode` / `security.enforcementMode` labels in `en/vi/zh`.

## Implementation Steps

1. Add `waf_mode?: InteropMode` to the FE security-event type.
2. Detail page: insert the Enforcement-mode item adjacent to action; render via
   `ModeTag`; handle absent value (don't render an empty tag).
3. Dashboard recent-events: add the narrow "Mode" column; render `ModeTag` only
   when `waf_mode` present.
4. Verify end-to-end against a backend with Phase 2 applied: a `log_only` decision
   shows `log_only` in both detail and feed.
5. `tsc --noEmit`; manual check.

## Success Criteria

- [x] Event detail shows Enforcement mode paired with action.
- [x] Recent-events feed shows a Mode column when value present; hidden/blank when
      absent. Backend `RecentEvent` extended to carry `waf_mode` so the feed
      populates (the recent-events query did not select it before).
- [x] Same `ModeTag` styling as the pill and catalog.
- [x] Value comes from the API `waf_mode` field (Phase 2), never client-inferred.
- [x] `tsc --noEmit` clean; labels i18n in all three locales.

## Risk Assessment

- **Hard dependency on Phase 2.** If Phase 2 is not yet deployed, rows lack
  `waf_mode`; the optional type + conditional render keep the UI correct (column
  simply hidden), so Phase 6 can ship ahead but only shows data post-Phase-2.
- **Detail layout crowding.** Mitigated by reusing the existing `Descriptions`
  column responsiveness; no new layout.

Rollback: revert the type field + two render additions; surfaces fall back to
prior behavior.
