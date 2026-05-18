---
id: issue-04
title: "Endpoint Heatmap"
type: AFK
status: ready
parent_prd: plans/prds/260512-mini-waf-security-gateway.md
blocked_by: [issue-02]
user_stories: [87]
created: 2026-05-12
tags: [dashboard, visualization]
---

# Issue 04: Endpoint Heatmap

## Parent

- PRD: `plans/prds/260512-mini-waf-security-gateway.md`

## What to build

Add an endpoint heatmap to the dashboard showing which routes are most frequently targeted. The heatmap uses color intensity to indicate request volume, with separate color scales for allowed (green) vs blocked (red) traffic. Operators can quickly identify which endpoints are under attack.

This completes the third part of FR-030.

## Acceptance criteria

- [ ] Heatmap displays route paths as rows (grouped by tier)
- [ ] Color intensity indicates request volume (darker = more requests)
- [ ] Two-color scheme: green gradient for allowed, red gradient for blocked
- [ ] Hovering shows exact counts and percentage
- [ ] Time range selector (1h, 24h, 7d)
- [ ] Click row → filtered live feed for that endpoint
- [ ] Routes with zero traffic are dimmed/hidden

## Blocked by

- `issue-02` — shares charting infrastructure and stats API patterns

## User stories covered

- PRD #87: As an operator, I want endpoint heatmap, so that I can see which routes are targeted.

## Notes

- Group by tier (Critical, High, Medium, CatchAll) for quick triage
- Consider treemap as alternative visualization if route count is high
- Backend endpoint: `/api/stats/endpoints?since={timestamp}`
