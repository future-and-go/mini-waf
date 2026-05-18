---
id: issue-03
title: "Top Attacker IPs Widget"
type: AFK
status: ready
parent_prd: plans/prds/260512-mini-waf-security-gateway.md
blocked_by: []
user_stories: [86]
created: 2026-05-12
tags: [dashboard, visualization]
---

# Issue 03: Top Attacker IPs Widget

## Parent

- PRD: `plans/prds/260512-mini-waf-security-gateway.md`

## What to build

Add a dashboard widget showing the top 10 attacker IPs ranked by blocked request count. Each row shows IP, country flag, block count, and last seen timestamp. Clicking an IP opens a detail view with that IP's full attack history.

This completes the second part of FR-030.

## Acceptance criteria

- [ ] Widget displays top 10 IPs by block count
- [ ] Each row shows: IP address, country flag (from GeoIP), block count, last seen
- [ ] Time range selector (1h, 24h, 7d) affects ranking
- [ ] Click IP → filtered view of that IP's blocked requests
- [ ] "Block IP" quick action button per row (adds to blacklist)
- [ ] Real-time updates via WebSocket

## Blocked by

None — can start immediately

## User stories covered

- PRD #86: As an operator, I want top attacker IPs list, so that I can identify persistent threats.

## Notes

- Backend endpoint: `/api/stats/attackers?limit=10&since={timestamp}`
- GeoIP country code already available from FR-041 GeoCheck
- Quick-block action calls existing `/api/access/blacklist` POST endpoint
