---
id: issue-02
title: "Attack Type Distribution Chart"
type: AFK
status: ready
parent_prd: plans/prds/260512-mini-waf-security-gateway.md
blocked_by: []
user_stories: [85]
created: 2026-05-12
tags: [dashboard, visualization]
---

# Issue 02: Attack Type Distribution Chart

## Parent

- PRD: `plans/prds/260512-mini-waf-security-gateway.md`

## What to build

Add a pie/donut chart to the Vue 3 admin dashboard showing the distribution of blocked attacks by type (SQLi, XSS, DDoS, path traversal, SSRF, brute force, scanner, etc.). The chart aggregates data from the existing audit log or stats API.

This completes the first part of FR-030 (attack visualization).

## Acceptance criteria

- [ ] Dashboard displays a pie/donut chart of attack types
- [ ] Chart shows percentage breakdown (e.g., "SQLi 34%, XSS 22%, DDoS 18%...")
- [ ] Time range selector (1h, 24h, 7d, 30d)
- [ ] Clicking a segment filters the live feed to that attack type
- [ ] Empty state handled gracefully ("No attacks detected in this period")
- [ ] Chart updates on WebSocket push (live mode) or polling (historical mode)

## Blocked by

None — can start immediately

## User stories covered

- PRD #85: As an operator, I want attack type distribution chart, so that I can see which attacks are most common.

## Notes

- Consider using Chart.js or Apache ECharts (already in Vue ecosystem)
- Backend endpoint: `/api/stats/attacks?group_by=type&since={timestamp}`
- Attack type taxonomy should match rule IDs: SQLI-*, XSS-*, DDOS-*, PATH-*, SSRF-*, BF-*, SCAN-*
