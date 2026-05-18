---
id: issue-06
title: "IP Reputation Runtime Refresh"
type: AFK
status: ready
parent_prd: plans/prds/260512-mini-waf-security-gateway.md
blocked_by: []
user_stories: [118, 119]
created: 2026-05-12
tags: [security, reputation]
---

# Issue 06: IP Reputation Runtime Refresh

## Parent

- PRD: `plans/prds/260512-mini-waf-security-gateway.md`

## What to build

Add periodic runtime refresh for IP reputation feeds (Tor exit list, bad ASN list). Currently these lists are loaded at startup only. This issue adds a background task that fetches updated lists on a configurable interval, performs atomic swap to avoid blocking request processing, and logs warnings on fetch failures.

This completes FR-042 (IP Reputation Feed — runtime refresh).

## Acceptance criteria

- [ ] Configurable refresh interval (default: 1 hour)
- [ ] Background tokio task fetches Tor exit list from configured URL
- [ ] Background tokio task fetches bad ASN list from configured URL
- [ ] Atomic swap via `ArcSwap` — no blocking during update
- [ ] Fetch failure → log warning, retain previous list, retry on next interval
- [ ] Metrics: `ip_reputation_refresh_total`, `ip_reputation_refresh_errors_total`, `ip_reputation_list_size`
- [ ] Manual refresh via CLI: `prx-waf reputation refresh`

## Blocked by

None — can start immediately

## User stories covered

- PRD #118: As an operator, I want periodic refresh, so that lists stay current.
- PRD #119: As a security engineer, I want auto risk boost for reputation-flagged IPs, so that known bad actors are scrutinized.

## Notes

- Existing loader: `waf-engine/src/relay/intel/` has startup loading logic
- Tor exit list URL: `https://check.torproject.org/torbulkexitlist`
- Bad ASN sources: Spamhaus ASN-DROP, or custom file
- Pattern reference: `GeoIP` updater in `waf-engine/src/checks/geo/` has similar scheduled refresh
