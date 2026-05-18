---
id: issue-05
title: "VPN Geo Bypass Detection"
type: AFK
status: ready
parent_prd: plans/prds/260512-mini-waf-security-gateway.md
blocked_by: []
user_stories: [115]
created: 2026-05-12
tags: [security, geoip]
---

# Issue 05: VPN Geo Bypass Detection

## Parent

- PRD: `plans/prds/260512-mini-waf-security-gateway.md`

## What to build

Detect when a user appears to be using a VPN to bypass geographic restrictions. Compare the client's GeoIP country against known VPN/proxy provider IP ranges. When a mismatch is detected (e.g., IP geolocates to allowed country but belongs to VPN provider), emit a `geo_vpn_bypass` signal to the Risk Aggregator.

This completes FR-041 (Geographic Restriction — VPN bypass detection).

## Acceptance criteria

- [ ] Load VPN provider IP ranges from configurable file at startup
- [ ] On each request, check if client IP belongs to known VPN range
- [ ] If VPN detected AND country is in restricted list → emit signal
- [ ] Signal increments risk score by configurable delta (default +20)
- [ ] Audit log includes `vpn_detected: true/false` field
- [ ] Hot-reload VPN list without restart

## Blocked by

None — can start immediately

## User stories covered

- PRD #115: As a security engineer, I want VPN geo bypass detection, so that evasion is flagged.

## Notes

- VPN provider lists available from: IPQualityScore, IP2Proxy, or community lists
- Consider ASN-based detection as fallback (hosting provider ASNs)
- Don't block outright — just signal. Decision is up to Risk Aggregator thresholds.
- Related: FR-007 Relay Intel already classifies datacenter vs residential ASN
