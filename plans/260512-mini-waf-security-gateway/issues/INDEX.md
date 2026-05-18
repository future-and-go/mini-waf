# Issues Index — Mini WAF Security Gateway

**Parent PRD:** `plans/prds/260512-mini-waf-security-gateway.md`  
**Created:** 2026-05-12  
**Total Issues:** 6  
**Estimated Effort:** ~4.5 days

---

## Dependency Graph

```
issue-01 (Circuit Breaker)     ─┐
issue-02 (Attack Chart)        ─┼─► issue-04 (Endpoint Heatmap)
issue-03 (Top Attackers)       ─┘
issue-05 (VPN Bypass)
issue-06 (IP Reputation)
```

**Parallelizable:** 01, 02, 03, 05, 06 can start immediately  
**Blocked:** 04 waits for 02

---

## Issue Summary

| # | Title | Type | Status | Blocked By | Effort | FR |
|---|-------|------|--------|------------|--------|-----|
| 01 | [Circuit Breaker Gateway Wiring](issue-01-circuit-breaker-gateway-wiring.md) | AFK | ready | — | 0.5d | FR-039 |
| 02 | [Attack Type Distribution Chart](issue-02-attack-type-distribution-chart.md) | AFK | ready | — | 1d | FR-030 |
| 03 | [Top Attacker IPs Widget](issue-03-top-attacker-ips-widget.md) | AFK | ready | — | 0.5d | FR-030 |
| 04 | [Endpoint Heatmap](issue-04-endpoint-heatmap.md) | AFK | ready | 02 | 1d | FR-030 |
| 05 | [VPN Geo Bypass Detection](issue-05-vpn-geo-bypass-detection.md) | AFK | ready | — | 1d | FR-041 |
| 06 | [IP Reputation Runtime Refresh](issue-06-ip-reputation-runtime-refresh.md) | AFK | ready | — | 0.5d | FR-042 |

---

## By Priority

### P0 Completion (0.5 days)
- **issue-01** — Circuit breaker wiring (last P0 gap)

### Dashboard FR-030 (2.5 days)
- **issue-02** — Attack type distribution chart
- **issue-03** — Top attacker IPs widget
- **issue-04** — Endpoint heatmap (blocked by 02)

### P1 Partial Completion (1.5 days)
- **issue-05** — VPN geo bypass detection (FR-041)
- **issue-06** — IP reputation runtime refresh (FR-042)

---

## Deferred (Phase 2)

| FR | Title | Reason |
|----|-------|--------|
| FR-043 | Multi-region Deploy CLI | Heavy (~2d), not needed for Attack Battle |
| FR-044 | Zero-downtime Config Sync | Depends on FR-043 |
| FR-045 | Auto Scaling State Sharing | Depends on FR-044 |

---

## Quick Start

```bash
# Pick an unblocked issue
open plans/260512-mini-waf-security-gateway/issues/issue-01-circuit-breaker-gateway-wiring.md

# Or hand off to /cook
/cook @plans/260512-mini-waf-security-gateway/issues/issue-01-circuit-breaker-gateway-wiring.md
```
