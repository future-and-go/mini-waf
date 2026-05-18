---
id: issue-01
title: "Circuit Breaker Gateway Wiring"
type: AFK
status: ready
parent_prd: plans/prds/260512-mini-waf-security-gateway.md
blocked_by: []
user_stories: [109]
created: 2026-05-12
tags: [resilience, gateway]
---

# Issue 01: Circuit Breaker Gateway Wiring

## Parent

- PRD: `plans/prds/260512-mini-waf-security-gateway.md`

## What to build

Wire the existing `circuit_breaker_threshold` and `circuit_breaker_reset_secs` config values to the gateway's upstream dispatch logic. When a backend becomes unresponsive (consecutive failures exceed threshold), the circuit opens and the WAF immediately returns 503 Service Unavailable instead of hanging on the failing upstream.

This completes FR-039 — the config exists, but the gateway doesn't act on it yet.

## Acceptance criteria

- [ ] Backend fails 5 consecutive requests (default threshold) → circuit opens
- [ ] While circuit is open, requests to that backend return 503 immediately (no upstream attempt)
- [ ] After reset period (default 30s), circuit half-opens and allows one probe request
- [ ] Probe succeeds → circuit closes, normal traffic resumes
- [ ] Probe fails → circuit stays open, reset timer restarts
- [ ] Metrics emitted: `circuit_breaker_state{backend}`, `circuit_breaker_trips_total`

## Blocked by

None — can start immediately

## User stories covered

- PRD #109: As an operator, I want circuit breaker for backend health, so that the WAF returns 503 instead of hanging.

## Notes

- Existing config in `waf-common/src/config.rs`: `circuit_breaker_threshold`, `circuit_breaker_reset_secs`
- Pattern reference: `BreakerStore` in DDoS module uses similar circuit breaker logic for Redis fallback
- Half-open state is critical — without it, recovery requires manual intervention or full timeout
