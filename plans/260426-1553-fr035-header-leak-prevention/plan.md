---
name: FR-035 Header Leak Prevention
description: Wire response-header leak prevention into Pingora pipeline; config-driven activation, code-driven detection cases.
status: completed
created: 2026-04-26
completed: 2026-04-26
pr: https://github.com/future-and-go/mini-waf/pull/14
type: implementation
scope: FR-035 only (FR-033/FR-034 deferred to separate plans)
blockedBy: []
blocks: []
---

# FR-035 — Header Leak Prevention

## Summary

Implement **FR-035** from the hackathon requirements: detect and strip response headers that leak server fingerprint, debug/internal info, error details, or PII to downstream clients. Detection cases live in code; activation toggles live in `configs/default.toml`.

**Source:** `analysis/requirements.md` line 75 — *"Detect and block PII leaks in response headers (X-Debug, X-Internal-*)"*.
**Gap:** flagged MISSING in `plans/reports/pm-260421-1031-requirements-gap-analysis.md` line 75.

## Current State

Untracked (WIP) skeleton present in `crates/waf-engine/src/outbound/`:

| File | State |
|------|-------|
| `outbound/mod.rs` | references missing `OutboundConfig` — does not compile |
| `outbound/header_filter.rs` | usable; references missing `HeaderFilterConfig` |
| `outbound/body_redactor.rs` | **out of scope (FR-034)** — remove |
| `outbound/response_filter.rs` | **out of scope (FR-033)** — remove |

Module not registered in `waf-engine/src/lib.rs`. Pingora `response_filter` hook not implemented in `gateway/src/proxy.rs`.

## Approach

Surgical: keep the existing `header_filter.rs` (it already encodes the "code = detection cases, config = activation" principle). Remove FR-033/FR-034 files (they belong to separate plans). Add config types, register module, wire one Pingora hook.

## Phases

| # | Phase | File | Status |
|---|-------|------|--------|
| 01 | Config & engine module | [phase-01-config-and-engine.md](./phase-01-config-and-engine.md) | completed |
| 02 | Gateway response-filter wiring | [phase-02-gateway-wiring.md](./phase-02-gateway-wiring.md) | completed |
| 03 | Tests, default config, docs | [phase-03-tests-and-docs.md](./phase-03-tests-and-docs.md) | completed |
| 04 | Build, branch, commit, push, PR | [phase-04-ship.md](./phase-04-ship.md) | completed |

## Key Decisions

1. **Scope = FR-035 only.** Body redaction (FR-034) and response content filtering (FR-033) are deferred. Their WIP files get deleted; replan separately.
2. **Detection in code, activation in config** — detection cases are hard-coded in `waf-engine`; the TOML decides which categories are active at runtime. Operator-supplied lists extend the built-ins. `HeaderFilter` already follows this contract; preserve.
3. **Pingora hook = `response_filter`** (synchronous header mutation). No `response_body_filter` in this plan (body work = separate FRs).
4. **Disabled by default** to preserve existing behavior. Operators opt in via TOML.
5. **Preserve security headers.** Never strip HSTS / CSP / X-Frame-Options / Content-Type / etc. — see `phase-01` strip-list contract.
6. **Hop-by-hop headers** (RFC 9110 §7.6.1) untouched — Pingora handles those.

## Research

- Reference: [research/researcher-01-header-leak-prevention.md](./research/researcher-01-header-leak-prevention.md)
- Standards: OWASP ASVS V14.4, CWE-200, CWE-209, RFC 9110, NIST SP 800-53 SI-11
- Reference impls: ModSecurity, Nginx headers-more, Caddy, Envoy, Coraza

## Success Criteria

- `cargo build --release` passes; `cargo clippy --workspace --all-targets --all-features -- -D warnings` clean
- `cargo test -p waf-engine outbound::` all green
- E2E: with `[outbound.headers] enabled = true`, a synthetic upstream response containing `Server: nginx`, `X-Debug-Token: abc`, `X-Internal-Path: /admin` returns to client with those headers stripped; `Content-Type` preserved
- E2E with `enabled = false`: no behavior change
- Performance budget: p99 added latency < 0.5 ms on 10-header response (allowlist O(1) lookup)
- New branch pushed to `origin`, PR opened against `main`

## Risk

| Risk | Mitigation |
|------|-----------|
| Stripping a header the client needs (e.g. `Content-Type`) | Hard allowlist of preserved headers; explicit unit test |
| ReDoS on PII regex | Patterns bounded; only run when `detect_pii_in_values = true` |
| Performance regression | O(1) HashSet for exact match; prefix scan only on `x-` headers |
| Breaks Pingora cache layer | `response_filter` runs after cache-store decision in Pingora; document |

## Out of Scope

- FR-033 response body content filtering (stack traces, API keys in body)
- FR-034 sensitive field redaction in JSON bodies
- Outbound rule DSL / per-route policies
- Cluster sync of outbound config
