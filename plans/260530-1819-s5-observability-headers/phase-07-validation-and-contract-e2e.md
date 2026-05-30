---
phase: 7
title: "Validation + Contract E2E"
status: pending
priority: P1
effort: "3h"
dependencies: [1, 2, 3, 4, 5, 6]
---

# Phase 7: Validation + Contract E2E

## Overview
Integration gate over the FULL egress inventory (11 paths). Prove all 6 headers appear on every
response class, survive FR-035 + blocklist, never leak via cache, and pass the workspace quality bar.

## Requirements
- Functional: live responses for every egress class carry all 6 contract-exact headers.
- Non-functional: `cargo check/test/clippy/fmt` clean across the workspace.

## Architecture
E2E: start the binary against a test upstream, drive requests that produce each egress class, assert
with `curl -i` / the existing harness. Verify §5.3 consistency + §5↔§6 correlation.

## Related Code Files
- Modify: `docs/request-pipeline.md` (egress header-injection step + ordering invariant)
- Modify: `docs/system-architecture.md` or `docs/codebase-summary.md` (note `waf_observability_headers` module)
- Read for context: `tests/e2e-cluster.sh`, `analysis/docs/EN_waf_interop_contract_v2.3.md` §5

## Implementation Steps
1. **FR-035 + blocklist survival test:** the 6 `x-waf-*` headers are NOT removed by `header_blocklist`
   or the FR-035 `header_filter` (confirm `preserve_prefixes` contains `x-waf-`); not added to the
   default blocklist `["x-powered-by-waf","x-waf-version"]`.
2. **E2E egress matrix — assert all 6 headers + correct values for EACH:**
   header-block (403), body-block, challenge-page, challenge-passed→upstream, access-gate-block (403),
   fail-closed (503), health (200, or documented exception), HTTP-redirect (301),
   access-bypass passthrough, allow→upstream (MISS), cache HIT, transport error (504/503).
   For each assert: `X-WAF-Action` matches class; `X-WAF-Mode` matches policy; `X-WAF-Cache` correct;
   `X-WAF-Risk-Score` integer 0–100; `X-WAF-Rule-Id` `[A-Za-z0-9-]+`|`none`.
3. **Correlation:** `X-WAF-Request-Id` equals audit log `request_id` for that request (§5↔§6),
   INCLUDING ctx-None error paths (assert the minimal audit stub was written for the fallback id).
4. **Cache no-leak:** two distinct clients on the same cacheable GET get DIFFERENT `X-WAF-Request-Id`
   on the HIT (no stale replay); the stored entry has no `x-waf-*`.
5. **log_only run:** set a feature to log_only; response NOT enforced but `X-WAF-Action` reports the
   intended action and `X-WAF-Mode: log_only`.
6. **risk_score reality:** scorer is wired (Phase 3) — assert a scored scenario yields a NON-zero
   `X-WAF-Risk-Score` (and a matching `X-WAF-Rule-Id` from `dominant_contributor`), not just format.
7. `cargo fmt --all` then `--check`; `cargo clippy --workspace -- -D warnings`; `cargo test --workspace`.
8. Update docs.

## Success Criteria
- [ ] All 6 headers verified on EVERY egress class in step 2 (or documented exception for health)
- [ ] FR-035 + blocklist do not strip x-waf-*; cache stores no x-waf-*; HIT request-id is fresh
- [ ] log_only reports intended action + `X-WAF-Mode: log_only` without enforcing
- [ ] `X-WAF-Request-Id` correlates with audit log on ALL paths (ctx-None via audit stub)
- [ ] scored scenario yields NON-zero `X-WAF-Risk-Score` + matching `X-WAF-Rule-Id` (no false-green)
- [ ] `cargo fmt --all -- --check`, `cargo clippy --workspace -- -D warnings`, `cargo test --workspace` green
- [ ] docs updated

## Risk Assessment
- Risk: e2e env (postgres/upstream) → reuse `docker compose up -d postgres` + existing harness.
- Risk: timeout/circuit_breaker not producible live → cover at unit/factory level (Phase 6); note e2e-deferred.

## Security Considerations
- No X-WAF-* value echoes attacker-controlled input; all server-derived.
- Confirm cache no-leak (cross-request request-id/score isolation) and `BYPASS` on auth/sensitive routes.
- Review `rule_id` namespace for sensitive internal names before go-live (validate decision: expose as-is, audit here).
