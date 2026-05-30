# Red-Team Review → §5 Observability Headers Plan

**Date:** 2026-05-30
**Plan:** `plans/260530-1819-s5-observability-headers/`
**Reviewers:** 2 hostile agents (correctness/egress + security/contract) + planner code verification
**Verdict:** Plan sound in design pattern; INCOMPLETE in egress coverage. 4 CRITICAL, 5 HIGH applied.

## Disposition Summary

| ID | Sev | Finding | Disposition |
|----|-----|---------|-------------|
| F1 | CRIT | `write_waf_body_decision` (body-inspect block path, proxy_waf_response.rs:204, called proxy.rs:759) emits 0 headers — uncovered | APPLIED → Phase 4 (signature takes `req_id`) |
| F2 | CRIT | Access-gate block (proxy.rs:662-672) runs pre-`inspect()`, no decision/meta, 0 headers | APPLIED → Phase 6 |
| F3 | CRIT | Cache poisoning: `begin_upstream_cache_capture` (proxy.rs:935) snapshots headers at END of `response_filter`; injected X-WAF-* get stored → stale replay to other clients on HIT | APPLIED → inject LAST + mandatory x-waf-* strip in capture. Resolves OQ2 |
| F4 | CRIT | FR-035 `header_filter` (proxy.rs:910-930) runs after response_chain; strips by name (operator `strip_prefixes`) or PII-value match (rule_id w/ RFC1918, etc.) | APPLIED → inject AFTER FR-035 (final step) + add `x-waf-` to `preserve_prefixes` default |
| F5 | HIGH | `fail_to_proxy`/fail-closed: `request_ctx` may be None → fresh UUID won't match audit log (§5↔§6 correlation) | APPLIED → Phase 6 + OQ (user decision) |
| F6 | HIGH | `access_bypass` fast-path (proxy.rs:677, `return Ok(false)` pre-inspect) → meta None on passthrough; plan comment "should not happen" is wrong | APPLIED → set meta on bypass + Phase 7 matrix |
| F7 | HIGH | Health 200 + HTTP→HTTPS redirect 301 (pre-inspect paths) uncovered | APPLIED → Phase 6 (+ health exception note) |
| F8 | HIGH | None-fallback hardcodes `mode=enforce` → lies on log_only deployments | APPLIED → derive mode from global default |
| F9 | HIGH | `write_cached_entry` hardcodes `action="allow"` on HIT → wrong for log_only-cached | APPLIED → read action from meta |
| F10 | MED | Challenge-cookie-valid → Ok(false) → upstream w/ `X-WAF-Action: challenge` (should be allow?) | APPLIED → clarify + OQ |
| F11 | MED | `risk_score: u8` can exceed 100 → contract 0-100 | APPLIED → clamp `min(100)` in injector + test |
| F12 | MED | rule_id CRLF strip → empty value violates `[A-Za-z0-9-]+\|none`; must become `none` | APPLIED → Phase 2 spec + test |
| F13 | MED | `WafDecisionMeta.action: &'static str` + `Default` = `""` → malformed header via `unwrap_or_default` | APPLIED → `Option`, never unwrap_or_default; default action="allow" |
| F14 | MED | §5.3 BYPASS on high-risk routes not mapped; rule_id alloc | APPLIED (note) → cache_status=Bypass when action!=allow; keep rule_id None in snapshot |
| F15 | LOW | rule_id may leak internal rule names in log_only (§5.2) | APPLIED → Phase 7 review item + OQ |
| F16 | LOW | Phase 1 TDD scaffold + Phase 7 E2E matrix omit unplanned egress classes (false-green) | APPLIED → both expanded to full egress inventory |

## Confirmed Code Facts (verified by planner)

- `engine.inspect()` (engine.rs:538) does NOT invoke the `Scorer`; every decision has `risk_score: 0` (engine.rs:693; `make_block_decision` engine.rs:750). The `Scorer`/`ScorerResult{action,score,is_new}` exists (risk/scorer.rs) but is not wired into the decision. **X-WAF-Risk-Score will be 0 and X-WAF-Rule-Id `none` for most requests unless the scorer is wired — this is real sub-scope, not a quick plumb.** (§3 RT-05 deferred it here.)
- `ErrorPageFactory::render` (error_page/error_page_factory.rs:22) returns `(ResponseHeader, Bytes)`; used by access-gate block, fail-closed 503, and `fail_to_proxy`. It has no ctx/req_id — inject at call sites.
- Egress paths total (11): header-block, body-block, challenge-page, challenge-passed→upstream, access-gate-block, fail-closed-503, health-200, redirect-301, access-bypass-passthrough, allow-upstream(MISS), cache-HIT, transport-error. Original plan covered ~5.

## Unresolved Questions (need user)

1. **Scorer wiring scope:** `inspect()` doesn't populate risk_score. Wire `Scorer` into the decision path now (bigger scope: needs RiskStore/config/RiskKey), or ship `X-WAF-Risk-Score: 0` v1 + follow-up? (affects benchmark scoring quality)
2. **Audit correlation on ctx-None error paths:** generate fallback UUID (won't be in audit log), write a minimal audit stub, or emit sentinel? Contract §5↔§6 wants correlation.
3. **Challenge-passed action:** report `allow` or `challenge` on the upstream 200 after a client solves the challenge?
4. **rule_id namespace:** are internal rule ids safe to expose (esp. log_only)? Need opaque ids if names encode detection logic.
