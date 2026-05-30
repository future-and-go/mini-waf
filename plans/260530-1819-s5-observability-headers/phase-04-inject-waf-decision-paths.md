---
phase: 4
title: "Inject on WAF-Decision Paths"
status: pending
priority: P1
effort: "3h"
dependencies: [2, 3]
---

# Phase 4: Inject on WAF-Decision Paths

## Overview
Inject the 6 headers on every response the WAF itself writes after `inspect()`: header-inspect
block/rate_limit/timeout/circuit_breaker/**redirect** (`write_waf_decision`), challenge page
(`handle_challenge`), and **body-inspect** block/rate_limit/timeout/redirect
(`write_waf_body_decision` — red-team F1). Makes Phase 1 path tests pass.

## Requirements
- Functional: every WAF-authored response carries all 6 headers; values from the decision; `cache = Bypass`.
- Non-functional: read `req_id` into a local `&str` before mutably borrowing the header.

## Architecture
`write_waf_decision` (proxy_waf_response.rs:30) builds `ResponseHeader::build(status, None)` per arm.
Inject AFTER build, BEFORE `session.write_response_header`, for Block/RateLimit/CircuitBreaker/Timeout
AND the **Redirect** arm (302; action maps to `allow` via `as_contract_str` but still emits 6 headers).

`handle_challenge` (proxy_waf_response.rs:109): inject on the challenge-page response
(`action="challenge"`, `mode` from decision, `cache=Bypass`). The valid-cookie branch returns
`Ok(false)` → request proxied upstream; **the snapshot action MUST be set to `allow` for that
passthrough** (validate decision: challenge-passed reports `allow`). Since `handle_challenge` has no
ctx access, signal the pass either by overwriting `ctx.waf_decision_meta` to `allow` at the call
site in `request_filter` when `write_waf_decision` returns `Ok(false)` for a Challenge decision, or
by having the cookie-valid path return a distinct signal. Simplest: in `request_filter`, after a
Challenge decision passes through (write_waf_decision → false), set `ctx.waf_decision_meta.action = "allow"`.

`write_waf_body_decision` (proxy_waf_response.rs:204): SEPARATE egress path called from
`request_body_filter` (proxy.rs:759). It does NOT currently receive `req_id`/ctx. **Change its
signature** to also accept `req_id: &str` (already have `request_ctx` — use `request_ctx.req_id`),
build `WafHeaderValues` per arm, inject before `write_response_header`. Update the call site and tests.

log_only nuance (contract §5): non-enforcing decisions (`is_enforcement_allowed()` true) return
`false`/`Ok(())` here and pass through — DO NOT inject `allow` on these paths; the passthrough
(Phase 5) injects using the snapshot, which carries the INTENDED action (`as_contract_str` maps
`Block`→`block` regardless of mode) with `mode=log_only`.

## Related Code Files
- Modify: `crates/gateway/src/proxy_waf_response.rs` (`write_waf_decision`, `handle_challenge`, `write_waf_body_decision`)
- Modify: `crates/gateway/src/proxy.rs` (`write_waf_body_decision` call site at line 759 — pass req_id)
- Read for context: `crates/gateway/tests/proxy_waf_response_writer.rs`

## Implementation Steps
1. `write_waf_decision`: inject in Block/RateLimit/CircuitBreaker/Timeout/**Redirect** arms (`cache=Bypass`).
2. `handle_challenge`: inject on challenge-page response (`action="challenge"`).
3. `write_waf_body_decision`: add `req_id: &str` param; inject in all enforcing arms; update call site.
4. Leave non-enforcing (LogOnly/Allow) early-returns WITHOUT injection here (passthrough owns it).
5. Run extended `proxy_waf_response_writer.rs` tests → green.

## Success Criteria
- [ ] block/rate_limit/timeout/circuit_breaker/redirect (header AND body paths) carry all 6 headers
- [ ] challenge page carries all 6, `X-WAF-Action: challenge`
- [ ] non-enforcing paths inject nothing here (verified — no premature `allow`)
- [ ] `cargo test -p gateway` green; clippy clean

## Risk Assessment
- Risk: `write_waf_body_decision` signature change ripples to its test call sites → update all (grep).
- Risk: borrow conflict (`request_ctx.req_id` vs `&mut header`) → bind `let rid = request_ctx.req_id.as_str();` first.

## Security Considerations
- Blocked/challenge responses must carry `X-WAF-Request-Id` for audit correlation (§5↔§6).
- These paths bypass FR-035, so the injector's own CRLF sanitization is the only guard (Phase 2).
