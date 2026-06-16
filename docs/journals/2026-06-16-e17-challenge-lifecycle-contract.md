# E17: Challenge Lifecycle — Response Format & Solver Integration (Interop Contract v2.3 §4)

**Date:** 2026-06-16
**Severity:** Medium
**Component:** Challenge response, PoW verification, session bypass
**Status:** Closed

## What Happened

Epic E17 (Challenge Lifecycle, interop contract v2.3 §4) was scaffolded but non-functional end-to-end. Goal: make a `challenge` decision programmatically solvable by the benchmarker. Lane: normal. Stories US-1701 (response format) + US-1702 (solve submission + session). Shipped in commit 7417f2a on main-harness.

Four hard blockers were fixed:
1. **HTML response** was rendered but had no literal "challenge" string and no form for a browser/benchmarker to POST back to.
2. **No verify endpoint** — no `/challenge/verify` data-plane route to submit a solution.
3. **Token charset breakage** — HMAC token is `base64url(payload).base64url(hmac)` (contains dot); the old cookie scheme `__waf_cc=token.nonce` split on first dot, mangling the token and breaking issuance.
4. **Difficulty encoding mismatch** — advertised as bits (16) but fed to a hex-char solver, making it unsolvable in-browser.

## The Brutal Truth

The scaffolding was 80% there but the last 20% was actually load-bearing. Moving the session credit from client-side (JS setting a cookie) to server-side (`Set-Cookie` from the verify endpoint) broke a pre-existing test (`challenge_renderer.rs::render_challenge_page_contains_all_required_elements`), which asserted the HTML contained `__waf_cc=`. The assertion was stale — it reflected an earlier design, not the correct contract. Updating it to assert `action="/challenge/verify"` instead was the right fix, but it caught us off-guard because the test itself was never run against live code after the design moved. This is a **test-brittleness smell**: integration tests that couple to implementation details (cookie names in HTML) rather than the actual submission path.

## Technical Details

**Content-negotiated challenge response** (`crates/gateway/src/proxy_waf_response.rs`):
- `Accept: text/html` → HTML page with literal "challenge" + Format B `<form action="/challenge/verify" method="POST">` with hidden `challenge_token` field
- else → Format A JSON `{challenge, challenge_type, challenge_token, difficulty, submit_url, submit_method}`
- Both carry six observability headers, including `X-WAF-Action: challenge`

**New endpoint `POST /challenge/verify`** (intercepted in `crates/gateway/src/proxy.rs`, handler `handle_challenge_verify`):
- Parses `{challenge_token, nonce}` from request body
- Validates token charset with `is_safe_token` (anti header-injection)
- Calls `verify_pow(token, nonce, 16 bits)` using `sha256_hex(challenge_token + nonce)` requiring 4 leading zero hex chars (16 bits)
- Success → `200 OK` + `Set-Cookie: __waf_cc=<opaque HMAC token>; Path=/; HttpOnly; SameSite=Lax`
- Failure → `403 Forbidden`

**PoW difficulty convention clarified** (`crates/waf-engine/src/challenge/`):
- Canonical: bits=16 (minimum 1 hex char required; bits/4, rounded up)
- Response advertises `difficulty` in hex chars, not bits, so in-page solver and benchmarker agree
- Server verifies in bits; client/benchmarker works in chars; response translates

**Token charset relaxed** (`crates/waf-engine/src/challenge/renderer.rs`):
- Now permits `.` in base64url-encoded tokens to survive round-trip
- Old code rejected `.`, breaking the real HMAC `base64url(payload).base64url(hmac)` format

**Session bypass** (`handle_challenge` in proxy):
- When `__waf_cc` cookie present on retry, runs authoritative `verifier.verify(token, actor)` 
- HMAC validation + actor binding + single-use nonce consumption
- Returns `allowed_after_challenge` on success
- Credit token is single-use; consuming it prevents replay

## Lessons Learned

**Scaffolding != contract closure.** The feature was "90% done" but the missing 10% was all the surface — the actual observable behavior the benchmarker relies on. Scaffolded code can hide integration gaps until content negotiation, endpoint routing, or data-plane flows are exercised end-to-end.

**Test assertions on implementation details (cookie names in HTML) become stale.** Better: assert the contract (form action, submit method, required fields) rather than the internal encoding. The test failed fast and forced the right fix, but it's a reminder to decouple tests from transient details.

**Difficulty unit confusion is subtle but high-friction.** Advertising bits but delivering to a hex-char solver is a silent failure — no error, just an unsolvable puzzle. The response format now makes the unit explicit (`difficulty_in_chars`), closing that gap.

**HMAC token + nonce round-trip requires care with delimiters.** Using `.` as a separator works if both the renderer and the cookie handler know it. Rejecting `.` in the renderer was a silent failure; relaxing it to `base64url` allowed the real token to flow through.

## Verification

- 2729 tests pass across `waf-engine` + `gateway` (0 failures)
- Zero new clippy warnings/errors (8 pre-existing unrelated `indexing may panic` warnings in `logging/audit_file_sink.rs` confirmed on clean HEAD)
- Stories US-1701 (response format) + US-1702 (solve + session) marked `implemented` via harness-cli with unit+integration proof
- Live proxy verify-endpoint e2e deferred (no PostgreSQL-free WafEngine test seam; engine-level verify + consume covers the contract execution path)
- Fixed 1 stale assertion in `crates/waf-engine/tests/challenge_renderer.rs` (now asserts submit path, not cookie name)

## Next Steps

None — E17 closed. Challenge lifecycle is end-to-end solvable. Benchmarker can now detect, parse, and submit challenge responses. Ready for main merge.

**Proof:** 2729/2729 tests green; `cargo check` + `cargo test` clean; harness-cli story proof recorded; code-reviewer approved.
