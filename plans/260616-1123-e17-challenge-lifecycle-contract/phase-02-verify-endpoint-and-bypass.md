# Phase 02 — `/challenge/verify` endpoint + retry-bypass rewrite

Story: US-1702. Contract: interop v2.3 §4.

## Overview

- Priority: high
- Status: done
- Add the data-plane solve endpoint and make the retried original request pass
  (`allowed_after_challenge`).

## Key insights

- `/health` is already short-circuited in `proxy.rs::request_filter` (~line 614)
  with observability headers — mirror that pattern for `POST /challenge/verify`.
- Pingora `Session` exposes `read_request_body().await -> Result<Option<Bytes>>`
  to read the POST body inside `request_filter`.
- The retry bypass must use the authoritative `verifier.verify` (HMAC + binding
  + single-use nonce consume), NOT a PoW-from-cookie re-check.

## Requirements

- `POST /challenge/verify`:
  - read JSON body `{challenge_token, nonce}`,
  - `verify_pow(challenge_token, nonce, 16)` (bits),
  - on success → `200` + `Set-Cookie: __waf_cc=<challenge_token>; Path=/;
    HttpOnly; SameSite=Lax` + observability headers,
  - on PoW failure / malformed body → `403` (or `400`) + observability headers,
  - never forwards upstream.
- Content negotiation for the challenge response (Format A JSON vs Format B HTML)
  is selected in `handle_challenge` based on the `Accept` header.
- Retry bypass (`handle_challenge`): read `__waf_cc` as an opaque HMAC token;
  `verifier.verify(token, binding, now_ms)` → `Valid` → allow (return so the
  request proceeds upstream). Any other outcome → issue a fresh challenge.

## Related code files

Modify:
- `crates/gateway/src/proxy.rs` — add `POST /challenge/verify` intercept in
  `request_filter` (mirror `/health`); helper to read+parse body and build the
  verify response.
- `crates/gateway/src/proxy_waf_response.rs` — `handle_challenge`:
  - content-negotiate Format A JSON vs Format B HTML on issue,
  - rewrite bypass to opaque-token `verifier.verify` only (drop PoW-from-cookie).

## Implementation steps

1. `proxy.rs`: after the `/health` block, add
   `if request_ctx.method == "POST" && request_ctx.path == "/challenge/verify"`
   → read body, `serde_json` parse `{challenge_token, nonce}`,
   `pow::verify_pow(&token, &nonce, 16)`; build 200 + Set-Cookie or 403; attach
   observability headers; `return Ok(true)` (response written, stop pipeline).
2. `proxy_waf_response.rs::handle_challenge` issue branch: compute
   `hex_difficulty = bits / 4` (=4); if `Accept` contains `text/html` → render
   HTML (phase 01 template); else build Format A JSON with `serde_json`.
3. `proxy_waf_response.rs::handle_challenge` bypass branch: if `__waf_cc` cookie
   present → `ctx.verifier.verify(cookie_val, build_fingerprint_binding(ctx),
   now_ms).await`; `VerifyOutcome::Valid` → allow; else fall through to issue.
4. Remove the now-dead PoW-cookie parse path (`PowSolution::parse_cookie` usage
   in the bypass) — surgical: only the lines that become orphaned by the rewrite.

## Todo

- [ ] `POST /challenge/verify` intercept in `request_filter`
- [ ] Read + parse JSON body, verify PoW (16 bits)
- [ ] 200 + `Set-Cookie __waf_cc=<token>` on success; 403 on failure
- [ ] Content-negotiated Format A JSON in `handle_challenge`
- [ ] Bypass via `verifier.verify` (opaque token); drop PoW-cookie path
- [ ] Observability headers on both verify + challenge responses

## Success criteria

- Integration: issue → solve (`POST /challenge/verify`) → retried original
  request with `__waf_cc` cookie is allowed (`allowed_after_challenge`).
- Insufficient/invalid nonce → non-200 from `/challenge/verify`.
- `challenge_flow.rs` + `pow.rs` tests stay green.

## Risks / security

- Single-use: `verifier.verify` consumes the nonce, so the cookie is one-shot —
  acceptable for the benchmarker's single retried request. Document inline as the
  reason (no plan refs).
- Binding mismatch (different client IP) must reject — covered by existing
  `challenge_flow.rs` binding test; ensure the gateway passes the same binding.
