# E17 — Challenge Lifecycle (interop v2.3 §4)

Make a `challenge` decision programmatically solvable by the benchmarker.
Lane: normal. Contract: `analysis/docs/EN_waf_interop_contract_v2.3.md` §4.
Stories: US-1701 (response format), US-1702 (solve submission + session).

## Problem (from scout)

The challenge lifecycle is scaffolded but **never worked end-to-end**:

1. `handle_challenge` (gateway) renders an HTML page with no literal "challenge"
   and no `<form>` → benchmarker can't detect/parse it (US-1701 fail).
2. No `/challenge/verify` data-plane endpoint → no programmatic solve (US-1702 fail).
3. The HMAC token is `base64url.base64url` (**contains `.`**), but `renderer.rs`
   rejects `.` and the `__waf_cc=token.nonce` cookie splits on the first `.` →
   real-issuer issuance errors and the cookie can't round-trip.
4. Advertised difficulty (`16`) is fed to a hex-char solver → unsolvable in-browser.

## Design (confirmed with user)

- **One solve path** for browser + benchmarker: both `POST /challenge/verify`
  with `{challenge_token, nonce}`.
- **PoW convention** (in-repo canonical, verified in `page_template.rs` +
  `challenge-test-server.ts`): `sha256_hex(challenge_token + nonce)` has
  `D` leading zero **hex chars**; nonce = decimal integer string. Server verifies
  via existing `verify_pow(token, nonce, D*4 bits)`. `D = 4` (matches contract
  example; ~65k iters, sub-second).
- **Response format** (content-negotiated): `Accept: text/html` → HTML page that
  contains the literal "challenge" + Format B `<form action="/challenge/verify"
  method="POST">` with hidden `challenge_token`; otherwise → JSON Format A.
- **Session**: `/challenge/verify` success → `Set-Cookie __waf_cc=<challenge_token>`
  (opaque HMAC token, dots-safe as a cookie value) + `200`. The retried original
  request's `handle_challenge` does the authoritative `verifier.verify` (HMAC +
  binding + single-use nonce consume) → allow (`allowed_after_challenge`).

## Phases

| # | Phase | Status |
| --- | --- | --- |
| 01 | Challenge response: Format A JSON + Format B HTML form, coherent difficulty | done |
| 02 | `/challenge/verify` data-plane endpoint + retry-bypass rewrite | done |
| 03 | Tests (unit + integration) + story/docs sync | done |

## Key files

- `crates/waf-engine/src/challenge/page_template.rs` — Format B form + "challenge" + JS posts to verify
- `crates/waf-engine/src/challenge/renderer.rs` — allow `.` in token; (opt) Format A helper
- `crates/gateway/src/proxy_waf_response.rs` — content negotiation, Format A JSON, retry bypass
- `crates/gateway/src/proxy.rs` — intercept `POST /challenge/verify` in `request_filter`

## Success criteria

- US-1701: challenge is `429`, body contains "challenge" (case-insensitive), and
  is either valid Format A JSON or Format B HTML with a parseable form.
- US-1702: `POST /challenge/verify {challenge_token,nonce}` with a valid nonce →
  `200` + `__waf_cc` cookie; retried request with that cookie is allowed.
- Invalid/insufficient nonce → non-200; no regression in existing challenge tests.
- All workspace tests + clippy pass.
