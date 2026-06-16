# Phase 01 — Challenge response: Format A JSON + Format B HTML form

Story: US-1701. Contract: interop v2.3 §4.

## Overview

- Priority: high (blocks US-1702 + benchmarker detection)
- Status: done
- Make the `challenge` (429) response detectable + parseable by the benchmarker
  in both content-negotiated modes.

## Key insights

- HMAC token format is `base64url(payload).base64url(hmac)` — it **contains a
  dot**. `renderer.rs` token-charset validation currently rejects `.`, which
  errors out real-issuer tokens before they ever reach the page.
- Advertised difficulty must be expressed in the same unit the in-page/benchmark
  solver uses: **leading zero hex chars**. Canonical PoW = `sha256_hex(token +
  nonce)` with `D` leading `0` hex chars; `D = 4` (contract example value).
  Server-side `verify_pow` takes **bits**, so it verifies with `D * 4 = 16`.

## Requirements

- `Accept: text/html` → HTML body that:
  - contains the literal string `challenge` (case-insensitive AC satisfied),
  - contains a Format B `<form action="/challenge/verify" method="POST">` with a
    hidden `challenge_token` input,
  - carries inline JS that solves PoW then `fetch('/challenge/verify', POST
    {challenge_token, nonce})` and on `200` does `location.href = redirect`.
- Otherwise → Format A JSON:
  `{"challenge":true,"challenge_type":"proof_of_work","challenge_token":"<t>",
  "difficulty":4,"submit_url":"/challenge/verify","submit_method":"POST"}`.
- Unparseable/issue failure path keeps returning the existing
  `challenge_unsolvable` behavior.

## Related code files

Modify:
- `crates/waf-engine/src/challenge/renderer.rs` — relax token charset to allow
  `.` (single change to the validation predicate). Keep difficulty bounds.
- `crates/waf-engine/src/challenge/page_template.rs` — add the literal
  `challenge`, the Format B `<form>` with hidden `challenge_token`, and change
  the JS solver to POST to `/challenge/verify` then redirect (instead of writing
  `document.cookie` + location).

## Implementation steps

1. `renderer.rs`: change the token-validation predicate from
   `c.is_ascii_alphanumeric() || c == '-' || c == '_'` to also accept `c == '.'`.
2. `page_template.rs`: in the rendered HTML, ensure the visible/marker text
   contains `challenge`; inject
   `<form action="{{submit_url}}" method="POST"><input type="hidden"
   name="challenge_token" value="{{token}}"></form>` (submit_url defaults
   `/challenge/verify`).
3. `page_template.rs` JS: keep the hex-char PoW loop `c(x,n)`; once a nonce is
   found, `fetch(submit_url, {method:'POST', headers:{'content-type':
   'application/json'}, body: JSON.stringify({challenge_token, nonce})})` →
   `.then(r => { if (r.ok) location.href = redirect })`.
4. Confirm difficulty rendered into the page = `4` (hex chars).

## Todo

- [ ] Relax renderer token charset (allow `.`)
- [ ] Add `challenge` literal + Format B form to HTML template
- [ ] Switch in-page JS to fetch `/challenge/verify` then redirect
- [ ] Format A JSON shaping lives in gateway (phase 02) — template only owns HTML

## Success criteria

- Unit: HTML render contains `challenge`, a `<form action="/challenge/verify"
  method="POST">`, and the hidden `challenge_token`.
- Unit: a real issuer token (with a `.`) renders without error.
- No regression in existing renderer tests.

## Risks

- Touching the JS could break the existing browser E2E. Mitigation: keep the PoW
  hex-char loop identical; only change the submit mechanism + redirect.
