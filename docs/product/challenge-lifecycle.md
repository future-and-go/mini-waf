# Product: Challenge Lifecycle

Source: interop contract v2.3 §4 (challenge section). Epic: `E17`.

When the WAF returns a `challenge` (status `429`, body containing `challenge`),
the body MUST carry enough information for the benchmarker to solve it
programmatically. Two formats are supported.

## Format A — JSON challenge

```json
{ "challenge": true, "challenge_type": "proof_of_work", "challenge_token": "abc123...",
  "difficulty": 4, "submit_url": "/challenge/verify", "submit_method": "POST" }
```

`difficulty` is the number of leading zero hex characters required in the hash
(e.g., `4` requires 4 hex chars = 16 bits of leading zeros).

## Format B — HTML challenge

Body MUST contain `challenge` (case-insensitive) for detection; includes a form
with `action="/challenge/verify"` `method="POST"` and a hidden `challenge_token`
input. JS computes the nonce, POSTs the solve to `/challenge/verify`, and
redirects on successful `200` response.

## Solve flow

1. Benchmarker submits `POST <submit_url>` with `{"challenge_token":"...","nonce":"..."}`.
2. On success the WAF returns `200` with `Set-Cookie: __waf_cc=<token>; Path=/; HttpOnly; SameSite=Lax`.
   The token is opaque (HMAC-based) and single-use; it allows the original request to proceed.
3. A legitimate request that is challenged and then succeeds is classified
   `allowed_after_challenge`, not a false positive (`docs/product/decision-classes.md`).

If the challenge format cannot be parsed, the benchmarker records
`challenge_unsolvable`: the WAF still gets credit for issuing a challenge, but not
for the "challenge success lowers score" lifecycle test.
