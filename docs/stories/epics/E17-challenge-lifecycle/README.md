# E17 — Challenge Lifecycle

Contract: interop v2.3 §4 (challenge). Product doc: `docs/product/challenge-lifecycle.md`.
Lane: normal. Code: challenge issue/verify in `crates/gateway` / `crates/waf-engine`.

A `challenge` decision (`429`, body containing `challenge`) MUST be programmatically
solvable by the benchmarker.

## Stories

| ID | Title | Lane | Status | §
| --- | --- | --- | --- | --- |
| US-1701 | Challenge response format (JSON A / HTML B), 429, body has "challenge" | normal | in_progress | §4 |
| US-1702 | Challenge solve submission + session token allows original request | normal | in_progress | §4 |

## Acceptance criteria (per story)

- **US-1701**: challenge response is `429` with a body containing `challenge`
  (case-insensitive); either JSON Format A (`challenge`, `challenge_type`,
  `challenge_token`, `difficulty`, `submit_url`, `submit_method`) or HTML Format B (form
  with `action`/`method` + hidden `challenge_token`). Unparseable format →
  `challenge_unsolvable` (credit for issuing, not for the lifecycle test).
- **US-1702**: `POST <submit_url>` with `{"challenge_token","nonce"}` on success returns
  `200` with a session cookie/token that lets the original request proceed; a legit
  challenged-then-solved request is `allowed_after_challenge`, not a false positive.

## Validation shape

Unit: challenge token issue/verify, PoW nonce check. Integration: issue → solve → proceed.
E2E: benchmarker-style auto-solve lowers risk and allows the original request.
