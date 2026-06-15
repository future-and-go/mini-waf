# US-1701 Challenge response format (JSON A / HTML B), 429, body has "challenge"

## Status

in_progress

## Lane

normal

## Product Contract

When the WAF issues a challenge decision, it MUST respond with status `429` and a
body containing the token `challenge` (case-insensitive) so the benchmarker can
detect it. The body MUST be programmatically solvable in one of two shapes: JSON
Format A carrying the proof-of-work fields, or HTML Format B carrying a form and
hidden challenge token. A body that cannot be parsed into either format yields
`challenge_unsolvable` — the WAF gets credit for issuing, not for the lifecycle test.

## Relevant Product Docs

- `docs/product/challenge-lifecycle.md`
- interop contract v2.3 §4 (challenge)

## Acceptance Criteria

- A challenge response returns status `429` with a body containing `challenge`
  (case-insensitive).
- JSON Format A bodies expose all of: `challenge`, `challenge_type`,
  `challenge_token`, `difficulty`, `submit_url`, `submit_method`.
- HTML Format B bodies include a form with `action`/`method` and a hidden
  `challenge_token` field; body still contains `challenge` for detection.
- A challenge body that parses as neither Format A nor Format B is classified
  `challenge_unsolvable` (issuing credit only).
- Detection is robust to case (`Challenge`, `CHALLENGE`, `challenge` all match).

## Design Notes

- Commands: challenge issue path in `crates/gateway`.
- Queries: format detection (JSON A vs HTML B vs unparseable) in `crates/waf-engine`.
- API: `429` challenge response; JSON Format A field set; HTML Format B form contract.
- Tables: n/a.
- Domain rules: body MUST contain `challenge` (case-insensitive); unparseable →
  `challenge_unsolvable`.
- UI surfaces: HTML Format B challenge page (form + hidden token).

## Validation

When updating durable proof status, use numeric booleans:
`scripts/bin/harness-cli story update --id <id> --unit 1 --integration 1 --e2e 0 --platform 0`.

| Layer | Expected proof |
| --- | --- |
| Unit | Challenge token issue/verify; Format A field set present; Format B form/hidden-token present; unparseable → `challenge_unsolvable`. |
| Integration | Issue → solve → proceed: challenge response is `429` with parseable Format A or B body. |
| E2E | Benchmarker-style auto-detect parses the issued challenge format. |
| Platform | |
| Release | |

## Harness Delta

Story registered under decision 0008-interop-contract-v2.3-adoption; durable proof
booleans set via harness-cli after verification.

## Evidence

Challenge issue/verify in crates/gateway + crates/waf-engine. Durable proof unset
pending `harness-cli story verify`.
