# US-1702 Challenge solve submission + session token allows original request

## Status

in_progress

## Lane

normal

## Product Contract

After a challenge is issued, the benchmarker submits `POST <submit_url>` with a
JSON body of `{"challenge_token","nonce"}`. On a valid solve the WAF MUST return
`200` and grant a session cookie/token that allows the original request to
proceed. A legitimate request that is challenged and then solved MUST be
classified `allowed_after_challenge`, not counted as a false positive.

## Relevant Product Docs

- `docs/product/challenge-lifecycle.md`
- interop contract v2.3 §4 (challenge)

## Acceptance Criteria

- `POST <submit_url>` with body `{"challenge_token","nonce"}` and a valid nonce
  returns `200`.
- The successful solve response carries a session cookie/token.
- Replaying the original request with that session cookie/token lets it proceed
  (no second challenge).
- A legit challenged-then-solved request is classified `allowed_after_challenge`,
  not a false positive.
- An invalid or missing nonce does not yield a passing session token.

## Design Notes

- Commands: challenge verify / session grant in `crates/gateway`.
- Queries: PoW nonce check and token verify in `crates/waf-engine`.
- API: `POST <submit_url>` accepting `{challenge_token, nonce}`; `200` + session
  cookie/token on success.
- Tables: n/a (token state).
- Domain rules: valid nonce → session token → original request proceeds; outcome
  is `allowed_after_challenge`, not a false positive.
- UI surfaces: n/a.

## Validation

When updating durable proof status, use numeric booleans:
`scripts/bin/harness-cli story update --id <id> --unit 1 --integration 1 --e2e 0 --platform 0`.

| Layer | Expected proof |
| --- | --- |
| Unit | PoW nonce check; challenge token verify; session token issue on valid solve. |
| Integration | Issue → solve → proceed: `POST <submit_url>` returns `200` + session token; original request proceeds. |
| E2E | Benchmarker auto-solve lowers risk; original request allowed; classified `allowed_after_challenge`. |
| Platform | |
| Release | |

## Harness Delta

Story registered under decision 0008-interop-contract-v2.3-adoption; durable proof
booleans set via harness-cli after verification.

## Evidence

Challenge issue/verify in crates/gateway + crates/waf-engine. Durable proof unset
pending `harness-cli story verify`.
