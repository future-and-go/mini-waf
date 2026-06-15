# US-1302 Threat category → action acceptable-set mapping

## Status

in_progress

## Lane

normal

## Product Contract

For each threat category, the chosen action must fall within the acceptable set
defined in §3.1, and never within the unacceptable set. The benchmark checks
membership in the acceptable set, not an exact action match, so the mapping is
semantic guidance rather than an exhaustive list. The generalizing principle is
that actions should target the actor responsible for the threat.

## Relevant Product Docs

- `docs/product/decision-classes.md`
- interop contract v2.3 §3.1 (threat-category → action mapping)

## Acceptance Criteria

- High-confidence injection (SQLi/XSS/cmd/SSRF): acceptable `block`, `challenge`;
  unacceptable `rate_limit`, `timeout`, `allow`.
- Low-confidence injection (heuristic): acceptable `block`, `challenge`,
  `log_only`.
- Auth abuse (cred stuffing, brute force): acceptable `rate_limit`, `challenge`,
  `block`; unacceptable `timeout`, `circuit_breaker`.
- Volumetric abuse, single source: acceptable `rate_limit`, `block`; unacceptable
  `circuit_breaker`.
- Slow-loris / connection exhaustion: acceptable `timeout`, `block`; unacceptable
  `rate_limit`.
- Upstream degradation (WAF-detected): acceptable `circuit_breaker`; unacceptable
  `block`, `rate_limit`.
- Recon / scanning: acceptable `block`, `rate_limit`, `challenge`.
- Known malicious IP (blacklist): acceptable `block`.
- Chosen actions target the actor responsible for the threat.

## Design Notes

- Commands: none.
- Queries: none.
- API: emitted action reported via `X-WAF-Action`.
- Tables: none.
- Domain rules: action enum in `crates/waf-common/src/types.rs`; threat→action
  decision mapping in `crates/gateway`.
- UI surfaces: none.

## Validation

When updating durable proof status, use numeric booleans:
`scripts/bin/harness-cli story update --id <id> --unit 1 --integration 1 --e2e 0 --platform 0`.

| Layer | Expected proof |
| --- | --- |
| Unit | per-category acceptable-set membership enforced. |
| Integration | threat classification maps to an acceptable action. |
| E2E | threat fixtures asserted within acceptable action set. |
| Platform | n/a. |
| Release | mapping consistent with §3.1 acceptable/unacceptable sets. |

## Harness Delta

Story registered under decision 0008-interop-contract-v2.3-adoption; durable proof
booleans set via harness-cli after verification.

## Evidence

Action enum + mapping in crates/waf-common + crates/gateway. Durable proof unset
pending `harness-cli story verify`.
