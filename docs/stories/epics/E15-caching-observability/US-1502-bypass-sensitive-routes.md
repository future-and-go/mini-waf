# US-1502 Sensitive/auth/dynamic/unknown routes return BYPASS

## Status

implemented

## Lane

normal

## Product Contract

Sensitive, authenticated, dynamic, and high-risk routes SHOULD NOT be cached and
MUST return `X-WAF-Cache: BYPASS` (§9). Unknown or default routes also return
`BYPASS` unless caching is provably safe. Because `X-WAF-Cache` is mandatory on all
responses (§5.1), `BYPASS` is likewise returned whenever caching is disabled, so
cache behavior stays safe and observable.

## Relevant Product Docs

- `docs/product/caching-observability.md`
- interop contract v2.3 §9 (route expectations), §2.6 (flush / control plane)

## Acceptance Criteria

- Sensitive routes return `X-WAF-Cache: BYPASS`.
- Authenticated routes return `X-WAF-Cache: BYPASS`.
- Dynamic and high-risk routes return `X-WAF-Cache: BYPASS`.
- Unknown / default routes return `X-WAF-Cache: BYPASS` unless caching is provably safe.
- `X-WAF-Cache: BYPASS` is also returned on all responses when caching is disabled.
- `BYPASS` value is uppercase and exact.

## Design Notes

- Commands: cache-decision classifier in `crates/gateway` that selects `BYPASS` for non-cacheable routes.
- Queries: route-type classification (sensitive, authenticated, dynamic, high-risk, unknown).
- API: `X-WAF-Cache: BYPASS` header emitted for non-cacheable routes and when caching is disabled.
- Tables: response cache store in `crates/gateway` (not written for `BYPASS`).
- Domain rules: sensitive/authenticated/dynamic/high-risk/unknown routes -> `BYPASS`; `BYPASS` also when caching disabled.
- UI surfaces: none.

## Validation

When updating durable proof status, use numeric booleans:
`scripts/bin/harness-cli story update --id <id> --unit 1 --integration 1 --e2e 0 --platform 0`.

| Layer | Expected proof |
| --- | --- |
| Unit | route classification maps non-cacheable routes to `BYPASS`. |
| Integration | BYPASS on sensitive routes (and when caching disabled). |
| E2E | |
| Platform | |
| Release | |

## Harness Delta

Story registered under decision 0008-interop-contract-v2.3-adoption; durable proof
booleans set via harness-cli after verification.

## Evidence

Response cache in crates/gateway; flush in crates/waf-api/src/interop_control.rs.
Durable proof recorded 2026-06-15: status=implemented, unit=1 integration=1 e2e=0 (e2e/benchmark loopback deferred); see harness.db.
