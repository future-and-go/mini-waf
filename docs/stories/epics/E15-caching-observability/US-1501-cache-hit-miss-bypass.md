# US-1501 X-WAF-Cache HIT/MISS/BYPASS correctness on cacheable routes

## Status

implemented

## Lane

normal

## Product Contract

If the WAF caches responses, cache behavior MUST be observable via the mandatory
`X-WAF-Cache` header on every response (§9, §5.1). The first cacheable response is
served fresh and stored, marked `MISS`; a later response served from cache is marked
`HIT`. Header values are uppercase and exact, and a `HIT` is classified by its
`X-WAF-Action` so a stale cache entry is never confused with a fresh upstream/WAF
decision.

## Relevant Product Docs

- `docs/product/caching-observability.md`
- interop contract v2.3 §9 (route expectations), §5.1 (`X-WAF-Cache` semantics)

## Acceptance Criteria

- First cacheable response carries `X-WAF-Cache: MISS` and the response is stored for reuse.
- A subsequent request to the same cacheable route is served from cache with `X-WAF-Cache: HIT`.
- `X-WAF-Cache` values are uppercase and exactly `MISS` or `HIT` (no aliases or casing variants).
- A `HIT` is classified by its own `X-WAF-Action`, verified separately from cache state.
- `X-WAF-Cache` is present on every response on the route, never omitted.

## Design Notes

- Commands: response-cache store/lookup in `crates/gateway`.
- Queries: cache-decision lookup keyed by cacheable route.
- API: `X-WAF-Cache` header (`MISS`, `HIT`) emitted on all responses.
- Tables: in-memory/response cache store in `crates/gateway`.
- Domain rules: first cacheable response `MISS` then stored; later served-from-cache `HIT`; values uppercase exact; `HIT` classified by `X-WAF-Action`, verified separately from cache state.
- UI surfaces: none.

## Validation

When updating durable proof status, use numeric booleans:
`scripts/bin/harness-cli story update --id <id> --unit 1 --integration 1 --e2e 0 --platform 0`.

| Layer | Expected proof |
| --- | --- |
| Unit | cache-decision maps to correct `X-WAF-Cache` header value. |
| Integration | MISS->HIT sequence across two requests to a cacheable route. |
| E2E | post-flush request returns fresh (`MISS`). |
| Platform | |
| Release | |

## Harness Delta

Story registered under decision 0008-interop-contract-v2.3-adoption; durable proof
booleans set via harness-cli after verification.

## Evidence

Response cache in crates/gateway; flush in crates/waf-api/src/interop_control.rs.
Durable proof recorded 2026-06-15: status=implemented, unit=1 integration=1 e2e=0 (e2e/benchmark loopback deferred); see harness.db.
