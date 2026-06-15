# US-1503 flush_cache clears stale entries before success

## Status

implemented

## Lane

normal

## Product Contract

If caching is implemented, `POST /__waf_control/flush_cache` MUST clear stale cache
entries before returning success (§2.6). If caching is not implemented, the endpoint
MAY return a clear not-supported response. This keeps cache behavior safe and
observable via the mandatory `X-WAF-Cache` header (§9, §5.1), so a post-flush request
is served fresh.

## Relevant Product Docs

- `docs/product/caching-observability.md`
- interop contract v2.3 §9 (route expectations), §2.6 (flush / control plane)

## Acceptance Criteria

- When caching is implemented, `POST /__waf_control/flush_cache` clears stale entries before returning success.
- Success is only returned after stale entries are cleared, not before.
- A request after a flush is served fresh (`X-WAF-Cache: MISS`).
- When caching is disabled/not implemented, the endpoint returns a clear not-supported response.
- `X-WAF-Cache` remains present and uppercase-exact on responses around flush.

## Design Notes

- Commands: `flush_cache` control-plane handler in `crates/waf-api/src/interop_control.rs` clears the response cache in `crates/gateway`.
- Queries: cache state read to confirm stale entries cleared before success.
- API: `POST /__waf_control/flush_cache`; `X-WAF-Cache` header on subsequent responses.
- Tables: response cache store in `crates/gateway`.
- Domain rules: flush clears stale entries before success when caching on; not-supported response when off.
- UI surfaces: none.

## Validation

When updating durable proof status, use numeric booleans:
`scripts/bin/harness-cli story update --id <id> --unit 1 --integration 1 --e2e 0 --platform 0`.

| Layer | Expected proof |
| --- | --- |
| Unit | flush handler clears cache store and returns not-supported when caching off. |
| Integration | flush clears entries; post-flush request returns fresh (`MISS`). |
| E2E | post-flush request returns fresh (`MISS`). |
| Platform | |
| Release | |

## Harness Delta

Story registered under decision 0008-interop-contract-v2.3-adoption; durable proof
booleans set via harness-cli after verification.

## Evidence

Response cache in crates/gateway; flush in crates/waf-api/src/interop_control.rs.
Durable proof recorded 2026-06-15: status=implemented, unit=1 integration=1 e2e=0 (e2e/benchmark loopback deferred); see harness.db.
