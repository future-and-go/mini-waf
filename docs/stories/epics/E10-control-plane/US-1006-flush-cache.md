# US-1006 POST /flush_cache

## Status

planned

## Lane

normal

## Product Contract

`POST /__waf_control/flush_cache` clears the WAF cache. When caching is implemented, it must clear stale entries before returning success; when caching is not implemented, it may return a clear not-supported response. The endpoint is secret-gated (interop v2.3 §2.6).

## Relevant Product Docs

- `docs/product/waf-control-plane.md`
- interop v2.3 §2.6 (flush_cache, clear-before-success vs not-supported)

## Acceptance Criteria

- When caching is on, stale entries are cleared before a success response returns.
- When caching is off, a clear not-supported response is returned (no false success).
- Secret-gated (403 without valid `X-Benchmark-Secret`).
- Response is unambiguous about whether a flush occurred or is unsupported.

## Design Notes

- Commands: flush WAF cache when caching present.
- Queries: none.
- API: `flush_cache_handler` (POST) in `crates/waf-api/src/interop_control.rs`; wired in `crates/waf-api/src/server.rs`.
- Tables: none.
- Domain rules: clear-before-success when caching on; explicit not-supported when off.
- UI surfaces: none.
- Endpoint: POST /__waf_control/flush_cache

## Validation

When updating durable proof status, use numeric booleans:
`scripts/bin/harness-cli story update --id <id> --unit 1 --integration 1 --e2e 0 --platform 0`.

| Layer | Expected proof |
| --- | --- |
| Unit | Flush path clears cache; not-supported branch returns clear response. |
| Integration | `crates/waf-api/tests/interop_control_integration.rs` asserts flush success / not-supported and 403 without secret. |
| E2E | Cached entries gone after flush in subsequent traffic. |
| Platform | Same behavior across platforms. |
| Release | Cache state deterministic post-flush. |

## Harness Delta

Story registered under decision 0008-interop-contract-v2.3-adoption; durable proof booleans set via harness-cli after verification.

## Evidence

Code present: `crates/waf-api/src/interop_control.rs`, `crates/waf-api/src/server.rs`, `crates/waf-common/src/config.rs`. Durable proof unset pending `harness-cli story verify`.
