# E15 — Caching Observability

Contract: interop v2.3 §9, §5.1, §2.6. Product doc: `docs/product/caching-observability.md`.
Lane: normal. Code: response cache in `crates/gateway`, flush in
`crates/waf-api/src/interop_control.rs`.

`X-WAF-Cache` is mandatory on all responses; cache behavior must be safe and observable.

## Stories

| ID | Title | Lane | Status | §
| --- | --- | --- | --- | --- |
| US-1501 | X-WAF-Cache HIT/MISS/BYPASS correctness on cacheable routes | normal | implemented | §9, §5.1 |
| US-1502 | Sensitive/auth/dynamic/unknown routes return BYPASS | normal | implemented | §9, §5.3 |
| US-1503 | flush_cache clears stale entries before success | normal | implemented | §9, §2.6 |

## Acceptance criteria (per story)

- **US-1501**: first cacheable response → `MISS` (then stored); later served-from-cache
  response → `HIT`; value uppercase exact; a `HIT` is classified by its `X-WAF-Action`.
- **US-1502**: sensitive/authenticated/dynamic/high-risk/unknown routes → `BYPASS`;
  `BYPASS` also returned when caching is disabled.
- **US-1503**: `POST /__waf_control/flush_cache` clears stale entries before returning
  success when caching is implemented; not-supported response when caching is off.

## Validation shape

Unit: cache-decision → header. Integration: MISS→HIT sequence, BYPASS on sensitive routes,
flush clears entries. E2E: post-flush request returns fresh (`MISS`).
