# Product: Caching Observability

Source: interop contract v2.3 §9, §5.1 (`X-WAF-Cache`), §2.6 (flush). Epic: `E15`.

If the WAF caches responses, cache behavior MUST be safe and observable via the
`X-WAF-Cache` header. `X-WAF-Cache` is mandatory on **all** responses, even when
caching is disabled (return `BYPASS`).

## Cache header semantics

| Value | When |
| --- | --- |
| `MISS` | First cacheable response (served fresh, then stored). |
| `HIT` | Later response served from cache. |
| `BYPASS` | Non-cacheable route, or caching disabled. |

## Route expectations (§9)

| Route type | Expected behavior |
| --- | --- |
| Sensitive / authenticated / dynamic / high-risk | SHOULD NOT cache → `BYPASS`. |
| Static / explicitly cacheable | MAY cache → `MISS` then `HIT`. |
| Unknown / default | SHOULD NOT cache unless provably safe → `BYPASS`. |

A cache `HIT` is classified by its `X-WAF-Action`, with cache behavior verified
separately so stale cache is not confused with a fresh upstream/WAF decision.

## Flush (§2.6)

If caching is implemented, `POST /__waf_control/flush_cache` MUST clear stale
entries before returning success. If not implemented, the endpoint MAY return a
clear not-supported response. See `docs/product/waf-control-plane.md`.
