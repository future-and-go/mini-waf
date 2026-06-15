# Product: Decision Classes & Threat→Action Semantics

Source: interop contract v2.3 §3, §4, §7. Epic: `E13` (classes/actions),
cross-referenced by `E14` (normalization in log_only).

Every request results in exactly one decision.

## Decision classes (§3)

| Decision | Meaning | Recommended HTTP (§4) |
| --- | --- | --- |
| `allow` | Proxied; upstream response returned. | upstream status |
| `block` | Denied before upstream. | `403` |
| `challenge` | Held; client must solve JS/PoW challenge. | `429` + challenge body |
| `rate_limit` | Denied for exceeding a rate threshold. | `429` |
| `timeout` | Proxied but upstream did not respond in time. | `504` |
| `circuit_breaker` | Refused to proxy; upstream unhealthy. | `503` |

Body format is free (HTML/JSON/text) as long as headers stay accurate and HTTP
behavior is consistent with the reported action.

## Threat-category → action mapping (§3.1)

The benchmark checks whether the chosen action is within the acceptable set:

| Threat category | Acceptable | Unacceptable |
| --- | --- | --- |
| High-confidence injection (SQLi/XSS/cmd/SSRF) | `block`, `challenge` | `rate_limit`, `timeout`, `allow` |
| Low-confidence injection (heuristic) | `block`, `challenge`, `log_only` | — |
| Auth abuse (cred stuffing, brute force) | `rate_limit`, `challenge`, `block` | `timeout`, `circuit_breaker` |
| Volumetric abuse, single source | `rate_limit`, `block` | `circuit_breaker` |
| Slow-loris / connection exhaustion | `timeout`, `block` | `rate_limit` |
| Upstream degradation (WAF-detected) | `circuit_breaker` | `block`, `rate_limit` |
| Recon / scanning | `block`, `rate_limit`, `challenge` | — |
| Known malicious IP (blacklist) | `block` | — |

Principle to generalize: actions should target the actor responsible for the
threat. The table is semantic guidance, not an exhaustive test list.

## Normalization matrix (§7)

The benchmarker classifies outcomes using the §5 headers plus organizer-side
validation. WAF-side obligation = emit headers that make these classifications
unambiguous:

- enforce + denial action (`block`/`challenge`/`rate_limit`/`timeout`/`circuit_breaker`)
  + unsafe effect prevented → `prevented`.
- enforce + `allow` + unsafe effect occurs → `passed`.
- sanitize/rewrite neutralizes attack → `prevented_sanitized` (`X-WAF-Rule-Id`
  identifies the detector).
- `log_only` + detected → `log_only_detected` (see `docs/product/enforcement-modes.md`).
- legit traffic denied outside stress → `false_positive`; challenge then success →
  `allowed_after_challenge`; rate limit under DDoS/stress → `collateral`.
