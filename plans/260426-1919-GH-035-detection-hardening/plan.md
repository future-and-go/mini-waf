---
name: FR-035 Detection Hardening — CVE-mapped Cases & Edge Hardening
description: Extend FR-035 with vendor/CVE-attributed detection cases, edge-case hardening (CRLF, multi-instance, Set-Cookie auth leaks), real-attack-vector tests. Code = specific cases, config = activation. Same branch / PR 14.
type: implementation
status: completed
created: 2026-04-26
completed: 2026-04-26
branch: feat/fr-035-header-leak-prevention
commit: b25bbc9
target_pr: https://github.com/future-and-go/mini-waf/pull/14
scope: FR-035 enhancement only (FR-033/FR-034 still deferred)
blockedBy: []
blocks: []
follows: 260426-1553-fr035-header-leak-prevention
---

# FR-035 Detection Hardening

## Why Another Plan

PR 14 ships the FR-035 base: 4 broad categories (server_info, debug, error_detail, PII), 19 unit tests, default-disabled. Reviewers asked for:

1. **Specific named detection cases** — not just `X-Powered-By` generic, but per-vendor/per-CVE coverage so an operator can point to "this strips the header that leaked CVE-2024-4577 fingerprinting". Code-side fixed; config-side toggled per family.
2. **Edge cases from real attacks** — CRLF in values, multi-instance headers, Set-Cookie carrying tokens, ETag/Location echoing internal state, etc.
3. **Tests that replay real-world leaks** — Equifax-class fingerprinting, Spring Boot Actuator banner, Drupalgeddon cache header, etc.

Goal: harden detection breadth & correctness without bloating config knobs and without scope creep into FR-033/FR-034.

## Design Anchor

```
Detection cases   → hard-coded const lists in waf-engine::outbound (one list per family)
Activation        → one boolean toggle per family in HeaderFilterConfig (TOML)
Operator override → strip_headers / strip_prefixes still extend any family
```

No regex DSL. No per-route policy. No body filtering.

## Detection Families (5 toggles, additive on top of existing 4)

| Toggle | Hard-coded cases | Past-incident anchor |
|--------|-----------------|----------------------|
| `strip_server_info` (existing — extended) | Adds `X-AspNetMvc-Version`, `X-OWA-Version`, `Liferay-Portal`, `MicrosoftSharePointTeamServices`, `MS-Author-Via`, `X-Mod-Pagespeed`, `X-Page-Speed` | Equifax 2017 (Struts/Apache fingerprint), CVE-2017-7269 (IIS/WebDAV), CVE-2017-12617 (Tomcat) |
| `strip_php_fingerprint` (NEW) | exact `X-Powered-By` PHP-flavoured stripped, `X-PHP-Response-Code`, `X-PHP-Version` | CVE-2024-4577 (PHP-CGI argument injection — banner enabled targeted scan) |
| `strip_aspnet_fingerprint` (NEW) | `X-AspNet-Version`, `X-AspNetMvc-Version`, `X-Powered-By: ASP.NET`, `X-SourceFiles` | CVE-2017-7269, ViewState attacks rely on .NET version |
| `strip_framework_fingerprint` (NEW) | `X-Drupal-Cache`, `X-Drupal-Dynamic-Cache`, `X-Generator`, `X-Magento-Cache-Debug`, `X-Magento-Tags`, `X-Pingback`, `X-Application-Context`, `X-Runtime`, `X-Rack-Cache` | Drupalgeddon (CVE-2014-3704, CVE-2018-7600), CVE-2022-22965 Spring4Shell (Actuator), Magento bug bounties |
| `strip_cdn_internal` (NEW, default **ON**) | `X-Backend-Server`, `Via`-when-internal, `X-Served-By`, `X-Varnish`, `X-Amz-Cf-Id`, `X-Amz-Cf-Pop`, `X-Akamai-*`, `X-Fastly-Request-Id` | This WAF is the edge — no upstream CDN. Any CDN/edge header in an upstream response is leakage from a backend that sits behind another infrastructure layer (AWS API GW, internal Varnish, etc.). Strip by default. |
| `strip_debug_headers` (existing) | as-is | unchanged |
| `strip_error_detail` (existing) | as-is + `X-Application-Trace`, `X-Exception-Class`, `X-DotNet-Version` | CWE-209; classic Rails / Django / Java stack-trace headers |
| `detect_pii_in_values` (existing) | extended below | — |

**`strip_session_headers_on_pii_match` (NEW, default OFF)** — when ON together with `detect_pii_in_values`, expands the value-scan strip to include `Set-Cookie`, `ETag`, and `Authorization` (i.e. headers that carry session/auth material). When OFF, those three headers are preserved even if their values match a PII pattern — operator's call: a noisy false-positive should not kill a user session by default.

PII pattern additions (gated by same `detect_pii_in_values`, no new toggle):
- AWS access key (`AKIA[0-9A-Z]{16}`) — historical S3-creds-in-headers leaks
- Google API key prefix (`AIza[0-9A-Za-z\-_]{35}`)
- Slack bot token (`xox[baprs]-…`) — known bug-bounty class
- GitHub PAT prefix (`gh[pousr]_[A-Za-z0-9]{36,}`) — token leakage CVEs

## Edge-case Hardening (phase 02)

| Case | Real vector | Plan |
|------|------------|------|
| CRLF in header value | CVE-2017-1000026 (Tomcat), HTTP response splitting | **Detect & strip** — any value containing `\r` or `\n` is treated as malicious; emit `tracing::warn!` |
| Multi-instance header (`Set-Cookie`, `X-Forwarded-For`) | RFC 9110 §5.2 — multiple values legal; current `retain` already handles | Add explicit test |
| `Set-Cookie` carrying auth token in URL/value | OAuth-leak class incidents | Strip only if BOTH `detect_pii_in_values` AND `strip_session_headers_on_pii_match` are on (operator opt-in; default preserves session) |
| `ETag` carrying internal hash exposing build info | Spring Boot ETag = SHA of internal classpath | Same gating as Set-Cookie — operator-decided via `strip_session_headers_on_pii_match` |
| `Authorization` echoed in response (rare backend bug) | OAuth misconfig | Same gating — operator-decided |
| `Location` with internal hostname / PII in query | Login redirects echoing email | Generic value scan applies when PII enabled (Location is not in the protected set; treated as a normal `X-*` header) |
| Empty header name | Malformed upstream | `should_strip("")` returns false; existing — add explicit test |
| Header value > 64 KiB | DoS attempt | Skip PII regex if value > 8 KiB (configurable cap, hard-coded `MAX_PII_SCAN_LEN = 8192`); always still subject to name-based strip |
| Non-UTF-8 binary value | Some CDN headers | already handled (`std::str::from_utf8`); add test |
| Hop-by-hop (Connection / Transfer-Encoding / TE / Upgrade) | RFC 9110 §7.6.1 | Explicit allowlist — never strip; current behaviour relies on absence; make implicit assumption explicit + test |
| Trailer headers | Pingora rarely surfaces, document non-coverage | Note in docs; no code |

## Phases

| # | Phase | File | Status |
|---|-------|------|--------|
| 01 | CVE-mapped detection catalog (code consts + 5 new config toggles) | [phase-01-cve-mapped-detection-catalog.md](./phase-01-cve-mapped-detection-catalog.md) | completed |
| 02 | Edge-case hardening (CRLF, value-cap, Set-Cookie, hop-by-hop guard) | [phase-02-edge-case-hardening.md](./phase-02-edge-case-hardening.md) | completed |
| 03 | Tests replaying real-world attack vectors | [phase-03-tests-with-attack-vectors.md](./phase-03-tests-with-attack-vectors.md) | completed |
| 04 | Build + commit + push to existing branch (PR 14 auto-updates) | [phase-04-update-pr-14.md](./phase-04-update-pr-14.md) | completed |

## Key Decisions

1. **Same branch / same PR** — push to `feat/fr-035-header-leak-prevention`; PR 14 auto-updates. Single shippable unit.
2. **Add 4 toggles, not 30** — granularity = vendor family, not per-header.
3. **All new vendor toggles default to `strip_*=true`** — including `strip_cdn_internal`, since this WAF is the public edge (no CDN in front). PHP/ASP.NET/framework/CDN fingerprints almost never legitimate to expose to clients in this deployment shape. Only `strip_session_headers_on_pii_match` defaults OFF (avoid killing session on regex false-positive).
4. **Hard cap on PII regex input** (`MAX_PII_SCAN_LEN = 8192`) — closes ReDoS DoS surface left open in v1.
5. **CRLF defensive strip is unconditional** when filter active — header-injection / response-splitting is never legitimate.
6. **Backward compatible config** — all new toggles `#[serde(default = "...")]`; existing TOMLs still parse.
7. **No body work, no JSON work, no per-route policy** — out of scope.

## Success Criteria

- All existing 19 tests pass unchanged.
- ≥ 12 new unit tests covering: each new family toggle on/off, CRLF strip, value-cap ReDoS guard, hop-by-hop preservation, Set-Cookie token scan, AWS/Slack/GitHub-token regex, multi-instance preservation behaviour.
- `cargo clippy --workspace --all-targets --all-features -- -D warnings` clean.
- `cargo fmt --all -- --check` clean.
- `cargo build --release` green.
- p99 added latency on a 30-header response < 0.7 ms with all toggles + PII on (relax from 0.5 → 0.7 since pattern set grew).
- PR 14 description updated to list new families & CVE attributions.

## Risk

| Risk | Mitigation |
|------|-----------|
| New defaults silently break someone proxying a Drupal site that legitimately reads `X-Drupal-Cache` from upstream JS | All new toggles default `true` ONLY when `outbound.enabled = true`; master toggle still off → zero impact unless opted in |
| ReDoS on token regexes (Slack/GitHub) | Patterns are anchored, finite-length; bounded by `MAX_PII_SCAN_LEN` hard cap |
| CRLF strip false-positive on legitimate value containing `\r\n` | RFC 9110 §5.5 forbids CR/LF in field-value; any upstream sending it is malformed; warn-log + strip is correct |
| PR 14 grows too large to review | Plan is +~250 LOC code, +~150 LOC tests, no new modules — review burden moderate |
| User wants per-PR split instead of stacking on PR 14 | Confirm before phase-04 push (see "Unresolved" below) |

## Standards & References

- OWASP ASVS V14.4 (HTTP security configuration)
- CWE-200 (Information Exposure), CWE-209 (Error-message info exposure), CWE-93 (CRLF injection)
- RFC 9110 §5.5 (field value charset), §7.6.1 (hop-by-hop)
- NIST SP 800-53 SI-11
- Cited CVEs (full list with link mapping in phase-01 file)

## Out of Scope

- FR-033 response body content filtering (separate plan)
- FR-034 sensitive-field JSON redaction (separate plan)
- Per-route / per-host outbound policy DSL
- Trailer header sanitisation (rare in Pingora; document only)
- Cluster sync of outbound config (stateless config — ships via TOML, no sync needed)

## Decisions (confirmed by user 2026-04-26)

1. ✅ Stack on PR 14 — single shippable unit on `feat/fr-035-header-leak-prevention`.
2. ✅ Set-Cookie / ETag / Authorization PII strip is operator-decided via new toggle `strip_session_headers_on_pii_match` (default OFF).
3. ✅ `strip_cdn_internal` defaults to **ON** — this WAF is the public edge with no upstream CDN. Any CDN/edge header in an upstream response is leakage from a layer behind the backend (AWS API GW, internal Varnish, etc.) and should not reach clients.
