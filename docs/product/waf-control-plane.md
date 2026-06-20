# Product: WAF Control Plane

Source: interop contract v2.3 §2. Implementation: `crates/waf-api/src/interop_control.rs`,
`crates/waf-api/src/server.rs`. Epic: `E10`.

The WAF exposes a small **local control plane** so the benchmarker can discover
capabilities, reset runtime state, toggle enforcement mode, and flush cache. All
control endpoints are local/admin-only and MUST NOT be proxied upstream.

## Endpoints

Prefix: `/__waf_control`.

| Method | Path | Requirement | Purpose |
| --- | --- | --- | --- |
| `GET` | `/__waf_control/capabilities` | REQUIRED | Discover supported features, policies, toggle controls, active mode. |
| `POST` | `/__waf_control/reset_state` | REQUIRED | Clear temporary runtime state between runs. |
| `POST` | `/__waf_control/set_profile` | REQUIRED | Toggle `enforce`/`log_only` for all/one/selected features/policies. |
| `POST` | `/__waf_control/flush_cache` | REQUIRED if caching exists | Clear WAF cache. |

## Authentication

Every control request MUST carry `X-Benchmark-Secret: waf-hackathon-2026-ctrl`.
Missing/invalid secret MUST return `403 Forbidden`. This is an auth hard gate.

## Capabilities (§2.3)

Returns `{ ok, features{ name: { supported, toggleable, policies[] } }, active{ default_mode, overrides{} } }`.
Feature/policy names are implementation-defined but MUST be stable within a run.

## reset_state (§2.4)

Clears at least: risk state, rate-limit counters, cache, challenge/session state,
temporary client/session metadata, temporary enforcement state. Synchronous and
atomic: success MUST NOT return until all temporary state is cleared, and partially
reset state MUST NOT be exposed after success. MUST NOT delete/truncate/rewrite
`./waf_audit.log`; the audit log stays append-only across resets. Success:
`{ ok, action:"reset_state", audit_log_preserved:true, ts_ms }`.

## set_profile (§2.5)

Body: `{ scope: "all"|"features"|"policies", mode: "enforce"|"log_only", features?[], feature?, policies?[] }`.

- `scope:"all"` sets default mode for all features/policies.
- `scope:"features"` changes only listed features; omitted features keep their mode.
- `scope:"policies"` changes only listed policies under `feature`; siblings unchanged.

Unsupported items MUST NOT be silently ignored. **Adopted behavior**
(decision 0008): return success for supported items and list unsupported ones in
`unsupported[]`; consistent for the whole run. Response echoes `applied` and the
resulting `active{ default_mode, overrides }`.

## flush_cache (§2.6)

If caching is implemented, MUST clear stale entries before returning success.
If not implemented, MAY return a clear not-supported response.

## Mode correlation (§2.7)

Every proxied response carries `X-WAF-Mode` reflecting the mode of the policy that
produced the final reported `X-WAF-Action`. See `docs/product/enforcement-modes.md`.

## Capability catalog

`capabilities` advertises a fixed catalog of 17 features, each `supported:true`,
`toggleable:true`. Source: `crates/waf-engine/src/interop/feature_catalog.rs`.
Phase→(feature,policy) binding: `crates/waf-engine/src/interop/checker_feature_map.rs`.

| Feature | Policies | Protection |
| --- | --- | --- |
| `access_control` | `ip_whitelist`, `ip_blacklist`, `url_whitelist`, `url_blacklist` | IP/URL allow + block lists |
| `injection_control` | `sqli`, `xss`, `rce` | SQL injection, XSS, RCE |
| `path_traversal` | `dir_traversal` | Directory traversal |
| `network_protection` | `ssrf`, `header_injection` | SSRF + header injection |
| `rate_limiting` | `per_ip`, `per_session` | Rate limiting |
| `ddos_protection` | `per_ip_burst`, `per_tier` | DDoS burst + per-tier thresholds |
| `bot_detection` | `scanner`, `bot` | Scanner + bot detection |
| `owasp_rules` | `core_ruleset` | OWASP CRS |
| `custom_rules` | `yaml_rules`, `rhai_scripts`, `wasm_plugins` | Custom YAML / Rhai / WASM logic |
| `geo_protection` | `geo_blocking` | Geo restriction |
| `data_protection` | `sensitive_data`, `anti_hotlink` | Sensitive-data + anti-hotlink |
| `reputation` | `crowdsec`, `community_blocklist` | CrowdSec + community blocklist |
| `risk_assessment` | `cumulative_risk` | Cumulative risk scoring |
| `velocity_control` | `tx_velocity` | Transaction velocity |
| `device_intelligence` | `fingerprint_analysis` | Device fingerprinting |
| `auth_protection` | `brute_force` | Brute-force / auth protection |
| `payload_protection` | `body_abuse` | Request-body abuse |

The catalog is static: `supported`/`toggleable` describe what the interop layer
*names*, not what the running config currently enables. A `set_profile` mode
override is stored per arbitrary feature/policy key regardless of detector wiring.

Known gap: the catalog advertises `ddos_protection.per_tier`, but no detection
phase binds to it (only `per_ip_burst` is mapped). A policy-scoped `set_profile`
on `per_tier` returns `ok:true` yet has no hot-path effect.

## Configuration boundary

The control plane is a **mode dial, not a configuration manager**. `set_profile`
only switches `enforce`/`log_only`; it never enables a detector or sets a
threshold, list, or band. Each capability is governed across three planes:

| Plane | Surface | Controls |
| --- | --- | --- |
| Config | startup `./waf.yaml`/`.toml`, hot-reload | Enable flags, thresholds, DB paths (e.g. `ddos.enabled`, `ddos.tiers.*.per_fp_threshold`, GeoIP `ipv4_path`/`ipv6_path`, risk bands) |
| Admin | admin API + Postgres + admin UI | Operator-managed rules and lists (e.g. geo country block/allow rules, IP/URL lists, custom rules) |
| Control | `/__waf_control/set_profile` | `enforce` ↔ `log_only` only, per scope |

Consequence: a detector disabled in config produces no verdict, so toggling its
mode via `set_profile` has no effect. Enabling and tuning a capability is always
a config or admin-plane operation, never a control-plane one.
