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
