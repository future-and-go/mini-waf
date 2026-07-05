---
phase: 3
title: "Real lookup_ip backed by GeoIpService"
status: completed
priority: P1
dependencies: []
effort: "1h"
---

# Phase 3: Real lookup_ip backed by GeoIpService

## Overview

Replace the hardcoded `iso_code:"XX"` stub in `lookup_ip` with a real lookup
through the `GeoIpService` the engine already owns. Independent of Phases 1–2
(no dependency) — can land in parallel; touches only `engine.rs` (one accessor)
and `geo_api.rs` (the handler).

## Requirements

- Functional: `POST /api/geoip/lookup {"ip":"<addr>"}` returns the country/ISO/ISP
  from `GeoIpService` when the xdb databases are loaded.
- Functional: when GeoIP is disabled (service never set) or the address is not in
  the xdb (private IP / miss), return the existing "not loaded / unknown" style
  stub — no error, backward-compatible response shape.
- Functional: an unparseable `ip` returns a clean client error, not a panic.

## Architecture

- Engine accessor (`crates/waf-engine/src/engine.rs`): the GeoIP service lives in
  `geoip: OnceLock<Arc<GeoIpService>>` (`engine.rs:107`) with a `set_geoip`
  (`engine.rs:529`) but **no public getter**. Add:
  ```rust
  /// Look up GeoIP info for `ip`. Returns `None` when the service is
  /// disabled/unset; returns a (possibly empty) `GeoIpInfo` otherwise.
  pub fn geoip_lookup(&self, ip: IpAddr) -> Option<GeoIpInfo> {
      self.geoip.get().map(|svc| svc.lookup(ip))
  }
  ```
  `GeoIpService::lookup` (`geoip.rs:94`) already returns `GeoIpInfo::default()`
  (all-empty) on family/searcher miss, so callers distinguish "service off"
  (`None`) from "no data for this IP" (`Some(empty)`). Ensure `IpAddr` and
  `waf_common::GeoIpInfo` are in scope in `engine.rs` (GeoIpInfo re-exported via
  `waf_common`; `IpAddr` from `std::net`).
- API handler (`crates/waf-api/src/geo_api.rs:147-159`): change signature from
  `_state: State<Arc<AppState>>` to `State(state): State<Arc<AppState>>`, then:
  ```rust
  let ip_str = body.get("ip").and_then(|v| v.as_str()).unwrap_or("").to_owned();
  let Ok(ip) = ip_str.parse::<std::net::IpAddr>() else {
      return Err(ApiError::BadRequest(format!("invalid ip: {ip_str}"))); // BadRequest(String) confirmed error.rs:15
  };
  match state.engine.geoip_lookup(ip) {
      Some(info) if !info.iso_code.is_empty() || !info.country.is_empty() => Ok(Json(json!({
          "success": true,
          "data": {
              "ip": ip_str,
              "iso_code": info.iso_code,
              "country_name": info.country,
              "isp": if info.isp.is_empty() { Value::Null } else { json!(info.isp) },
          }
      }))),
      _ => Ok(Json(json!({          // service off, or empty (private IP / xdb miss)
          "success": true,
          "data": { "ip": ip_str, "iso_code": "XX",
                    "country_name": "Unknown — GeoIP database not loaded", "isp": null }
      }))),
  }
  ```
  `ApiError::BadRequest(String)` (`error.rs:15` → `StatusCode::BAD_REQUEST`
  `error.rs:37`) is confirmed present — use it, no new variant needed.
- Update the module/file docstring (`geo_api.rs:4-5`, `145-146`) that calls the
  response a permanent stub — it is now real when xdb is present.

## Related Code Files

- Modify: `crates/waf-engine/src/engine.rs` (add `geoip_lookup`; imports if needed)
- Modify: `crates/waf-api/src/geo_api.rs` (`lookup_ip` handler + docstrings)
- Reference: `geoip.rs:94-122` (`GeoIpService::lookup`), `waf_common::GeoIpInfo`
  fields (`country, province, city, isp, iso_code`), `state.rs:19` (`engine`),
  `crates/waf-api/src/error.rs` (error variants)

## Implementation Steps

1. Add `WafEngine::geoip_lookup` + confirm imports compile.
2. Rewrite `lookup_ip` to take `State(state)`, parse the IP, call the accessor,
   map `GeoIpInfo` → response, fall back to the stub on `None`/empty/parse-miss.
3. Fix the misleading "stub" docstrings.
4. `cargo test -p waf-api geo`; `cargo build -p prx-waf`.

## Success Criteria

- [ ] With no xdb loaded (CI default), `lookup_ip` still returns the "not loaded"
      stub and `success:true` — no regression, no error.
- [ ] `geoip_lookup` returns `None` when `set_geoip` was never called; `Some(info)`
      when it was (unit-testable on the engine with a service built from a tiny
      fixture, or asserted via the mapping test if no xdb fixture exists).
- [ ] Invalid `ip` input yields a clean 4xx (or the stub) — never a 500/panic.
- [ ] Response envelope unchanged (`{success, data:{ip, iso_code, country_name, isp}}`).

## Risk Assessment

- **No xdb in CI (High likelihood, handled).** ip2region xdb files are not in the
  repo, so a real-country assertion can't run in CI. Cover the stub/fallback path
  deterministically; assert the `GeoIpInfo`→JSON mapping directly (pure fn), and
  gate any real-xdb assertion behind file existence (skip when absent), matching
  how `geoip.rs` tests only `parse_region`.
- **Backward compatibility (Low).** The response envelope and the GeoIP-off
  behavior are preserved exactly; only the populated-xdb path changes from stub to
  real data. Existing FE consumers of `{ip, iso_code, country_name, isp}` unaffected.
</content>
