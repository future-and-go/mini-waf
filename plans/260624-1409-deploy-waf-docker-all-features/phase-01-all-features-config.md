---
phase: 1
title: "All-Features Config"
status: pending
effort: "M"
---

# Phase 1: All-Features Config

## Overview

Create a new self-contained TOML (`configs/full-features.toml`) plus its companion panel TOML that turn on every single-node feature. **Do not edit `configs/default.toml`** — it is the conservative dev default and is shared by tests/local runs. Every key must be grounded against `crates/waf-common/src/config.rs`; an unknown key or wrong type makes the binary refuse to boot.

## Requirements

- Functional: produce a config that enables HTTP/3, security hardening, outbound header-leak strip, sqli-scan, audit, GeoIP lookup, OWASP CRS + bot + scanner detectors, Valkey cache, rate-limit subsystem, and panel auto-block.
- Non-functional: parses cleanly (`waf -c configs/full-features.toml rules validate` or equivalent parse path), no invented keys, self-signed/local-appropriate values.

## Architecture

`AppConfig` (config.rs:5) sections and the intended state for "all single-node features":

| Section | Action | Notes |
|---|---|---|
| `[proxy]` | keep | same listen addrs as default; TLS cert/key from `/etc/prx-waf/tls` (self-signed via `tls-init`) |
| `[api]` + `[api.tls]` | keep | admin HTTPS auto self-signed (already default) |
| `[storage]` | keep | `DATABASE_URL` env overrides at runtime |
| `[cache]` | `enabled=true`, `backend="standalone"` | `CACHE_BACKEND` env still overrides; `[cache.valkey] seeds=["valkey:6379"]` |
| `[http3]` | **`enabled=true`** | set `cert_pem`/`key_pem` to the self-signed pair; binds UDP 443 (see Phase 2 port map) |
| `[security]` | harden | `max_request_body_bytes` set, `api_rate_limit_rps` > 0 (e.g. 50). Keep `admin_ip_allowlist=[]` and `cors_origins=[]` (local demo → allow all, documented) |
| `[rules]` | explicit section | `dir="rules/"`, `hot_reload=true`, `enable_builtin_owasp/bot/scanner=true` (defaults already true; state explicitly so "all features" is visible in the file) |
| `[geoip]` | enable lookup | **caveat:** auto-update needs network/DB; if no `.xdb` present, lookups no-op. Document, don't fail boot |
| `[sqli_scan]` | enable | header scanning + size limits on |
| `[panel]` | point to companion | `config_path="full-features-panel.toml"` |
| `[rate_limit]` | keep | `config_path="configs/rate-limit.yaml"` (already wired) |
| `[outbound]` + `[outbound.headers]` | **`enabled=true`** | all `strip_*` families on (defaults true once section present); leave `detect_pii_in_values=false` (perf cost, off by design) |
| `[audit]` | keep on | `enabled=true` |
| `[crowdsec]` | **omit/off** | needs external CrowdSec LAPI — excluded |
| `[community]` | **omit/off** | needs `community enroll` + external server — excluded |
| `[cluster]` | **omit** | multi-node topology — excluded |
| `[interop]` | **omit/off** | benchmark control plane only — excluded |

Companion `configs/full-features-panel.toml` (mirror of `waf-panel.toml` with stronger posture):
- `shadow_mode=false` (enforce, not observe)
- risk bands kept (`risk_allow=51`, `risk_challenge=74`, `risk_block=75`)
- `honeypot_paths` kept
- `[auto_block] enabled=true`, `min_events=5`, `window_secs=60`
- `[response_filtering] block_stack_traces=true`
- `[trusted_waf_bypass] cidrs=["127.0.0.1/32","::1/128"]`
- `[rate_limits]` kept (`fail_open=false`)

## Related Code Files

- Create: `configs/full-features.toml`
- Create: `configs/full-features-panel.toml`
- Read-only reference (verify keys/types, do not edit): `crates/waf-common/src/config.rs`, `crates/waf-common/src/panel_config.rs`, `configs/default.toml`, `configs/waf-panel.toml`

## Implementation Steps

1. Re-read `crates/waf-common/src/config.rs` for every section to be enabled (`Http3Config`, `SecurityConfig`, `OutboundConfig`/`HeaderFilterConfig`, `RulesConfig`, `GeoIpConfig`, `SqliScanConfig`) — record exact field names, types, and `#[serde(rename)]`/defaults. List any field whose meaning is unclear in the phase report; do not guess a value that changes behavior.
2. Copy `configs/default.toml` content as the base, then apply the section changes in the table above. Keep comments terse — explain each newly-flipped toggle in one line.
3. Read `crates/waf-common/src/panel_config.rs` to confirm the panel schema, then write `configs/full-features-panel.toml`.
4. Point `[panel] config_path` in `full-features.toml` at `full-features-panel.toml`.
5. Parse-check: `cargo run --release --features gateway/valkey -- -c configs/full-features.toml rules validate` (or the lightest command that deserializes `AppConfig`). It must not panic/error on parse. If a DB connection is required even for parse, note it and fall back to a unit-level parse via a scratch `cargo` snippet.

## Success Criteria

- [ ] `configs/full-features.toml` + `configs/full-features-panel.toml` exist and deserialize into `AppConfig` / panel config without error.
- [ ] Every enabled toggle traces to a real field in `config.rs` / `panel_config.rs` (no invented keys).
- [ ] `configs/default.toml` and `configs/waf-panel.toml` are unchanged.
- [ ] HTTP/3, outbound strip, security rps limit, sqli-scan, audit, auto-block are explicitly `true` in the files.

## Risk Assessment

- **Wrong key name / type → boot failure.** Mitigate: ground every key against `config.rs`; run the parse-check in step 5 before Phase 2.
- **HTTP/3 cert path mismatch.** The self-signed pair lives at `/etc/prx-waf/tls/{cert,key}.pem` inside the container; `[http3]` cert paths must match exactly.
- **GeoIP without a DB file** logs a warning. Acceptable for demo; documented, not a blocker.
