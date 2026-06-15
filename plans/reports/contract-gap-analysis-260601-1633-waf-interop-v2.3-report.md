# WAF Interop Contract v2.3 — Gap Analysis Report

**Date:** 2026-06-01  
**Scope:** Full codebase audit against `analysis/docs/EN_waf_interop_contract_v2.3.md`  
**Method:** 7 parallel Explore agents covering all contract sections, verified by manual reads

---

## Executive Summary

The WAF has strong compliance on **observability headers** (all 6 on every response path), **control API surface** (all 4 endpoints + auth), and **decision classes** (all 6 exist). Three **critical gaps** block benchmark automation: no file-based audit log, ModeRegistry disconnected from the engine, and challenge format incompatible with the benchmarker's programmatic solver.

---

## Compliance Matrix

### COMPLIANT

| Contract § | Requirement | Evidence |
|---|---|---|
| §2.1 | 4 control endpoints exist | `waf-api/src/interop_control.rs` — capabilities, reset_state, set_profile, flush_cache |
| §2.2 | X-Benchmark-Secret auth (403 on invalid) | Constant-time comparison, `interop_control.rs:29-52` |
| §2.3 | capabilities returns features + active snapshot | 17 features, all `supported: true, toggleable: true` |
| §2.4 | reset_state clears runtime state, preserves audit | Clears engine, cache, CrowdSec, mode_registry |
| §2.5 | set_profile supports all/features/policies scopes | Validation, unsupported list, active snapshot |
| §2.6 | flush_cache endpoint | `interop_control.rs:252-260` |
| §3 | 6 decision classes | `WafAction` enum: Allow, Block, Challenge, RateLimit, Timeout, CircuitBreaker |
| §5.1 | All 6 observability headers on every response | `waf_observability_headers.rs` — 5 injection sites cover all egress paths |
| §5.2 | Header values correctly formatted | Sanitized, clamped, enum-driven; 20+ unit tests |
| §5.3 | X-WAF-Action matches actual behavior in enforce | Yes — `is_enforcement_allowed()` gate |
| §8 | Binary named `./waf` | `crates/prx-waf/Cargo.toml` `[[bin]] name = "waf"` |
| §8 | `./waf run` starts WAF | `Commands::Run` subcommand, blocks on `run_server()` |
| §8 | Health endpoint returns 200 | `GET /health` with JSON component status |
| §9 | X-WAF-Cache HIT/MISS/BYPASS on every response | Default `Bypass`, HIT on cache serve, MISS on cache store |
| §9 | Sensitive/authenticated routes → BYPASS | Authorization header, cookies, non-allow decisions all → BYPASS |
| §10 | TCP peer_addr as primary IP | `resolve_client_ip()` returns peer_ip when `trust_proxy_headers=false` |
| §10 | XFF is supplementary only | Gated by `trust_proxy_headers` + `trusted_proxies` CIDR |

---

### CRITICAL GAPS (block benchmark automation)

#### C1. VictoriaLogs audit sender needs file-tap to `./waf_audit.log`

**Contract §6, §8:** WAF MUST write JSONL to `./waf_audit.log` (configurable). Benchmarker reads this file after each run.

**Current:** Audit events go to VictoriaLogs HTTP endpoint only (`audit_sender.rs:89-129`). No local file writer exists. No config field for audit log path.

**Decision:** VictoriaLogs remains the primary audit backend. The audit sender already serializes events as JSONL for the HTTP POST — add a file-tap that appends each serialized line to `./waf_audit.log` alongside the VictoriaLogs HTTP send.

**Impact:** Without the file-tap, benchmarker cannot read audit data for correlation, score validation, or post-run inspection.

**Fix scope:**
1. Add `audit_log_path` config field (default `./waf_audit.log`) to config struct
2. In `audit_sender.rs`, open the file (append mode, create-if-absent) at startup
3. On each event: serialize contract-compliant JSONL line → append to file + send to VictoriaLogs
4. File writes must be append-only; `reset_state` must NOT truncate/delete the file
5. Field names in the file-tap line must match contract schema (see H1 below) — VictoriaLogs can keep its existing `_time`/`req_id` format separately

---

#### C2. ModeRegistry disconnected from engine — `set_profile` is a no-op

**Contract §2.5:** `set_profile` toggles enforce/log_only per-feature/policy. X-WAF-Mode must reflect the policy mode. In log_only, enforcement must not apply.

**Current:**
- `set_profile` updates `ModeRegistry` ✅
- `ModeRegistry.resolve()` exists ✅
- Engine **never calls** `resolve()` ❌ — checks only `ctx.host_config.log_only_mode`
- X-WAF-Mode derived from `host_config.log_only_mode`, not ModeRegistry ❌
- Checkers don't declare their feature identity ❌

**Impact:** The benchmarker can toggle individual features/policies via `set_profile`, but the engine ignores it. All features stay in whatever mode `host_config.log_only_mode` says. Per-feature mode evaluation is impossible.

**Fix scope:**
1. Inject `ModeRegistry` ref into engine
2. Each checker/detection declares its feature+policy identity
3. `make_block_decision()` calls `mode_registry.resolve(feature, policy)` instead of `ctx.host_config.log_only_mode`
4. Gateway reads `decision.mode` for X-WAF-Mode header (already does this)

---

#### C3. Challenge format incompatible with benchmarker

**Contract §4:** Benchmarker expects either JSON or HTML with `submit_url` + `challenge_token` + `difficulty`. Benchmarker submits `POST <submit_url>` with `{"challenge_token":"...","nonce":"..."}`.

**Current:** Challenge renders HTML with embedded JS that auto-computes PoW, sets `__waf_cc` cookie, and redirects. No `submit_url` endpoint. No JSON challenge format. Benchmarker cannot submit `POST /challenge/verify`.

**Impact:** Benchmarker records `challenge_unsolvable` — WAF gets credit for issuing challenge but loses "challenge success lowers score" lifecycle test points.

**Fix scope:** Add `POST /challenge/verify` endpoint accepting `{"challenge_token":"...","nonce":"..."}` and returning `200` + session cookie on valid PoW. Optionally add JSON challenge format (Format A).

---

### HIGH GAPS (contract violation, scoring deduction)

#### H1. Audit log field schema mismatch

**Contract §6 required fields:**
| Required | Current | Status |
|---|---|---|
| `request_id` (UUID) | `req_id` | ❌ Wrong field name |
| `ts_ms` (epoch ms) | `_time` (RFC3339) | ❌ Wrong format |
| `ip` (TCP peer_addr) | `client_ip` (may be XFF-derived) | ⚠️ Conditional |
| `action` (6 decision classes) | `event_type` (block/allow/challenge/rate_limit/log_only) | ❌ Wrong field name + wrong values |
| `risk_score` (0-100) | missing | ❌ Not in AuditEvent |
| `mode` (enforce/log_only) | missing | ❌ Not in AuditEvent |
| `method` | `method` | ✅ |
| `path` (with query) | `path` | ✅ |

**Fix scope:** Add a contract-compliant serialization path for the file-tap (C1). The `AuditEvent` struct gains `risk_score` and `mode` fields. The file-tap serializer maps: `req_id`→`request_id`, `_time`→`ts_ms` (epoch ms), `event_type`→`action` (using 6 contract values), `client_ip`→`ip`. VictoriaLogs format can stay unchanged (its own schema, no benchmarker dependency).

---

#### H2. No audit events for `allow` decisions

**Contract §5.3:** "Required headers MUST be present on allowed responses... The benchmarker uses allowed-response risk scores to verify risk accumulation and decay."

**Current:** `send_audit_event()` only fires for non-allow decisions (lines 651-824 of `engine.rs`). Also, `send_audit_event()` returns early if `decision.result` is `None` (line 996-997), which is the case for `WafDecision::allow()`.

**Impact:** Benchmarker cannot correlate allowed responses with audit log entries. Risk lifecycle validation incomplete.

**Fix scope:** Call `send_audit_event()` for allow decisions too. Create a synthetic `DetectionResult` for allow outcomes so the event has context. Both VictoriaLogs and the file-tap (C1) must receive allow events.

---

#### H3. Gateway doesn't intercept `/__waf_control/*` from upstream proxying

**Contract §2.1:** "All control endpoints MUST be local/admin-only and MUST NOT be proxied to upstream."

**Current:** Gateway only intercepts `/health` (proxy.rs:613). If a host routes `/__waf_control/*` requests, they get proxied to upstream.

**Impact:** Control plane requests could leak to upstream origins. The benchmarker's secret header would be sent to an untrusted backend.

**Fix scope:** Add `/__waf_control/` prefix intercept in gateway `request_filter`, similar to `/health` handling. Return 404 or route to admin API.

---

#### H4. Config file path mismatch

**Contract §8:** `Config: ./waf.yaml (or ./waf.toml) — MUST exist in working directory`

**Current:** Default config path is `configs/default.toml` (via CLI `--config` flag). Not `./waf.yaml` or `./waf.toml` in working directory root.

**Impact:** Benchmarker expects `./waf.toml` in CWD. Current default doesn't match.

**Fix scope:** Change CLI default to `./waf.toml` (or support both `./waf.yaml` and `./waf.toml` with fallback). Alternatively, create a symlink or wrapper.

---

### MEDIUM GAPS (potential scoring deduction)

#### M1. Audit `client_ip` may use XFF instead of TCP peer_addr

**Contract §6, §10:** Audit `ip` field MUST be TCP peer address, never XFF-derived.

**Current:** When `trust_proxy_headers=true` and peer is in `trusted_proxies`, `client_ip` becomes XFF-derived (`request_ctx_builder.rs:227-248`). This is the same IP logged in audit events.

**Mitigation:** Default config has `trust_proxy_headers=false`, so peer_addr is used. But if the competition sandbox uses any proxy config, this breaks.

**Fix scope:** Store raw `peer_addr` separately from `client_ip` in `RequestCtx`. Audit log always writes `peer_addr`. Rate-limiting/risk-scoring can continue using `client_ip`.

---

#### M2. `ddos.yaml` config uses wrong schema

**Contract §2.3:** Features like `ddos_protection` must be functionally operational for toggling.

**Current:** `configs/ddos.yaml` uses `per_ip/per_fingerprint/ban_durations_secs/store` schema, but `DdosFileConfig` parser expects `ddos:` root with `tiers:` containing `critical/high/medium/catch_all` entries. Config silently ignored.

**Impact:** DDoS protection may not load correctly from YAML config, making the feature non-functional despite being listed in capabilities.

**Fix scope:** Rewrite `configs/ddos.yaml` to match `DdosFileConfig` schema.

---

#### M3. No explicit 127.0.0.x loopback distinction tests

**Contract §10:** "WAF MUST treat different 127.0.0.x addresses as distinct clients."

**Current:** No evidence of loopback collapsing — IPs are `std::net::IpAddr` compared atomically. Likely compliant but no integration test proves 127.0.0.1 and 127.0.0.2 are rate-limited separately.

**Fix scope:** Add integration test verifying distinct rate-limit counters for 127.0.0.1 vs 127.0.0.2.

---

## Priority-Ordered Fix Roadmap

| Priority | Gap | Effort | Dependency |
|---|---|---|---|
| P0 | C1 — VictoriaLogs file-tap to `./waf_audit.log` | Medium | None |
| P0 | C2 — ModeRegistry→engine wiring | Large | None |
| P0 | H1 — Contract-compliant field schema for file-tap | Small | Blocked by C1 |
| P1 | C3 — Challenge submit_url endpoint | Medium | None |
| P1 | H2 — Audit events for allow decisions | Small | Blocked by C1 |
| P1 | H3 — Gateway intercepts /__waf_control | Small | None |
| P1 | H4 — Config path default | Small | None |
| P2 | M1 — Separate peer_addr from client_ip | Medium | None |
| P2 | M2 — Fix ddos.yaml schema | Small | None |
| P2 | M3 — Loopback distinction test | Small | None |

---

## Files Involved

| File | Gaps |
|---|---|
| `crates/waf-engine/src/logging/audit_sender.rs` | C1, H1 |
| `crates/waf-engine/src/engine.rs` | C2, H2 |
| `crates/waf-engine/src/interop/mode_registry.rs` | C2 |
| `crates/waf-engine/src/interop/feature_catalog.rs` | C2 |
| `crates/gateway/src/proxy_waf_response.rs` | C3 |
| `crates/gateway/src/proxy.rs` | H3 |
| `crates/gateway/src/ctx_builder/request_ctx_builder.rs` | M1 |
| `crates/waf-api/src/interop_control.rs` | — (compliant) |
| `crates/gateway/src/waf_observability_headers.rs` | — (compliant) |
| `crates/prx-waf/src/main.rs` | H4 |
| `configs/ddos.yaml` | M2 |
| `crates/waf-common/src/types.rs` | — (compliant) |

---

## Unresolved Questions

1. ~~Should the file-based audit log replace VictoriaLogs, or run in parallel?~~ **DECIDED:** VictoriaLogs stays as primary backend. File-tap appends contract-compliant JSONL to `./waf_audit.log` alongside VictoriaLogs HTTP send.
2. Should `host_config.log_only_mode` be deprecated in favor of ModeRegistry, or remain as a fallback? (Recommend: fallback — ModeRegistry overrides when set, host_config is default)
3. For challenge, should we implement both Format A (JSON) and Format B (HTML with submit_url), or just one? (Recommend: JSON Format A for benchmarker, keep HTML for browsers)
4. When logging allow decisions to audit, should we log ALL allowed requests or only those that triggered some detection signal? (Contract implies all, but volume concern)
