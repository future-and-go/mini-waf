# WAF Interop Contract v2.3 — Gap Analysis Report

**Date:** 2026-05-27  
**Scope:** Full codebase audit against `analysis/docs/EN_waf_interop_contract_v2.3.md`  
**Severity:** CRITICAL — multiple contract-blocking gaps prevent benchmark compatibility  

---

## Executive Summary

The WAF has strong detection capabilities (SQLi, XSS, RCE, rate-limit, challenge/PoW, OWASP CRS, device-fp, risk scoring) but is **not benchmark-compatible** with interop contract v2.3. The entire control plane (§2), all 6 mandatory response headers (§5), the file-based JSONL audit log (§6), and the binary startup contract (§8) are missing or incompatible.

**Estimated gaps:** 6 CRITICAL, 4 HIGH, 3 MEDIUM

---

## §2 — WAF Control Interface: **ENTIRELY MISSING** [CRITICAL]

### Gap 2.1: No control endpoints exist

| Required Endpoint | Status | Evidence |
|---|---|---|
| `GET /__waf_control/capabilities` | **MISSING** | grep finds zero matches for `__waf_control` or `capabilities` endpoint |
| `POST /__waf_control/reset_state` | **MISSING** | No runtime state reset endpoint |
| `POST /__waf_control/set_profile` | **MISSING** | No feature/policy mode toggle |
| `POST /__waf_control/flush_cache` | **MISSING** | Cache flush exists at `/api/cache` (JWT-auth), not at contract path |

**Impact:** Benchmarker cannot discover features, reset state between runs, toggle enforce/log_only per feature, or flush cache. All benchmark orchestration blocked.

### Gap 2.2: No `X-Benchmark-Secret` authentication

Contract requires `X-Benchmark-Secret: waf-hackathon-2026-ctrl` header guard on control endpoints. No implementation exists.

### Gap 2.3: log_only mode is per-host boolean, not per-feature/policy

Current: `HostConfig::log_only_mode: bool` — single toggle per virtual host.  
Required: Granular enforce/log_only per feature AND per policy, togglable at runtime via `set_profile`.

**Impact:** Cannot selectively evaluate individual detection features.

---

## §3 — WAF Decision Classes: **INCOMPLETE** [CRITICAL]

### Gap 3.1: Missing action types in `WafAction` enum

Current `WafAction` variants (`types.rs:95`):
- `Allow`, `Block { status, body }`, `LogOnly`, `Redirect { url }`, `Challenge`

Contract requires 6 decision classes:

| Decision | Status | Notes |
|---|---|---|
| `allow` | Present | `WafAction::Allow` |
| `block` | Present | `WafAction::Block` |
| `challenge` | Present | `WafAction::Challenge` |
| `rate_limit` | **MISSING** | Rate-limit phase exists but maps to `Block` action |
| `timeout` | **MISSING** | Upstream timeouts exist (FR-039) but not as a WAF decision class |
| `circuit_breaker` | **MISSING** | No circuit-breaker action for upstream health protection |

`LogOnly` and `Redirect` are implementation variants not in the contract. The contract treats `log_only` as a mode, not an action.

**Impact:** Benchmarker classification matrix (§7) relies on exact `X-WAF-Action` values. Rate-limited requests will be misclassified as `block`; timeout/circuit-breaker scenarios cannot be classified at all.

---

## §5 — Mandatory Observability Headers: **ALL 6 MISSING FROM RESPONSES** [CRITICAL]

None of the 6 required headers are injected into HTTP responses:

| Header | Status | Evidence |
|---|---|---|
| `X-WAF-Request-Id` | **NOT SET** | UUID generated (`req_id` in `request_ctx_builder.rs:174`) but never added to response headers |
| `X-WAF-Risk-Score` | **NOT SET** | Score computed by risk scorer (`scorer.rs`) but never injected into response |
| `X-WAF-Action` | **NOT SET** | Decision is made but never reported via header |
| `X-WAF-Rule-Id` | **NOT SET** | `dominant_contributor()` exists in `score.rs:57` but result never set on response |
| `X-WAF-Cache` | **NOT SET** | Cache exists (Moka) but no HIT/MISS/BYPASS header emitted |
| `X-WAF-Mode` | **NOT SET** | `log_only_mode` boolean exists but never surfaced as response header |

**Where injection should happen:** `proxy.rs:response_filter()` (line 792) and `proxy_waf_response.rs:write_waf_decision()` — neither injects any `X-WAF-*` headers. The `write_waf_decision` function builds response headers but only sets status code and body.

**Impact:** Benchmarker's PRIMARY classification mechanism is completely non-functional. Every request will be recorded as an observability contract failure.

---

## §6 — Audit Log: **WRONG FORMAT AND DESTINATION** [CRITICAL]

### Gap 6.1: No file-based JSONL audit log

Contract requires: `./waf_audit.log` — append-only JSONL file, one JSON object per line.  
Current: Audit events sent to VictoriaLogs via HTTP batch (`audit_sender.rs` → `BatchSender` → `POST /insert/jsonline`). No local file written.

### Gap 6.2: Audit schema mismatch

| Required Field | Current State | Gap |
|---|---|---|
| `request_id` (UUID v4) | `req_id` (present) | Field name mismatch; must also match `X-WAF-Request-Id` |
| `ts_ms` (epoch millis) | `_time` (RFC3339) | Wrong format — contract requires integer Unix epoch ms |
| `ip` (TCP peer_addr) | `client_ip` | May come from XFF when `trust_proxy_headers=true`; contract mandates TCP peer_addr |
| `method` | `method` (present) | OK |
| `path` | `path` (present) | OK (truncated at 500 chars — acceptable) |
| `action` (6 classes) | `event_type` | Field name mismatch; only covers block/allow/challenge/rate_limit/log_only — missing timeout, circuit_breaker |
| `risk_score` (0–100) | **MISSING** | Not included in audit event payload |
| `mode` (enforce/log_only) | **MISSING** | Not included in audit event payload |

### Gap 6.3: Audit log not preserved across reset_state

Contract §2.4: `reset_state` MUST NOT modify `./waf_audit.log`.  
Not applicable yet (no reset_state exists), but design must account for this when implementing.

---

## §8 — WAF Startup & Binary Contract: **INCOMPATIBLE** [HIGH]

| Contract Requirement | Current State | Gap |
|---|---|---|
| Binary at `./waf` | `./target/release/prx-waf` | Binary name and location differ |
| Start: `./waf run` | `prx-waf -c configs/default.toml run` | Requires explicit config flag |
| Config: `./waf.yaml` or `./waf.toml` | `configs/default.toml` | Different path and no auto-discovery |
| Logs: `./waf_audit.log` | VictoriaLogs HTTP | No local file output |
| Health endpoint polled on startup | `GET /health` on admin port (9527) | Exists but benchmarker must know correct port |

**Impact:** Benchmarker automation (`./waf run` → poll health → begin tests) will fail at startup.

---

## §4 — Challenge Response Format: **PARTIALLY COMPATIBLE** [HIGH]

### Gap 4.1: Challenge verification path

Contract Format B expects: `<form action="/challenge/verify" method="POST">` with `challenge_token` + JS-computed nonce.  
Current: Cookie-based verification (`__waf_cc` cookie with embedded PoW solution). No distinct `POST /challenge/verify` endpoint exists.

Contract benchmarker submission: `POST <submit_url>` with `{"challenge_token":"...","nonce":"..."}`.  
Current: Challenge solution embedded in cookie, verified on next request via `proxy_waf_response.rs:handle_challenge()`.

**Impact:** Benchmarker cannot programmatically solve challenges → recorded as `challenge_unsolvable`. Loses lifecycle test credit.

### Gap 4.2: Challenge HTTP status

Contract recommends `429` for challenge responses. Current implementation uses custom status from `challenge_response.status` (renderer-dependent). Need to verify it returns 429.

---

## §7 — Decision Normalization: **BROKEN BY §5 GAPS** [HIGH]

All normalization logic depends on `X-WAF-Action`, `X-WAF-Mode`, `X-WAF-Rule-Id`, `X-WAF-Cache` headers. Since none are present, the entire classification matrix is non-functional.

---

## §9 — Caching Observability: **MISSING** [HIGH]

Cache exists (Moka LRU with tier-aware bypass, tag-based purge) but:
- `X-WAF-Cache: HIT/MISS/BYPASS` header never set on responses
- `POST /__waf_control/flush_cache` not implemented at contract path
- No `BYPASS` signal for sensitive/auth/dynamic routes in response headers

---

## §10 — Source IP Trust Model: **PARTIAL** [MEDIUM]

### Gap 10.1: Audit log IP semantics

Contract: `ip` field MUST be TCP peer_addr, NOT XFF.  
Current: `client_ip` in audit event comes from `extract_client_ip_from_session()` which can use XFF when `trust_proxy_headers=true`.

### Gap 10.2: Loopback address distinction

Contract: Different `127.0.0.x` MUST be treated as distinct clients.  
Current: `resolve_client_ip()` uses `peer_addr.ip()` as fallback, which preserves loopback distinction. Likely OK when `trust_proxy_headers=false`, but needs explicit verification.

---

## §5.2/§6 — log_only Mode Semantics: **WRONG IMPLEMENTATION** [MEDIUM]

### Gap: Log-only changes the action instead of preserving it

Contract §2.5: In `log_only`, the WAF MUST evaluate normally and report the **intended** `X-WAF-Action` (e.g., `block`) while NOT enforcing. `X-WAF-Mode: log_only` indicates the mode.

Current (`engine.rs:557`): When `host_config.log_only_mode` is true, the engine returns `WafAction::LogOnly` — **replacing** the intended action. The original intended action (block/challenge/rate_limit) is lost.

```rust
// Current (WRONG per contract):
let decision = if ctx.host_config.log_only_mode {
    WafDecision { action: WafAction::LogOnly, result: Some(result) }
} else {
    WafDecision::block(403, Some(body), result)
};
```

Contract requires: preserve `action: block` and add `mode: log_only`, then skip enforcement.

**Impact:** Benchmarker cannot verify detector accuracy in log_only mode — the intended action is discarded.

---

## §4 — Challenge Format Compatibility: **MINOR** [MEDIUM]

Challenge page is rendered server-side via `ChallengeContext` with `token`, `difficulty`, `redirect_url`, `branding_title`, `branding_message`. The HTML format needs verification against Format B requirements (must contain "challenge" case-insensitive, hidden `challenge_token` input, `action="/challenge/verify"`).

---

## Summary Matrix

| Contract Section | Severity | Status | Effort Estimate |
|---|---|---|---|
| §2 Control Interface (4 endpoints) | CRITICAL | 0% done | Large — new module |
| §3 Decision Classes (6 actions) | CRITICAL | 50% done | Medium — enum + pipeline changes |
| §5 Observability Headers (6 headers) | CRITICAL | 0% done | Medium — inject in response_filter |
| §6 JSONL Audit Log | CRITICAL | 0% done | Medium — new file writer + schema |
| §5+§6 log_only semantics | CRITICAL | Wrong | Medium — refactor action vs mode |
| §8 Binary/Startup Contract | CRITICAL | Incompatible | Small — wrapper script or alias |
| §4 Challenge Format | HIGH | Partial | Medium — verification endpoint |
| §7 Normalization Matrix | HIGH | Blocked by §5 | Zero (auto-fixed by §5) |
| §9 Cache Observability | HIGH | Partial | Small — add header in response_filter |
| §10 IP Trust Model | MEDIUM | Mostly OK | Small — audit log fix |

---

## Recommended Implementation Order

1. **§3 + §5 + §6 log_only refactor** — Fix `WafAction` enum (add `RateLimit`, `Timeout`, `CircuitBreaker`), preserve intended action in log_only mode, inject all 6 `X-WAF-*` response headers, implement `./waf_audit.log` JSONL writer. These are deeply coupled.
2. **§2 Control Interface** — New `/__waf_control/*` handler module with benchmark-secret auth, capabilities discovery, state reset, profile toggle, cache flush.
3. **§8 Binary Contract** — Wrapper script or cargo alias for `./waf run` with default config path.
4. **§9 Cache Observability** — Add `X-WAF-Cache` header injection (piggybacks on §5 work).
5. **§4 Challenge Format** — Add `/challenge/verify` POST endpoint with benchmarker-compatible JSON/HTML format.
6. **§10 IP audit fix** — Ensure audit log `ip` field always uses TCP peer_addr.

---

## Unresolved Questions

1. **Binary naming**: Should we rename the binary from `prx-waf` to `waf`, or create a symlink/wrapper? Renaming affects CI, Docker, systemd units.
2. **Config path**: Contract expects `./waf.yaml` or `./waf.toml` in CWD. Should we add auto-discovery fallback, or create a symlink?
3. **VictoriaLogs coexistence**: The JSONL file audit log is required by the contract. Should it replace VictoriaLogs ingestion or run in parallel (dual-write)?
4. **Granularity of features/policies**: Contract requires per-feature and per-policy mode control. How should existing detection phases map to "features" and "policies" in the capabilities response?
5. **Circuit breaker**: No upstream circuit-breaker exists today. Is implementing one in-scope for the hackathon, or should we report it as unsupported in capabilities?
