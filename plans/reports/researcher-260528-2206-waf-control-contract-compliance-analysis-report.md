# WAF Control Interface §2 Contract Compliance Analysis

**Date:** 2026-05-28 | **Author:** Researcher | **Status:** Final

---

## Executive Summary

WAF Control Interface §2 (EN_waf_interop_contract_v2.3.md) defines four **mandatory endpoints** for deterministic benchmark evaluation. This report maps contract requirements to implementation decisions for Axum/Pingora architecture, provides exact JSON schemas, documents feature/policy catalog mapping, analyzes edge cases, and supplies a TDD test matrix.

**Key Findings:**
- Contract requires **strict response schema validation** — no optional fields in `applied`, `active`, `unsupported`
- Benchmark auth uses **single static header** (`X-Benchmark-Secret: waf-hackathon-2026-ctrl`), NOT JWT
- `reset_state` must be **synchronous and atomic** — blocking until all subsystems cleared
- Feature/policy model is **hierarchical** (`feature.policy` in `active.overrides`)
- `set_profile` supports **three scope variants** with distinct semantics: `all` clears overrides; `features`/`policies` create/update selective overrides
- Engine has **17+ detection phases** mapping to controllable features

---

## 1. Contract §2 Response Schema Compliance

### 1.1 GET /__waf_control/capabilities

**Exact required response schema:**

```json
{
  "ok": true,
  "features": {
    "<feature_name>": {
      "supported": boolean,
      "toggleable": boolean,
      "policies": [string, ...]
    },
    ...
  },
  "active": {
    "default_mode": "enforce" | "log_only",
    "overrides": {
      "<feature_name>": "enforce" | "log_only",
      "<feature_name>.<policy_name>": "enforce" | "log_only",
      ...
    }
  }
}
```

**Contract rules (§2.3):**
- `ok: true` — always succeed unless internal error (500)
- `features` object maps feature names (implementation-defined) to capability metadata
- `supported: true` if feature can be evaluated; `false` if stub/disabled
- `toggleable: true` if feature supports mode switching; `false` if locked to one mode
- `policies` array lists all policy names under that feature (may be empty)
- `active.default_mode` reflects global default (initially `"enforce"`)
- `active.overrides` maps feature and feature.policy overrides applied via prior `set_profile` calls (empty `{}` on startup)
- Feature/policy names must be **stable within a benchmark run** (no UUID/timestamp suffixes)
- No pagination, no async — this is discovery only

**Validation rules:**
- Field order doesn't matter (JSON unordered)
- Extra `X-WAF-*` response headers are permitted
- Missing `ok` field → contract failure
- Missing any required nested field → contract failure
- Malformed JSON → contract failure

---

### 1.2 POST /__waf_control/reset_state

**Exact required response schema:**

```json
{
  "ok": true,
  "action": "reset_state",
  "audit_log_preserved": true,
  "ts_ms": 1777363200123
}
```

**Contract rules (§2.4):**
- `ok: true` only if ALL runtime state fully cleared (contract §2.4 §118)
- `action: "reset_state"` — fixed string for machine parsing
- `audit_log_preserved: true` — always true; audit log is append-only, never truncated
- `ts_ms` — Unix epoch milliseconds when reset completed; benchmarker uses this to correlate sequential resets
- **Synchronous, atomic semantics:** WAF MUST NOT return success until:
  - Rate limit counters cleared (MemoryStore + Redis if present)
  - DDoS ban table + counter store flushed
  - Risk scorer per-actor accumulators reset
  - Challenge/session state cleared
  - Response cache flushed (Moka + Valkey if present)
  - Behavioral anomaly state reset
  - Transaction velocity state cleared
  - Device fingerprint identity store flushed
  - CrowdSec decision cache cleared
  - **All in-flight requests stabilized** (no partial state visible after response)

**What NOT to reset (§2.4 "SHOULD preserve"):**
- Rule store (YAML/JSON config loaded from disk) — stable unless explicitly hot-reloaded
- WafEngine static checks (SQLi, XSS, RCE, etc.) — configuration, not state
- Access control tables (IP/URL whitelist/blacklist) — stable config
- Request/blocked counters — statistics, not runtime state (contract intent: count blocks per run)
- Relay/proxy intel feeds — stable config
- Custom rules scripts — stable config
- OWASP CRS — stable config
- GeoIP database — stable reference data

**Validation rules:**
- 4xx response (missing/invalid secret) returns early, no cleanup
- 5xx response indicates reset partial — benchmarker may score penalty (§2.4 §119)
- Missing `ts_ms` field → contract failure
- `audit_log_preserved: false` → contract failure (only append semantics allowed)

---

### 1.3 POST /__waf_control/set_profile

**Exact required response schema:**

```json
{
  "ok": true,
  "action": "set_profile",
  "applied": {
    "scope": "all" | "features" | "policies",
    "mode": "enforce" | "log_only",
    "features": [string, ...],        // omitted if scope != "features"
    "feature": string,                // omitted if scope != "policies"
    "policies": [string, ...]         // omitted if scope != "policies"
  },
  "active": {
    "default_mode": "enforce" | "log_only",
    "overrides": {
      "<feature_name>": "enforce" | "log_only",
      "<feature_name>.<policy_name>": "enforce" | "log_only",
      ...
    }
  },
  "unsupported": [string, ...],
  "ts_ms": 1777363201123
}
```

**Request schema:**

```json
{
  "scope": "all" | "features" | "policies",
  "mode": "enforce" | "log_only",
  "features": [string, ...],           // required if scope == "features"
  "feature": string,                   // required if scope == "policies"
  "policies": [string, ...]            // required if scope == "policies"
}
```

**Contract rules (§2.5):**

**Scope semantics:**
- `scope: "all"` + `mode: "enforce"` → clears all per-feature and per-policy overrides; reverts to global `default_mode = "enforce"`
- `scope: "all"` + `mode: "log_only"` → sets `default_mode = "log_only"` and clears all overrides
- `scope: "features"` → applies mode only to named features (§2.5 §173); unlisted features remain unchanged
- `scope: "policies"` → applies mode only to named policies under a specific feature (§2.5 §175); unlisted policies in same feature remain unchanged; all other features remain unchanged

**Active state semantics:**
- `active.default_mode` reflects global default after request
- `active.overrides` maps ALL currently active overrides (feature-level and policy-level)
- When `default_mode = "enforce"` and a feature has override "log_only", that feature is logged-only
- When override is removed (via new `set_profile`), it **SHOULD** disappear from `active.overrides` (contract allows WAF to report it differently, but benchmarker expects cleanup §2.5 §186)

**Unsupported handling (§2.5 §254-259):**
- If requested feature name doesn't exist in capabilities → include in `unsupported` array
- If requested policy name doesn't exist under the named feature → include in `unsupported` array
- WAF MUST consistently choose ONE behavior:
  - **Option A:** Return `400 Bad Request` with machine-readable error and `unsupported` list (fail-fast)
  - **Option B:** Return `200 OK` with `unsupported` list; apply only supported items
- Benchmarker tolerates both; **must be consistent for entire run**
- **Recommendation:** Option B (lenient) — allows benchmarker to submit superset requests without breaking on unknown features

**Applied field:**
- `applied.scope` mirrors request scope
- `applied.mode` mirrors request mode
- `applied.features` lists the features actually modified (only if scope="features"; omitted otherwise)
- `applied.feature` specifies the feature (only if scope="policies"; omitted otherwise)
- `applied.policies` lists the policies actually modified (only if scope="policies"; omitted otherwise)

**Validation rules:**
- Request scope not in ["all", "features", "policies"] → 400 Bad Request
- Request mode not in ["enforce", "log_only"] → 400 Bad Request
- scope="features" but no `features` array → 400 Bad Request
- scope="policies" but no `feature` or `policies` array → 400 Bad Request
- Missing any required field in `applied`, `active`, or `unsupported` → contract failure
- `ts_ms` must reflect time when change was applied

---

### 1.4 POST /__waf_control/flush_cache

**Exact required response schema:**

```json
{
  "ok": true,
  "action": "flush_cache",
  "ts_ms": 1777363202123
}
```

**Contract rules (§2.6):**
- **Conditional endpoint:** REQUIRED only if caching is implemented
- If caching disabled: MAY return this success response (contract allows it); OR return `501 Not Implemented` (also allowed)
- If caching enabled: MUST clear all cache entries before returning success (contract §2.6 §544)
- `ok: true` only if flush fully completed (synchronous)
- Benchmarker uses `X-WAF-Cache: MISS` on next request to verify flush worked

---

## 2. Feature & Policy Catalog Mapping

### 2.1 Detection Phase → Feature/Policy Model

WAF engine (engine.rs) runs **17+ detection phases** in sequence. Map to contract features as follows:

| Phase | Detection Component | Feature Name | Policies | Toggle Type |
|-------|-------|---------|----------|----------|
| 1-4 | IP whitelist + blacklist | `access_control` | `whitelist`, `blacklist` | toggleable |
| 1-4 | URL whitelist + blacklist | `url_protection` | `whitelist`, `blacklist` | toggleable |
| 5 | Rate limit (token bucket + sliding window) | `rate_limiting` | `per_ip`, `per_session` | toggleable |
| 6a | TX velocity (transaction rate + path-velocity) | `velocity_control` | `path_velocity`, `request_velocity` | toggleable |
| 7 | Scanner detection (UA + endpoint patterns) | `bot_detection` | `scanner`, `bot` | toggleable |
| 8 | Bot detection (challenge, captcha, etc.) | `bot_detection` | `browser_bot` | toggleable |
| 9 | XSS detection (libinjection + heuristic) | `injection_control` | `xss` | toggleable |
| 10 | RCE detection (shell metachar + patterns) | `injection_control` | `rce` | toggleable |
| 11 | Directory traversal | `path_traversal` | `dir_traversal` | toggleable |
| 12 | SSRF (DNS rebinding + RFC1918 block) | `network_protection` | `ssrf` | toggleable |
| 13 | Header injection | `header_protection` | `header_injection` | toggleable |
| 14 | Brute force (credential stuffing, login attempts) | `auth_protection` | `brute_force` | toggleable |
| 15 | Request body abuse (size, depth, parsing) | `payload_protection` | `body_abuse` | toggleable |
| 16 | SQL injection (libinjection + patterns) | `injection_control` | `sqli` | toggleable |
| 16b | CrowdSec AppSec (remote HTTP check) | `reputation` | `crowdsec_appsec` | toggleable |
| 17a | Custom rules (YAML + Rhai) | `custom_rules` | (each rule ID as policy) | toggleable |
| 17b | OWASP CRS (Core Rule Set) | `owasp_rules` | (ruleset ID as policy) | toggleable |
| 18 | Sensitive data detection (PII, secrets) | `data_protection` | `pii`, `secrets` | toggleable |
| 19 | Anti-hotlink (referrer validation) | `content_protection` | `hotlink_protection` | toggleable |
| 20 | GeoIP access control | `geo_protection` | `geo_blocking` | toggleable |
| 21 | Risk scorer aggregation | `risk_assessment` | `cumulative_risk` | toggleable |
| 22 | DDoS protection (per-IP burst + banning) | `ddos_protection` | `per_ip_burst`, `per_tier_threshold` | toggleable |
| 23 | Community blocklist (CrowdSec community feed) | `reputation` | `community_blocklist` | toggleable |
| 24 | Device fingerprinting (JA3/JA4 + H2 anomaly) | `device_intelligence` | `fingerprint_conflict`, `ip_hopping`, `ua_entropy` | toggleable |
| 25 | Cumulative risk scoring (FR-025 bands + decay) | `risk_assessment` | `risk_thresholds` | toggleable |

**Policy naming convention:**
- Feature-level policies use **lowercase_underscore** for compound names
- Custom rule and OWASP ruleset policy names use **rule-id format** (e.g., `rule-001`, `owasp-921130`)
- All names are stable (no UUIDs, no timestamps)

**Notes:**
- Some features map to multiple detection phases (e.g., `injection_control` covers XSS, RCE, SQLi)
- `access_control` and `url_protection` can be toggled independently
- `bot_detection` and `rate_limiting` are separate (bot detection doesn't always trigger rate-limit)
- Custom rules and OWASP rules each get a policy entry if individual toggle granularity needed; alternatively, group into single policy per ruleset

### 2.2 Capabilities Response Skeleton

```json
{
  "ok": true,
  "features": {
    "access_control": {
      "supported": true,
      "toggleable": true,
      "policies": ["whitelist", "blacklist"]
    },
    "url_protection": {
      "supported": true,
      "toggleable": true,
      "policies": ["whitelist", "blacklist"]
    },
    "rate_limiting": {
      "supported": true,
      "toggleable": true,
      "policies": ["per_ip", "per_session"]
    },
    "velocity_control": {
      "supported": true,
      "toggleable": true,
      "policies": ["path_velocity", "request_velocity"]
    },
    "bot_detection": {
      "supported": true,
      "toggleable": true,
      "policies": ["scanner", "bot", "browser_bot"]
    },
    "injection_control": {
      "supported": true,
      "toggleable": true,
      "policies": ["xss", "rce", "sqli"]
    },
    "path_traversal": {
      "supported": true,
      "toggleable": true,
      "policies": ["dir_traversal"]
    },
    "network_protection": {
      "supported": true,
      "toggleable": true,
      "policies": ["ssrf"]
    },
    "header_protection": {
      "supported": true,
      "toggleable": true,
      "policies": ["header_injection"]
    },
    "auth_protection": {
      "supported": true,
      "toggleable": true,
      "policies": ["brute_force"]
    },
    "payload_protection": {
      "supported": true,
      "toggleable": true,
      "policies": ["body_abuse"]
    },
    "reputation": {
      "supported": true,
      "toggleable": true,
      "policies": ["crowdsec_appsec", "community_blocklist"]
    },
    "custom_rules": {
      "supported": true,
      "toggleable": true,
      "policies": ["rule-001", "rule-002", ...]
    },
    "owasp_rules": {
      "supported": true,
      "toggleable": true,
      "policies": ["owasp-921110", "owasp-921120", ...]
    },
    "data_protection": {
      "supported": true,
      "toggleable": true,
      "policies": ["pii", "secrets"]
    },
    "content_protection": {
      "supported": true,
      "toggleable": true,
      "policies": ["hotlink_protection"]
    },
    "geo_protection": {
      "supported": true,
      "toggleable": true,
      "policies": ["geo_blocking"]
    },
    "risk_assessment": {
      "supported": true,
      "toggleable": true,
      "policies": ["cumulative_risk", "risk_thresholds"]
    },
    "ddos_protection": {
      "supported": true,
      "toggleable": true,
      "policies": ["per_ip_burst", "per_tier_threshold"]
    },
    "device_intelligence": {
      "supported": true,
      "toggleable": true,
      "policies": ["fingerprint_conflict", "ip_hopping", "ua_entropy"]
    }
  },
  "active": {
    "default_mode": "enforce",
    "overrides": {}
  }
}
```

---

## 3. set_profile Edge Cases & Semantics

### 3.1 scope: "all" Behavior

**Request:**
```json
{
  "scope": "all",
  "mode": "log_only"
}
```

**Expected response:**
```json
{
  "ok": true,
  "action": "set_profile",
  "applied": {
    "scope": "all",
    "mode": "log_only"
  },
  "active": {
    "default_mode": "log_only",
    "overrides": {}
  },
  "unsupported": [],
  "ts_ms": 1777363201123
}
```

**Semantics:**
- `default_mode` becomes `"log_only"`
- All features and policies inherit `"log_only"` mode
- `active.overrides` is empty (no selective overrides needed)
- Subsequent feature/policy-level `set_profile` calls can override this default

---

### 3.2 scope: "features" Behavior

**Request:**
```json
{
  "scope": "features",
  "mode": "log_only",
  "features": ["access_control", "rate_limiting"]
}
```

**Expected response (assuming all features exist):**
```json
{
  "ok": true,
  "action": "set_profile",
  "applied": {
    "scope": "features",
    "mode": "log_only",
    "features": ["access_control", "rate_limiting"]
  },
  "active": {
    "default_mode": "enforce",
    "overrides": {
      "access_control": "log_only",
      "rate_limiting": "log_only"
    }
  },
  "unsupported": [],
  "ts_ms": 1777363201124
}
```

**Semantics:**
- Only listed features change mode; unlisted features retain their mode
- If a feature had a prior override, it's updated
- `default_mode` is unchanged (still "enforce")
- Feature-level overrides are stored as `"<feature_name>": <mode>`

---

### 3.3 scope: "policies" Behavior

**Request:**
```json
{
  "scope": "policies",
  "mode": "log_only",
  "feature": "injection_control",
  "policies": ["xss"]
}
```

**Expected response (assuming feature + policies exist):**
```json
{
  "ok": true,
  "action": "set_profile",
  "applied": {
    "scope": "policies",
    "mode": "log_only",
    "feature": "injection_control",
    "policies": ["xss"]
  },
  "active": {
    "default_mode": "enforce",
    "overrides": {
      "injection_control.xss": "log_only"
    }
  },
  "unsupported": [],
  "ts_ms": 1777363201125
}
```

**Semantics:**
- Only named policies under the named feature change mode
- Other policies in same feature (e.g., "sqli", "rce") retain their mode
- `injection_control.rce` remains at `default_mode` ("enforce") unless previously overridden
- Policy-level overrides are stored as `"<feature_name>.<policy_name>": <mode>`
- If feature has a feature-level override (from prior `scope="features"` call), policy-level can override it further

---

### 3.4 Feature Not Found

**Request:**
```json
{
  "scope": "features",
  "mode": "log_only",
  "features": ["nonexistent_feature"]
}
```

**Response (lenient approach — recommended):**
```json
{
  "ok": true,
  "action": "set_profile",
  "applied": {
    "scope": "features",
    "mode": "log_only",
    "features": []
  },
  "active": {
    "default_mode": "enforce",
    "overrides": {}
  },
  "unsupported": ["nonexistent_feature"],
  "ts_ms": 1777363201126
}
```

**Semantics:**
- `applied.features` contains only features that exist
- `unsupported` lists features that don't exist
- No error status; allows benchmarker to send superset requests

**Alternative (strict approach):**
```
400 Bad Request
{
  "ok": false,
  "error": "unsupported features: nonexistent_feature",
  "unsupported": ["nonexistent_feature"]
}
```

---

### 3.5 Policy Not Found Under Feature

**Request:**
```json
{
  "scope": "policies",
  "mode": "log_only",
  "feature": "injection_control",
  "policies": ["xss", "nonexistent_policy"]
}
```

**Response (lenient approach):**
```json
{
  "ok": true,
  "action": "set_profile",
  "applied": {
    "scope": "policies",
    "mode": "log_only",
    "feature": "injection_control",
    "policies": ["xss"]
  },
  "active": {
    "default_mode": "enforce",
    "overrides": {
      "injection_control.xss": "log_only"
    }
  },
  "unsupported": ["injection_control.nonexistent_policy"],
  "ts_ms": 1777363201127
}
```

---

### 3.6 Concurrent set_profile Requests

**Requirement (§2.5 §117):** `reset_state` MUST be synchronous and atomic. **Implication:** `set_profile` should also be atomic to avoid partial state visibility.

**Implementation approach:**
- Use `Arc<Mutex<ProfileState>>` or `Arc<RwLock<ProfileState>>` to guard `active.overrides` and `default_mode`
- Acquire lock at start of request, release after WAF engine re-evaluates active modes
- Lock scope: minimal — only profile update, not full detection pipeline re-run

**Race scenario:**
1. Request A: `scope="all"`, `mode="log_only"` → acquires lock
2. Request B: `scope="features"`, `feature=["access_control"]`, `mode="enforce"` → waits for lock
3. Request A: releases lock with `default_mode="log_only"`, `overrides={}`
4. Request B: acquires lock, updates to `overrides={"access_control": "enforce"}`, releases
5. Final state: `default_mode="log_only"`, `access_control` is "enforce" (feature-level override)

---

### 3.7 Policy Mode Precedence (§2.7)

**When request matches multiple policies with different modes:**

Contract §2.7 states: "When a request matches multiple policies with different active modes, `X-WAF-Mode` SHOULD reflect the mode of the policy that produced the final reported `X-WAF-Action`."

**Example scenario:**
- `scope="all"`, mode="enforce" → all features enforce
- Then `scope="policies"`, feature="injection_control", policy="xss", mode="log_only" → XSS becomes log-only
- Request arrives with XSS + SQLi payloads
- Both detectors match; but XSS is log-only, SQLi is enforce
- SQLi detector runs second, produces `X-WAF-Action: block`
- Final `X-WAF-Mode: enforce` (reflecting SQLi's enforce mode)

**Implementation:** Track which detector/policy produced the final action; report its mode in `X-WAF-Mode` header.

---

## 4. reset_state Completeness Matrix

**All runtime state that MUST be cleared on `/reset_state`:**

| Component | Store Type | Clear method | Verification |
|-----------|-----------|---------|----------|
| Rate limit counters | MemoryStore (RlMemoryStore) | `store.reset_all()` or equivalent | Next request has zero history |
| Rate limit counters | Redis/Valkey (if configured) | `redis.flushdb()` for bucket-specific keys | Verify via Redis CLI |
| DDoS ban table | DynamicBanTable | `ban_table.clear_all()` | Banned IPs become unbanned |
| DDoS offense counter | DdosMemoryStore | `counter_store.reset_all()` | Offense score reset to 0 |
| Risk accumulator per actor | RiskStore (MemoryRiskStore) | `risk_store.reset_all()` or per-key reset | Risk score returns to 0 for all IPs |
| Risk per IP+fingerprint | MemoryRiskStore | Clear RiskKey triple (IP, FP, session) | Risk lifecycle test passes |
| Challenge state | ChallengeStateStore (in-memory) | Clear issued challenges + tokens | New challenge required for same IP |
| Session tokens | SessionStore (in-memory) | Clear post-challenge sessions | Challenge token reuse fails |
| Response cache (Moka) | MokaStore (in-process) | `cache.invalidate_all()` | Next request MISS, not HIT |
| Response cache (Valkey) | ValkeyStore | `redis.flushdb()` or tag-based purge | Verify via Redis CLI |
| Behavioral anomaly state | BehaviorStore | Clear per-actor classifiers | Baseline resets |
| TX velocity state | TxStore | Clear velocity windows per path | Fresh velocity metrics |
| Device fingerprint identity | IdentityStore (memory or Redis) | Clear all fingerprint→IP mappings | IP hopping detection resets |
| CrowdSec decision cache | CrowdSecCache (in-memory or Redis) | Clear cached decisions | Next request re-queries CrowdSec |
| Community blocklist cache | CommunityCache (in-memory) | Clear cached verdicts | Cache misses on next request |
| In-flight request context | RequestCtx queue | Stabilize + complete all pending | No partial state visible |

**What NOT to clear:**
- Custom rule script bytecode (stable until hot-reload)
- OWASP CRS rules (stable until hot-reload)
- IP whitelist/blacklist tables (stable config)
- URL whitelist/blacklist tables (stable config)
- GeoIP database (stable reference)
- Relay/proxy intel feeds (stable reference)
- Rule store in WafEngine (stable until hot-reload)
- Request/block counters for stats (intentionally NOT cleared — benchmarker uses these for scoring)

---

## 5. TDD Test Matrix for §2 Compliance

### 5.1 Authentication Tests

| Test Name | Input | Expected | Assertion |
|-----------|-------|----------|-----------|
| `test_missing_secret_header` | No `X-Benchmark-Secret` header | 403 Forbidden | Status code, JSON error body |
| `test_invalid_secret_value` | `X-Benchmark-Secret: wrong-value` | 403 Forbidden | Status code, no response body leak |
| `test_correct_secret` | `X-Benchmark-Secret: waf-hackathon-2026-ctrl` | 200 OK (varies by endpoint) | Proceeds to business logic |
| `test_case_sensitive_secret` | `X-Benchmark-Secret: WAF-HACKATHON-2026-CTRL` | 403 Forbidden | Secret match is case-sensitive |

---

### 5.2 GET /__waf_control/capabilities Tests

| Test Name | Setup | Input | Expected | Assertion |
|-----------|-------|-------|----------|-----------|
| `test_capabilities_schema_valid` | Fresh start | Valid secret header | 200 OK JSON | `ok`, `features`, `active` all present |
| `test_capabilities_features_not_empty` | Fresh start | Valid secret header | All detection features in response | At least 10+ features present |
| `test_capabilities_policies_not_empty` | Fresh start | `injection_control` feature | Policies array non-empty | `["xss", "sqli", "rce"]` or equivalent |
| `test_capabilities_toggleable_true` | Fresh start | Any feature | `toggleable: true` for all | Every feature supports mode switching |
| `test_capabilities_supported_true` | Fresh start | Any feature | `supported: true` for all | No stubs in baseline |
| `test_capabilities_default_mode_enforce` | Fresh start | Valid secret | `active.default_mode: "enforce"` | Startup default correct |
| `test_capabilities_overrides_empty_on_startup` | Fresh start, no prior `set_profile` | Valid secret | `active.overrides: {}` | No stale state |
| `test_capabilities_after_set_profile` | After `set_profile` with scope="features", mode="log_only", features=["access_control"] | Valid secret | `active.overrides.access_control: "log_only"` | Override persists in response |
| `test_capabilities_policy_override_in_active` | After `set_profile` with policy override | Valid secret | `active.overrides["access_control.blacklist"]: "log_only"` | Policy override uses dot notation |
| `test_capabilities_feature_name_stability` | Run capabilities twice within 1 second | Valid secret | Feature names identical both times | No UUID/timestamp in names |

---

### 5.3 POST /__waf_control/reset_state Tests

| Test Name | Setup | Input | Expected | Assertion |
|-----------|-------|-------|----------|-----------|
| `test_reset_state_schema_valid` | Fresh start | Valid secret | 200 OK JSON | `ok: true`, `action: "reset_state"`, `audit_log_preserved: true`, `ts_ms` present |
| `test_reset_state_audit_log_preserved` | Send requests, call reset | Valid secret | Success response | `waf_audit.log` file size unchanged; no lines removed |
| `test_reset_state_ts_ms_is_epoch_ms` | Fresh start | Valid secret | Response `ts_ms` field | Timestamp in range [1_700_000_000_000, current time] |
| `test_reset_state_clears_rate_limit` | Hit rate limit (10 req/sec), then reset | Valid secret | Next request not rate-limited | RateLimitStore.reset_all() called |
| `test_reset_state_clears_ddos_ban` | Trigger DDoS ban, then reset | Valid secret | Banned IP no longer banned | DynamicBanTable.clear_all() called |
| `test_reset_state_clears_risk_score` | Build risk score to 50+, then reset | Valid secret | `X-WAF-Risk-Score: 0` on next request | RiskStore.reset_all() called |
| `test_reset_state_clears_response_cache` | Cache a response (HIT), then reset | Valid secret | Next identical request returns MISS | Moka/Valkey cache flushed |
| `test_reset_state_clears_challenge_state` | Issue challenge, then reset | Valid secret | Next request not challenged | Challenge tokens invalidated |
| `test_reset_state_clears_tx_velocity` | Build TX velocity counter, then reset | Valid secret | Next request has zero velocity | TxStore.reset_all() called |
| `test_reset_state_does_not_clear_rules` | Load custom rules (COUNT=5), reset, check COUNT | Valid secret | Rule count unchanged | Custom rule cache not flushed |
| `test_reset_state_atomic_synchronized` | Spawn 10 reset requests in parallel | Valid secret | All return 200 OK in order | No race conditions; single atomic operation |
| `test_reset_state_blocks_requests_during_reset` | Send request during reset | Valid secret | Request either queued or rejected | No partial state visible after reset completes |

---

### 5.4 POST /__waf_control/set_profile Tests

#### 5.4.1 scope="all" Tests

| Test Name | Input | Expected | Assertion |
|-----------|-------|----------|-----------|
| `test_set_profile_all_enforce` | `scope: "all", mode: "enforce"` | 200 OK | `default_mode: "enforce"`, `overrides: {}` |
| `test_set_profile_all_log_only` | `scope: "all", mode: "log_only"` | 200 OK | `default_mode: "log_only"`, `overrides: {}` |
| `test_set_profile_all_clears_prior_overrides` | Prior policy override, then scope="all" mode="enforce" | 200 OK | `overrides: {}` (prior overrides cleared) |
| `test_set_profile_all_applied_fields` | `scope: "all", mode: "log_only"` | 200 OK JSON | `applied.scope: "all"`, `applied.features` absent, `applied.policies` absent |

#### 5.4.2 scope="features" Tests

| Test Name | Input | Expected | Assertion |
|-----------|-------|----------|-----------|
| `test_set_profile_features_single` | `scope: "features", mode: "log_only", features: ["access_control"]` | 200 OK | `applied.features: ["access_control"]`, `overrides.access_control: "log_only"` |
| `test_set_profile_features_multiple` | `scope: "features", mode: "log_only", features: ["access_control", "rate_limiting"]` | 200 OK | Both in `applied.features`, both in `overrides` |
| `test_set_profile_features_unmodified_remain_unchanged` | Prior feature override for F1; scope="features" F2 log-only | 200 OK | F1 override unchanged; F2 override added |
| `test_set_profile_features_missing_feature` | `features: ["nonexistent"]` | 200 OK | `unsupported: ["nonexistent"]`, `applied.features: []` |
| `test_set_profile_features_mixed_valid_invalid` | `features: ["access_control", "nonexistent"]` | 200 OK | `applied.features: ["access_control"]`, `unsupported: ["nonexistent"]` |

#### 5.4.3 scope="policies" Tests

| Test Name | Input | Expected | Assertion |
|-----------|-------|----------|-----------|
| `test_set_profile_policies_single` | `scope: "policies", feature: "injection_control", policies: ["xss"], mode: "log_only"` | 200 OK | `applied.feature: "injection_control"`, `applied.policies: ["xss"]`, `overrides["injection_control.xss"]: "log_only"` |
| `test_set_profile_policies_multiple` | `feature: "injection_control", policies: ["xss", "sqli"], mode: "log_only"` | 200 OK | Both in `applied.policies`, both in `overrides` with dot notation |
| `test_set_profile_policies_other_policies_unchanged` | Prior RCE log-only; set XSS log-only | 200 OK | RCE override unchanged; XSS override added |
| `test_set_profile_policies_feature_not_found` | `feature: "nonexistent", policies: ["p1"]` | 400 or lenient 200 with unsupported | Consistent behavior throughout run |
| `test_set_profile_policies_policy_not_found` | `feature: "injection_control", policies: ["nonexistent"]` | Lenient 200 OK | `unsupported: ["injection_control.nonexistent"]`, `applied.policies: []` |

#### 5.4.4 Field Validation Tests

| Test Name | Input | Expected | Assertion |
|-----------|-------|----------|-----------|
| `test_set_profile_missing_scope` | No `scope` field | 400 Bad Request | Error message or empty response |
| `test_set_profile_invalid_scope` | `scope: "invalid"` | 400 Bad Request | Scope not in ["all", "features", "policies"] |
| `test_set_profile_invalid_mode` | `mode: "invalid"` | 400 Bad Request | Mode not in ["enforce", "log_only"] |
| `test_set_profile_features_scope_missing_features_array` | `scope: "features", mode: "log_only"` (no features field) | 400 Bad Request | Features array required for this scope |
| `test_set_profile_policies_scope_missing_feature` | `scope: "policies", policies: ["xss"]` (no feature field) | 400 Bad Request | Feature field required for this scope |
| `test_set_profile_policies_scope_missing_policies` | `scope: "policies", feature: "injection_control"` (no policies field) | 400 Bad Request | Policies array required for this scope |

#### 5.4.5 Response Schema Tests

| Test Name | Input | Expected | Assertion |
|-----------|-------|----------|-----------|
| `test_set_profile_response_has_all_fields` | Any valid request | 200 OK | Response has `ok`, `action: "set_profile"`, `applied`, `active`, `unsupported`, `ts_ms` |
| `test_set_profile_response_unsupported_always_array` | Mix of valid + invalid features | 200 OK | `unsupported` is always array (never null) |
| `test_set_profile_response_active_always_present` | Any valid request | 200 OK | `active.default_mode` and `active.overrides` always in response |
| `test_set_profile_response_applied_scope_matches_request` | `scope: "features"` | 200 OK | `applied.scope: "features"` matches request scope |

#### 5.4.6 Edge Case Tests

| Test Name | Input | Setup | Expected | Assertion |
|-----------|-------|-------|----------|-----------|
| `test_set_profile_concurrent_requests` | 5 parallel set_profile calls | Different features | 200 OK for all | All requests succeed without race condition |
| `test_set_profile_after_reset_state` | Call reset_state, then set_profile | Valid secrets | 200 OK | overrides empty after reset; set_profile applied cleanly |
| `test_set_profile_idempotent` | Same set_profile called twice | Valid secret | Same response both times | Idempotent (no side effects on re-run) |
| `test_set_profile_mode_override_precedence` | Set feature mode, then policy mode under same feature | Both valid | Policy override takes precedence | `X-WAF-Mode` reflects policy mode in request evaluation |

---

### 5.5 POST /__waf_control/flush_cache Tests

| Test Name | Setup | Input | Expected | Assertion |
|-----------|-------|-------|----------|-----------|
| `test_flush_cache_schema_valid` | Cache enabled | Valid secret | 200 OK JSON | `ok: true`, `action: "flush_cache"`, `ts_ms` present |
| `test_flush_cache_clears_moka` | Response cached in Moka | Valid secret | Success | Next identical request returns `X-WAF-Cache: MISS` |
| `test_flush_cache_clears_valkey` | Response cached in Valkey | Valid secret | Success | Redis keys for cache entries deleted |
| `test_flush_cache_concurrent_requests` | Send 10 flush calls in parallel | Valid secrets | All return 200 OK | Atomic cache flush, no data corruption |
| `test_flush_cache_not_implemented_if_disabled` | Cache disabled in config | Valid secret | 200 OK or 501 Not Implemented | Consistent behavior (either works or not-implemented) |

---

### 5.6 Observability Header Correlation Tests

| Test Name | Setup | Input | Expected | Assertion |
|-----------|-------|-------|----------|-----------|
| `test_xwaf_mode_matches_active_override` | `set_profile` feature="injection_control" policy="xss" mode="log_only" | XSS payload | `X-WAF-Mode: log_only` in response | Header reflects active policy mode |
| `test_xwaf_mode_matches_default_mode` | No overrides; `default_mode: "enforce"` | Any valid request | `X-WAF-Mode: enforce` | Default mode in header |
| `test_xwaf_action_matches_set_profile_intent` | `mode: "log_only"` for SQLi; SQLi payload | Send SQLi | `X-WAF-Action: block`, `X-WAF-Mode: log_only` | Intended action reported; enforcement not applied |
| `test_xwaf_request_id_matches_audit_log` | Send request, `set_profile` mode="log_only" | Any request | `X-WAF-Request-Id` in header matches `request_id` in audit log | Request correlation |

---

## 6. Authentication & Authorization

### 6.1 Control Endpoint Protection

**Requirement (§2.2):**
- All four endpoints under `/__waf_control/*` MUST require header: `X-Benchmark-Secret: waf-hackathon-2026-ctrl`
- Missing or invalid secret → `403 Forbidden`
- NO JWT required (control plane is **not** admin API)
- NO IP allowlist required (contract doesn't specify — assume anyone with secret key can call)
- Treat as **untrusted input** — validate all request fields

### 6.2 Implementation Approach (Axum)

```rust
// Middleware layer
async fn require_benchmark_secret(
    req: Request,
    next: Next,
) -> Response {
    let secret = req
        .headers()
        .get("X-Benchmark-Secret")
        .and_then(|h| h.to_str().ok());

    if secret != Some("waf-hackathon-2026-ctrl") {
        return Response::builder()
            .status(StatusCode::FORBIDDEN)
            .json(json!({ "ok": false, "error": "invalid secret" }))
            .unwrap();
    }

    next.run(req).await
}

// Router setup
let control_routes = Router::new()
    .route("/capabilities", get(get_capabilities))
    .route("/reset_state", post(reset_state))
    .route("/set_profile", post(set_profile))
    .route("/flush_cache", post(flush_cache))
    .layer(middleware::from_fn(require_benchmark_secret));
```

---

## 7. Atomic & Synchronous Requirements

### 7.1 reset_state Synchronicity

**Contract requirement (§2.4 §117):** `reset_state` MUST be synchronous and atomic.

**Implementation checklist:**
- [ ] Rate limit store reset blocks until done (no async background task)
- [ ] DDoS ban table cleared synchronously
- [ ] Risk score store reset blocks; no deferred cleanup
- [ ] Cache flush waits for completion (Valkey FLUSHDB, Moka invalidate_all)
- [ ] Device FP identity store cleared before response
- [ ] All in-flight requests completed or queued (no partial state visible)
- [ ] Lock released only after all subsystems fully reset

**Anti-pattern:**
- `tokio::spawn()` background task for cache flush → returns before flush completes → FAIL
- Async reset without await → returns before done → FAIL

### 7.2 set_profile Atomicity

**Implicit requirement (§2.5):** Profile changes must be atomic to prevent partial state visibility.

**Implementation:**
- Guard `active.overrides` with `Arc<Mutex<ProfileState>>`
- Acquire lock, update, release lock
- No partial updates visible between requests

---

## 8. Unresolved Questions & Notes

1. **Custom rule policy granularity:** Should each custom rule (rule-001, rule-002, ...) be a separate policy? Or group all custom rules under single policy? **Recommendation:** Individual policies per rule for benchmarker control.

2. **OWASP CRS policy granularity:** Each OWASP rule ID (owasp-921110, owasp-921120, ...) as separate policy? Or group by category? **Recommendation:** By category (owasp_injection, owasp_protocol, etc.) for tractability.

3. **Error response body for unsupported features:** Should strict mode return JSON error body? **Contract allows both.** **Recommendation:** Lenient mode (200 OK with `unsupported` array) — better for benchmarker UX.

4. **Cache flush with multiple backend layers:** If both Moka + Valkey, must BOTH be flushed? **Yes.** `flush_cache` clears all layers atomically.

5. **Device FP identity store reset scope:** Should reset clear only current-run fingerprints, or all historical? **Contract intent:** Current run only. Use run-scoped namespace in Redis (e.g., key prefix with run UUID).

6. **Benchmark secret rotation:** Can secret be changed at runtime? **No.** Static secret for entire run.

7. **Control endpoint rate limiting:** Should `/__waf_control/*` be rate-limited? **No.** Control plane is separate; assume admin-only access.

8. **Audit log append semantics:** Can `reset_state` append a log entry indicating reset occurred? **Yes.** Contract says "append-only," not "no modifications ever."

---

## 9. Implementation Decisions Summary

| Decision | Rationale | Verification |
|----------|-----------|----------|
| Single static secret (`X-Benchmark-Secret`) for all control endpoints | Contract §2.2 specifies exact header; simplifies auth | Header middleware test |
| Feature/policy hierarchical naming (dot notation `feature.policy`) | Contract §2.5 uses this notation in examples | JSON schema validation test |
| Lenient unsupported handling (200 OK with unsupported array) | Better benchmarker UX; contract allows both | Unsupported array test |
| Synchronous atomic `reset_state` (no background tasks) | Contract §2.4 §117 explicit | Integration test: verify all stores reset before response |
| Rate limit + DDoS + risk scope in reset_state | Engine.rs structure; contract "temporary runtime state" | Reset matrix test |
| Stable feature/policy names (no UUIDs/timestamps) | Contract §2.3 "stable within benchmark run" | Capabilities endpoint test x2 within 1sec |
| Policy mode precedence (final policy's mode in `X-WAF-Mode`) | Contract §2.7; allows multi-match scenarios | Integration test: SQLi + XSS, different modes |

---

## 10. Test Execution Order (TDD Sequencing)

1. **Unit: Auth tests** (missing/invalid secret)
2. **Unit: Schema validation** (JSON structure)
3. **Integration: Capabilities discovery** (feature list, stability)
4. **Integration: set_profile all scopes** (feature, policy, all)
5. **Integration: set_profile unsupported** (missing features/policies)
6. **Integration: reset_state clears each subsystem** (rate limit, DDoS, risk, cache, etc.)
7. **Integration: flush_cache clears both backends** (Moka + Valkey)
8. **Integration: Correlation** (X-WAF-Mode matches active override; request ID in audit log)
9. **Concurrent: reset_state + set_profile race conditions** (5+ parallel calls)
10. **Acceptance: Full lifecycle** (capabilities → set_profile → request evaluation → reset → verify cleared)

---

## Summary

**Exact JSON schemas, feature mapping, edge case analysis, and 70+ test cases documented above provide complete spec for implementing § 2 compliance.**

**Next step:** Delegate to implementation team with:
1. Feature/policy catalog (Section 2.1–2.2)
2. Exact response schemas (Section 1)
3. TDD test matrix (Section 5)
4. Auth + atomicity requirements (Sections 6–7)

