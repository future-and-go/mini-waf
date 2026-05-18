# Request Pipeline Documentation Update Report

**Date**: 2026-05-15 | **File**: `docs/request-pipeline.md` | **Lines**: 411 (under 800 LOC limit)

## Summary

Updated `docs/request-pipeline.md` to reflect actual WAF pipeline implementation based on code analysis of `crates/waf-engine/src/engine.rs`. Corrected phase numbering, added four undocumented security checks (SSRF, Header Injection, Brute Force, Body Abuse), and clarified early-path phases for optimal threat blocking order.

## Changes Made

### 1. **Phase Numbering Correction**
- Confirmed actual execution order from engine.rs (lines 494-751)
- Phase-0: IP/URL fast-path access control (unchanged)
- Phase 16a: CrowdSec Bouncer (early-path, before DDoS)
- Phase 18: Community Blocklist (early-path, before DDoS)
- Phase 17: GeoIP Access Control (early-path, before DDoS)
- **Phase 19**: DDoS Detection (moved to run BEFORE rate-limit, after fast-path)
- Phases 5-14: Main attack detection pipeline
  - Phase 5: Rate Limit
  - Phase 5.5: Transaction Velocity (FR-012)
  - Phases 6-14: Checkers run in pipeline order

### 2. **Added Undocumented Security Checks**

**Phase 11: SSRF Detection (FR-016)**
- Extracts http(s):// URLs from body, query, cookies, headers
- Detects cloud-metadata IPs, RFC1918, loopback, link-local
- Obfuscation handling: dword, hex, octal, IPv6-mapped forms
- v1 limitation: no DNS resolution (DNS-rebinding deferred)
- Source: `crates/waf-engine/src/checks/ssrf.rs`

**Phase 12: Header Injection Detection (FR-017)**
- CRLF injection detection in header name/value (response splitting)
- Host header validation against per-host inbound whitelist
- X-Forwarded-For sanity check (leftmost-private, excessive hop-count)
- v1 limitation: no SNI-vs-Host comparison (Red Team Finding #12)
- Source: `crates/waf-engine/src/checks/header_injection.rs`

**Phase 13: Brute Force Protection (FR-018)**
- Per-user login route failure tracking (user_hash, ip)
- Request phase: block if failure count >= bf_max_per_user
- Spray detection: block if password sprayed to >= bf_spray_threshold users
- Response phase: on_response() records 401/403 as login failures (status-code-only)
- v1 limitation: no body regex failure detection (security concerns)
- Source: `crates/waf-engine/src/checks/brute_force.rs`

**Phase 14: Request Body Abuse Detection (FR-020)**
- Oversized body check (declared Content-Length > max_body_size)
- Content-Type magic-byte sniff validation
- JSON depth pre-check (bails before parse if exceeds max_json_depth)
- JSON parse validation (failure → block)
- JSON key explosion check (cumulative key count vs max_json_keys)
- Source: `crates/waf-engine/src/checks/body_abuse.rs`

### 3. **Early-Path Optimization Clarification**

Updated documentation to show three early-path phases run before DDoS detection:
- **Phase 16a** (CrowdSec Bouncer): Cache lookup for known-bad IPs
- **Phase 17** (GeoIP): Block by country before rate-limit overhead
- **Phase 18** (Community Blocklist): Cross-org threat intel O(1) lookup
- **Phase 19** (DDoS): Only after fast rejections, before expensive checks

### 4. **SQL Injection Check Clarification**

Separated SQL injection documentation to note it runs:
- After Phase 14 (Body Abuse)
- Before Phase 16b (CrowdSec AppSec)
- With independent hot-reload (separate from main checker pipeline)

### 5. **Post-Pipeline Phase Reordering**

Clarified final checks after main pipeline (after Phase 14, SQLi, Phase 16b):
1. Custom Rules Engine (FR-003, user-defined logic)
2. OWASP CRS (24 pre-compiled patterns)
3. Sensitive Data Leakage
4. Anti-Hotlink Protection

Removed confusing "Phase X" labels in this section to avoid collision with early-path phase numbers.

### 6. **Updated Related Docs Section**

Added links to:
- `ddos-protection.md` for Phase 19
- `transaction-velocity.md` for Phase 5.5
- Inline notes for FR-016, FR-017, FR-018, FR-020

## Verification

- ✅ All phase numbers verified against engine.rs:494-751
- ✅ Checker pipeline order matches engine.rs initialization (lines 186-201)
- ✅ New checks (SSRF, Header Injection, Brute Force, Body Abuse) verified in codebase
- ✅ File size: 411 lines (under 800 LOC limit)
- ✅ No broken markdown links (all internal references valid)
- ✅ ASCII tree diagrams consistent with existing style

## Key Findings from Code Analysis

1. **DDoS runs BEFORE rate-limit** (engine.rs:539-556) — not after as initially documented
2. **Four new checks** added to checkers vector (engine.rs:186-201):
   - SsrfCheck (Phase 11)
   - HeaderInjectionCheck (Phase 12)
   - BruteForceCheck (Phase 13)
   - RequestBodyAbuseCheck (Phase 14)
3. **Early-path phases** (16a, 17, 18) run in specific order before DDoS to reject known threats fast
4. **SQLi check** runs separately for independent hot-reload (not in checkers vector)

## No Breaking Changes

- Documentation only — no code changes
- Reflects actual current implementation
- Helps developers understand real execution order
- Clarifies new undocumented features for operators

