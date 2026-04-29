# Phase 02 — Edge-Case Hardening

**Priority:** P0
**Status:** pending
**Depends on:** phase-01

## Goal

Close the residual attack/DoS surface left in PR-14: CRLF in header values (response splitting class), unbounded PII regex input (ReDoS surface), Set-Cookie carrying auth tokens (session-leak class), implicit assumption that hop-by-hop headers will never appear in `should_strip` checks. All hardening is unconditional once the master `outbound.enabled` is on — no new toggles for these.

## Context Links

- Existing impl: `crates/waf-engine/src/outbound/header_filter.rs`
- Pingora wiring: `crates/gateway/src/proxy.rs` `response_filter` (lines ~325-360)
- RFC 9110 §5.5 (field-value charset — CR/LF forbidden)
- RFC 9110 §7.6.1 (hop-by-hop list)
- CVE-2017-1000026 (Tomcat HTTP response splitting via CRLF in value) — vector this phase closes

## Files

**Modify:**
- `crates/waf-engine/src/outbound/header_filter.rs` — value-cap constant, CRLF check, hop-by-hop allowlist, Set-Cookie value scan
- `crates/gateway/src/proxy.rs` — pass through unchanged; the new logic lives in `HeaderFilter` so the hook code does not change

**Read for context:**
- `crates/waf-engine/src/outbound/header_filter.rs` — `filter_headers`, `detect_pii_in_value`, `should_strip` for integration shape

## Hardening Cases

### 1. PII scan input cap (closes ReDoS DoS)

```rust
/// Hard cap on input length passed to PII regex set.
/// Headers longer than this skip value-scan (still subject to name-based strip).
/// Chosen at 8 KiB — bigger than any realistic legitimate header, smaller than
/// pathological values an attacker could send to inflate regex backtracking cost.
const MAX_PII_SCAN_LEN: usize = 8 * 1024;

pub fn detect_pii_in_value(&self, value: &str) -> Option<&'static str> {
    if !self.detect_pii { return None; }
    if value.len() > MAX_PII_SCAN_LEN { return None; }
    // ... existing pattern walk ...
}
```

### 2. CRLF strip (closes response-splitting class)

Reject any header value containing `\r` or `\n`. RFC 9110 §5.5 forbids CR/LF in field-value; presence indicates CVE-2017-1000026-class injection or backend bug. Strip + warn.

```rust
pub fn has_crlf_injection(value: &str) -> bool {
    value.bytes().any(|b| b == b'\r' || b == b'\n')
}

// In filter_headers, before the should_strip check:
if has_crlf_injection(value) {
    tracing::warn!(
        "Outbound: stripping header {} — CRLF in value (CWE-93 / RFC 9110 §5.5 violation)",
        name
    );
    stripped.push(format!("{name} (CRLF injection)"));
    return false;  // drop from headers
}
```

### 3. Hop-by-hop allowlist (never strip these even if a future toggle matches)

```rust
/// RFC 9110 §7.6.1 hop-by-hop headers. Pingora handles these; we must never
/// strip them — doing so would break HTTP semantics for the next hop.
const HOP_BY_HOP_HEADERS: &[&str] = &[
    "connection",
    "keep-alive",
    "proxy-authenticate",
    "proxy-authorization",
    "te",
    "trailer",
    "transfer-encoding",
    "upgrade",
];

pub fn should_strip(&self, name: &str) -> bool {
    let lower = name.to_lowercase();
    if HOP_BY_HOP_HEADERS.contains(&lower.as_str()) {
        return false;  // never strip hop-by-hop
    }
    // ... existing logic ...
}
```

This is **belt-and-braces** — current strip lists do not include these names, but the guard prevents future const additions from accidentally introducing the bug.

### 4. Set-Cookie / ETag / Authorization value scan — operator-gated

`Set-Cookie` (session token), `ETag` (Spring Boot leaks classpath SHA), and `Authorization` (rare backend echo) all carry sensitive material. Stripping them on a PII regex match could kill a real user session on a false-positive — so the choice is **not** ours, it is the operator's.

Behaviour:
- These three header names form a hard-coded **session-protected set** (`SESSION_PROTECTED_HEADERS`).
- During `filter_headers`, when iterating, if the header name is in the protected set:
  - If `strip_session_headers_on_pii_match = true` AND `detect_pii_in_values = true` → run PII scan as normal; strip on match.
  - Else → skip the PII scan for these names (still subject to name-based strip rules, though none of these are in the strip lists).

Code sketch (added inside `filter_headers`, after the CRLF check, before the existing PII scan):

```rust
const SESSION_PROTECTED_HEADERS: &[&str] = &["set-cookie", "etag", "authorization"];

let lower = name.to_lowercase();
let is_session_protected = SESSION_PROTECTED_HEADERS.contains(&lower.as_str());

if is_session_protected && !self.strip_session_on_pii_match {
    return true;  // keep — operator did not opt in
}
```

Where `self.strip_session_on_pii_match: bool` is a new field on `HeaderFilter` populated from `HeaderFilterConfig::strip_session_headers_on_pii_match` in `HeaderFilter::new`.

### 5. ETag handling

Folded into case 4 — same gate applies.

### 6. Empty / malformed name no-panic

`should_strip("")` must return `false`. Current impl: `lower = "".to_lowercase()` → empty string; `strip_exact.contains("")` false; `strip_prefixes.iter().any(|p| "".starts_with(p))` returns true if any `p` is empty (none are; const lists all have content). Defensive guard:

```rust
if name.is_empty() { return false; }
```

at top of `should_strip`. Test in phase-03.

### 7. Multi-instance header behaviour

`Vec<(String, String)>` already preserves order and supports duplicates. `retain` removes per-pair, so `X-Forwarded-For: 10.0.1.1` and `X-Forwarded-For: 10.0.1.2` (two entries) both get evaluated and stripped. No code change needed; explicit test in phase-03.

## Implementation Steps

1. **Add** `MAX_PII_SCAN_LEN` const + length guard in `detect_pii_in_value`.
2. **Add** `has_crlf_injection` helper (private) and the CRLF guard inside `filter_headers`, before `should_strip`.
3. **Add** `HOP_BY_HOP_HEADERS` const and the early-return in `should_strip`.
4. **Add** `if name.is_empty() { return false; }` at top of `should_strip`.
5. **Add** `SESSION_PROTECTED_HEADERS` const, `strip_session_on_pii_match: bool` field on `HeaderFilter`, populate it from config, and gate Set-Cookie/ETag/Authorization PII scan accordingly inside `filter_headers`.
6. **Run** `cargo check -p waf-engine` then `cargo clippy --workspace --all-targets --all-features -- -D warnings`.
7. **Sanity-check** existing tests still green (no behavioural change for compliant inputs).

## Verification

- `cargo test -p waf-engine outbound::` — existing 19 tests still green.
- `cargo clippy ... -D warnings` clean.

## Risks & Mitigations

| Risk | Mitigation |
|------|-----------|
| CRLF guard rejects header injected as part of intentional cookie batching (very rare; not RFC-compliant) | RFC explicitly forbids; warn-log preserves visibility; operator can rebuild cookie via Pingora request_filter if needed |
| `MAX_PII_SCAN_LEN` set too low — misses real PII in long Authorization values | 8 KiB > any legitimate token; if a token is bigger, it is itself an anomaly — log-strip on name basis still applies |
| Hop-by-hop allowlist hides a future bug where someone DOES want to strip `Trailer` | We are not in that business — Trailer / Connection management belongs to the proxy core (Pingora), not WAF policy |
| `name.is_empty()` guard masks an upstream bug emitting empty-named headers | Pingora rejects malformed headers before they reach `response_filter`; guard is defensive only |

## Success Criteria

- [ ] `MAX_PII_SCAN_LEN = 8192` const added; `detect_pii_in_value` returns `None` past it
- [ ] `has_crlf_injection` helper exists; `filter_headers` strips + warns on CRLF
- [ ] `HOP_BY_HOP_HEADERS` const added; `should_strip` returns false for any of those
- [ ] `should_strip("")` returns false (defensive guard)
- [ ] `SESSION_PROTECTED_HEADERS` const + gating field added; Set-Cookie / ETag / Authorization preserved on PII match unless operator opts in
- [ ] `cargo clippy ... -D warnings` clean
- [ ] All existing tests still green

## Next

→ phase-03-tests-with-attack-vectors.md
