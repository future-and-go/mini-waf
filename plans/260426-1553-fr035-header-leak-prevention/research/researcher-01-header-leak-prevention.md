# FR-035: HTTP Response Header Leak Prevention — Research Report

**Date:** 2026-04-26  
**Scope:** Standards, implementation patterns, test vectors, PII patterns for WAF header stripping  
**Target:** Rust WAF (Pingora-based) implementing response header leak detection/blocking

---

## 1. HEADER TAXONOMY: WHAT TO STRIP

### 1.1 Information Disclosure Categories (OWASP Secure Headers Project)

**Server Fingerprinting Headers** — identify technologies, versions, runtime versions to enable targeted exploits:
- `Server` (e.g., "Apache/2.4.41") — explicit server type & version
- `X-Powered-By` (e.g., "PHP/7.4.3", "Express") — application framework
- `X-AspNet-Version` — .NET version fingerprint
- `X-Runtime` — Ruby/Rails runtime info
- `Via` — intermediary proxy identification (hop-by-hop, RFC 9110 §7.6)
- `X-Generator` — CMS/framework identifier (Drupal, Magento, WordPress)

**Debug/Internal Headers** — expose internal routing, backends, caches:
- `X-Debug-*` (family) — debug flags, execution time, memory
- `X-Internal-*` (family) — internal IPs, backend names, routing decisions
- `X-Backend-*` — backend server identification
- `X-Cache`, `X-Cache-Status` — caching layer exposure (when leaking implementation)
- `X-Varnish` — Varnish cache layer identification
- `X-Served-By`, `X-Push` — CDN/infrastructure detail

**Error/Exception Headers** — expose stack traces, code paths, system state:
- `X-Error-*` (family)
- `X-Exception-*` (family)
- `X-Stack-Trace` — dangerous; direct code exposure
- `X-Request-ID` (conditional) — when leaking internal correlation IDs with PII

**Real Client IP Headers** — expose internal IPs when proxied:
- `X-Real-IP` — claimed real client IP; spoofable, can leak internal addresses
- `X-Forwarded-For` — list of IPs through proxy chain; untrustworthy, can contain internal IPs
- `X-Forwarded-Server` — claimed origin server hostname (often internal)

**PII-bearing Custom Headers** — project-specific risk:
- `X-User-ID`, `X-User-Email` — direct PII in headers
- `X-Session-Token` — authentication material in response (wrong place; should be Set-Cookie)
- `X-Auth-Token` — similar risk

**Sources:** [OWASP Secure Headers Project](https://owasp.org/www-project-secure-headers/), [OWASP HTTP Headers Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/HTTP_Headers_Cheat_Sheet.html), [ZAP Alert 10037 (X-Powered-By)](https://www.zaproxy.org/docs/alerts/10037/)

---

## 2. CONSOLIDATED DEFAULT STRIP LIST

**Recommended minimum set to remove from ALL responses (regardless of status code):**

```
Server
X-Powered-By
X-AspNet-Version
X-Runtime
X-Generator
X-Drupal-Cache
X-Magento-Cache-Id
X-Varnish
X-Cache
X-Cache-Status
X-Served-By
X-Debug
X-Exception
X-Stack-Trace
X-Request-ID (if contains sensitive correlation info)
X-Real-IP
X-Forwarded-For (on response; note: common in reverse proxy output)
X-Forwarded-Server
X-Forwarded-Host
X-Forwarded-Proto (conditional: safe if value is https/http only)
```

**Optional / Project-Specific:**
- `X-Backend-*` (if backend hostnames are internal secrets)
- `X-User-ID`, `X-User-Email`, `X-Session-Token` (if ever leaked in responses)
- Custom project headers starting with `X-Internal-*`

**NOTE:** RFC 9110 §7.6 distinguishes **hop-by-hop** headers (Connection, Max-Forwards, TE, Transfer-Encoding, Upgrade, Proxy-Authenticate, Proxy-Authorization, Age, Cache-Control, Expires, Date) — proxies MUST NOT forward these. Do NOT strip them in response path (proxy core handles this).

**Source:** [RFC 9110 §7.6.1 Hop-by-Hop](https://www.rfc-editor.org/rfc/rfc9110.html), [OWASP ASVS v4 V14.4](https://github.com/OWASP/ASVS/blob/master/4.0/en/0x22-V14-Config.md)

---

## 3. PII PATTERN CATALOG FOR HEADER VALUES

Headers to scan in VALUES (not just names) for embedded PII:

### 3.1 Email Detection
- Regex: `[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}`
- Example leaks: `X-User-Email: user@internal.corp`, `Location: /profile?email=attacker@example.com`

### 3.2 Phone Numbers
- Regex: `\+?[1-9]\d{1,14}` (E.164 format) or local patterns (e.g., `\d{3}-\d{3}-\d{4}`)
- Example: `X-Debug-Phone: 555-123-4567`

### 3.3 Internal IP Addresses (IPv4)
- Ranges: `10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`, `127.0.0.0/8` (loopback)
- Regex: `(10|172|192)\.\d{1,3}\.\d{1,3}\.\d{1,3}|127\.\d{1,3}\.\d{1,3}\.\d{1,3}`
- Example: `X-Real-IP: 192.168.1.100`, `X-Backend: 10.0.1.50`

### 3.4 IPv6 Loopback / Link-Local
- Patterns: `::1`, `fe80::`, `fc00::`
- Example: `X-Internal-Backend: [::1]:8080`

### 3.5 JWT / Bearer Tokens
- Regex: `Bearer eyJ[A-Za-z0-9_-]*\.[A-Za-z0-9_-]*\.[A-Za-z0-9_-]*` or raw JWT pattern
- Risk: Token contains base64-encoded PII (email, claims) without encryption; attackers decode payload
- Example: `Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...` (contains user=alice@corp.com in payload)
- **Source:** [JWT PII Leakage via Payload](https://medium.com/@jhansi12.cs/finding-jwt-tokens-that-lead-to-pii-data-leakage-247829f27610)

### 3.6 Session/API Keys
- Patterns: 32+ hex/alphanumeric strings in value
- Regex: `[a-f0-9]{32,}|sk_live_[A-Za-z0-9]{32,}`
- Example: `X-Session-Token: a1b2c3d4e5f6...` (64 chars of hex)

### 3.7 Database Identifiers / Internal Resource IDs
- Suspicious if numeric or UUID in non-public context
- Example: `X-DB-User: user_5432`, `X-Internal-ID: 550e8400-e29b-41d4-a716-446655440000`

### 3.8 Credit Card Numbers (PCI-DSS Concern)
- Regex: `\b(?:\d{4}[ -]?){3}\d{4}\b` (16-digit card)
- Should never appear in headers but check if backend misbehaves

### 3.9 Social Security Numbers (US)
- Regex: `\d{3}-\d{2}-\d{4}` (XXX-XX-XXXX format)

**Note:** OWASP CWE-200 / CWE-209 emphasize error responses leak more PII than normal responses. Prioritize scanning error headers (4xx, 5xx responses, custom error detail headers).

**Sources:** [CWE-200](https://cwe.mitre.org/data/definitions/200.html), [CWE-209](https://cwe.mitre.org/data/definitions/209.html), [Huntress CWE-200 Analysis](https://www.huntress.com/threat-library/weaknesses/cwe-200-information-exposure)

---

## 4. IMPLEMENTATION GUIDANCE

### 4.1 Case-Insensitive Header Matching (RFC 9110)

**Requirement:** RFC 9110 mandates header field names are case-insensitive.

**Implementation:**
1. Normalize header name to **lowercase** at ingestion
2. Store strip list in lowercase: `vec!["server", "x-powered-by", ...]`
3. Compare normalized name to list (e.g., `header.name.to_lowercase() == "server"`)
4. Do NOT strip based on partial matches unless using prefix pattern (see 4.2)

**Pitfall:** Naive exact-match strips on `Server` but miss `server` or `SERVER` — unsafe.

**Rust pattern (Pingora):**
```rust
let normalized = header_name.to_ascii_lowercase();
if STRIP_LIST.contains(&normalized.as_str()) {
    response.remove_header(&header_name)?; // use original case for removal
}
```

**Source:** [RFC 9110 §17.10 Case-Insensitive Matching](https://www.rfc-editor.org/rfc/rfc9110.html), [Mastering Case-Insensitive HTTP Headers](https://runebook.dev/en/docs/http/rfc9110/section-17.10)

### 4.2 Prefix-Based Stripping for Families (X-Debug-*, X-Internal-*)

**Pattern:** Match header names starting with specific prefixes (case-insensitive).

**Rationale:** Avoids hardcoding every variant (X-Debug-Memory, X-Debug-Time, X-Debug-SQL, etc.).

**Implementation:**
```rust
const STRIP_PREFIXES: &[&str] = &["x-debug-", "x-internal-", "x-error-", "x-exception-"];

fn should_strip(name: &str) -> bool {
    let normalized = name.to_ascii_lowercase();
    STRIP_LIST.contains(normalized.as_str()) ||
    STRIP_PREFIXES.iter().any(|p| normalized.starts_with(p))
}
```

**Testing:** Verify both `X-Debug-Foo` and `x-debug-bar` and `X-DEBUG-BAZ` are caught.

### 4.3 Multivalue Header Handling

**Context:** Some headers allow comma-separated values (e.g., `Set-Cookie` is NOT comma-separated per RFC; `Accept` IS).

**Risk:** Stripping logic must handle:
1. Single value: `Server: Apache/2.4`
2. Multiple instances of same header name (appended by proxies): `X-Forwarded-For: 10.0.1.1, 10.0.1.2`

**Guidance:**
- Remove entire header if name matches, regardless of value count
- Do NOT attempt to parse/split values to conditionally remove (too complex, error-prone)
- If value scanning for PII (section 3): scan entire comma-delimited value as one string, or split and scan each part

**Example:** If `X-Forwarded-For: 192.168.1.1, attacker.com` contains internal IP, remove entire header, not just that value.

**Source:** [RFC 9110 §5.3 Header Field Order](https://www.rfc-editor.org/rfc/rfc9110.html)

### 4.4 Performance Optimization

**Context:** WAFs handle high throughput; regex scanning every header on every response is expensive.

**Strategies:**

1. **Allowlist (Safe-List) Approach (Recommended)**
   - Most common headers are safe (Content-Type, Content-Length, Date, Etag, Last-Modified, Cache-Control, Expires, etc.)
   - Only scan headers NOT in allowlist OR headers matching suspicious patterns
   - Pros: O(1) lookup, minimal regex
   - Cons: Requires periodic review as new headers emerge

2. **Early-Exit Pattern**
   - Check header name against strip list first (fast)
   - Only if name is suspicious (X-*, custom), then scan value for PII
   - Avoids regex on every header

3. **Compiled Regex Once**
   - Pre-compile regex patterns at initialization, not per-request
   - Use lazy_static or OnceCell to cache patterns

4. **Conditional Value Scanning**
   - Scan values for PII only on:
     - Error responses (4xx, 5xx)
     - Custom X-* headers
     - Headers known to sometimes carry sensitive data (Location, Set-Cookie for tokens, Authorization if in response)
   - Skip safe content headers (Content-Type: "text/plain", Content-Length: "1234")

**Benchmarking:** Measure stripping overhead on typical responses (assume 15–25 headers). Target <1ms per response.

**Sources:** Production experience from [Cloudflare Transform Rules](https://developers.cloudflare.com/rules/transform/response-header-modification/), [ModSecurity CRS](https://github.com/coreruleset/coreruleset)

### 4.5 Ordering & Filter Phase

**HTTP Processing Phases (Pingora):**
1. Receive response from backend
2. Apply WAF response filters (header stripping happens HERE)
3. Return to client

**Order of Operations:**
- Strip leaky headers BEFORE returning response to client
- Do NOT strip headers before forwarding to backend (upstream is not client-facing)
- Apply stripping in response phase, not request phase

**Interaction with Other Rules:**
- HSTS (Strict-Transport-Security): Preserve — security-critical
- CSP (Content-Security-Policy): Preserve — security-critical
- X-Frame-Options: Preserve — security-critical
- Stripping does NOT interfere with these (separate concerns)

**Edge Case:** If backend returns `Server: CustomApp/1.0`, WAF strips it. If backend THEN returns error page with `<title>CustomApp Error</title>`, that's OK (body is harder to scan; focus on headers).

---

## 5. TEST SCENARIOS CHECKLIST

### 5.1 Positive Tests (Verify Stripping Works)

- [ ] `Server: Apache/2.4` → stripped
- [ ] `server: apache/2.4` (lowercase) → stripped
- [ ] `SERVER: APACHE/2.4` (uppercase) → stripped
- [ ] `X-Powered-By: PHP/7.4` → stripped
- [ ] `X-Powered-By: Express` → stripped
- [ ] `X-Debug-Time: 0.042s` → stripped
- [ ] `X-Internal-Backend: 192.168.1.50` → stripped
- [ ] `X-Exception-Message: NullPointerException at line 45` → stripped
- [ ] Multiple instances of same header (via proxy): `X-Forwarded-For: 10.0.1.1, 10.0.1.2` → stripped
- [ ] `X-Debug-Custom-Foo: bar` (prefix match) → stripped
- [ ] `X-Internal-Request-ID: req_12345` (prefix match) → stripped

### 5.2 Negative Tests (Verify Safe Headers Preserved)

- [ ] `Content-Type: application/json` → preserved
- [ ] `Content-Length: 1024` → preserved
- [ ] `Date: Mon, 26 Apr 2026 12:00:00 GMT` → preserved
- [ ] `Cache-Control: max-age=3600` → preserved
- [ ] `Etag: "abc123"` → preserved
- [ ] `Strict-Transport-Security: max-age=31536000` → preserved
- [ ] `Content-Security-Policy: default-src 'self'` → preserved
- [ ] `X-Frame-Options: DENY` → preserved
- [ ] `Set-Cookie: sessionid=...` → preserved (unless scanning for leaked tokens)
- [ ] `Location: /redirect` → preserved (unless value has suspicious pattern)

### 5.3 PII Detection Tests

- [ ] `X-User-Email: alice@corp.com` → detected & stripped (or flagged)
- [ ] `X-Debug-Phone: +1-555-123-4567` → detected & stripped
- [ ] `X-Real-IP: 192.168.1.100` → internal IP detected & stripped
- [ ] `X-Internal-Backend: [::1]:8080` (IPv6 loopback) → detected & stripped
- [ ] `Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...` (JWT in response) → detected & stripped
- [ ] `X-Session-Token: a1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6` → detected & stripped
- [ ] `Location: /profile?email=user@company.com` (PII in query) → consider flag (may not strip URL)

### 5.4 Edge Cases

- [ ] Response with no headers → no error
- [ ] Response with 1000+ headers → completes <5ms
- [ ] Header value with newline injection attempt (`X-Foo: bar\r\nX-Injected: true`) → RFC 9110 rejects/sanitizes; WAF processes safely
- [ ] Empty header name `""` → no crash
- [ ] Very long header value (8KB) → scans without DoS
- [ ] Header name with null bytes → RFC 9110 invalid; dropped before WAF
- [ ] Response with `Via: proxy1.internal, proxy2.internal` (Via is hop-by-hop) → do NOT strip (proxy handles)
- [ ] Status 204 (No Content) with erroneous `Server` header → strip even if no body

### 5.5 Scanner Detection

**Tools that check for information disclosure via headers:**

- **OWASP ZAP:** Passive scan rule `Server Leaks Information via X-Powered-By` (Alert 10037)
- **Burp Suite:** Checks for Server, X-Powered-By, X-AspNet-Version, X-Runtime in responses
- **Mozilla Observatory:** Flags presence of informative Server, X-Powered-By, X-AspNet-Version (grade penalty)
- **Nikto:** Plugin `000005` checks for Server identification

**Test:** Run response through [Mozilla Observatory](https://developer.mozilla.org/en-US/observatory) or Burp Repeater after WAF deployment; verify no such headers present.

**Sources:** [OWASP ZAP Alert 10037](https://www.zaproxy.org/docs/alerts/10037/), [Mozilla Observatory](https://developer.mozilla.org/en-US/observatory), [Burp Suite Testing](https://portswigger.net/burp/documentation)

---

## 6. IMPLEMENTATION REFERENCES BY TOOL

### 6.1 ModSecurity (Apache/Nginx)

**Directive:** `SecRule` with `id`, `chain`, and `setenv` to trigger removal; or use `Header` directive in Apache.

**Example (Apache + ModSecurity):**
```
SecRule RESPONSE_HEADERS:Server ".*" "id:1001,phase:3,setenv:remove_server,log"
Header always unset Server env=remove_server
```

**Limitation:** [ModSecurity v2.9.3 on Nginx inadvertently strips ALL custom response headers](https://github.com/SpiderLabs/ModSecurity/issues/1993); use v3.x or apply patches.

**Source:** [ModSecurity Reference Manual (v3.x)](https://github.com/owasp-modsecurity/ModSecurity/wiki/Reference-Manual-(v3.x))

### 6.2 Nginx + headers-more Module

**Directive:** `more_clear_headers` (wildcard support).

**Example:**
```nginx
more_clear_headers "Server";
more_clear_headers "X-Powered-By";
more_clear_headers "X-Debug-*";  # Wildcard prefix
```

**Limitation:** Cannot remove `Connection` header (Nginx core generates it after filter runs).

**Source:** [NGINX Headers-More Module](https://github.com/openresty/headers-more-nginx-module), [GetPageSpeed Guide](https://www.getpagespeed.com/server-setup/nginx/nginx-headers-more-module)

### 6.3 Caddy

**Directive:** `header` with `-` prefix to remove.

**Example:**
```
header /* {
  -Server
  -X-Powered-By
  -X-Debug-*  # NOT wildcard; must enumerate
}
```

**Note:** Prefix matching not supported; enumerate each header or use `header_down` in reverse_proxy.

**Source:** [Caddy Documentation: header directive](https://caddyserver.com/docs/caddyfile/directives/header)

### 6.4 Envoy Proxy

**Field:** `response_headers_to_remove` (VirtualHost config).

**Example (YAML):**
```yaml
response_headers_to_remove:
  - Server
  - X-Powered-By
  - X-Debug-Time
  - X-Internal-Backend
```

**Limitation:** No wildcard or regex; must enumerate all headers.

**Source:** [Envoy HTTP Header Manipulation](https://www.envoyproxy.io/docs/envoy/latest/configuration/http/http_conn_man/headers)

### 6.5 Cloudflare Workers / Transform Rules

**Approach:** Transform Rules API for response header modification.

**Example:**
```
When hostname matches example.com
Remove response header "Server"
Remove response header "X-Powered-By"
```

**Limitation:** Cannot remove headers starting with `cf-` or `x-cf-`; cannot modify `server`, `eh-cache-tag`, or `eh-cdn-cache-control`.

**Source:** [Cloudflare Response Header Transform Rules](https://developers.cloudflare.com/rules/transform/response-header-modification/)

### 6.6 Coraza WAF (Go, ModSecurity-compatible)

**Approach:** Use SecLang rules (ModSecurity syntax) or Go API.

**Example (SecLang):**
```
SecRule RESPONSE_HEADERS:Server "@rx .*" "id:1001,phase:3,log,block,setenv:!remove_server"
SecRule RESPONSE_HEADERS:Server "@rx .*" "id:1002,phase:3,log,del_header:Server"
```

**Known Issue:** [Coraza-Caddy does not strip headers on WAF-triggered 403](https://github.com/corazawaf/coraza-caddy/issues/144); post-filter chain may not execute.

**Source:** [Coraza WAF GitHub](https://github.com/corazawaf/coraza), [OWASP Coraza Docs](https://www.coraza.io/)

---

## 7. SECURITY PITFALLS & MITIGATIONS

### 7.1 Case Sensitivity Bypass
**Pitfall:** Hardcode `header.name == "Server"` (exact match, case-sensitive).  
**Attack:** Attacker backend sends `server` or `SERVER`; bypass.  
**Mitigation:** Always `.to_lowercase()` before comparison (RFC 9110 mandate).

### 7.2 Prefix Mismatch for Families
**Pitfall:** Strip `X-Debug` but miss `X-Debug-Foo` or `X-DebugInfo`.  
**Attack:** Backend sends `X-DebugInfo: secret` or `X-Debug_Internal: ...`; leaks.  
**Mitigation:** Use prefix match for families (e.g., `starts_with("x-debug")` catches `x-debug*`); consider hyphen normalization.

### 7.3 Hop-by-Hop Header Confusion
**Pitfall:** Strip `Via`, `Max-Forwards`, or `Connection` (WAF removes what proxy layer should handle).  
**Attack:** Breaks HTTP semantics or causes unexpected behavior downstream.  
**Mitigation:** DO NOT strip hop-by-hop headers; RFC 9110 §7.6 reserves these for proxy.

### 7.4 Interaction with CORS / CSP Headers
**Pitfall:** Overzealous stripping removes `Access-Control-*` or `Content-Security-Policy` headers (security headers).  
**Attack:** Defeats CORS/CSP protections; enables XSS.  
**Mitigation:** Maintain allowlist of headers NOT to strip; treat CSP, HSTS, X-Frame-Options as sacred.

### 7.5 Regex DoS (ReDoS) in PII Scanning
**Pitfall:** Naive email regex like `.*@.*\..*` on unbounded header value.  
**Attack:** Attacker sends 1000-char header with backtracking-prone regex; CPU spike.  
**Mitigation:** Pre-compile regex, use bounded patterns (e.g., `[a-zA-Z0-9._%+-]{1,64}@[a-zA-Z0-9.-]{1,255}\.[a-zA-Z]{2,}`), test regex on long inputs.

### 7.6 Value Scanning Blind Spots
**Pitfall:** Scan header name for leaks but not value (e.g., `Location: /error?msg=database+connection+failed`).  
**Attack:** Backend sends `Location: /login?email=victim@corp.com`; WAF does not detect.  
**Mitigation:** Scan VALUES in high-risk headers (Location, Set-Cookie for tokens, custom X-* headers).

### 7.7 Error Response Context
**Pitfall:** Strip headers uniformly; do not prioritize error responses (4xx, 5xx leak more).  
**Attack:** Backend error page includes stack trace in `X-Stack-Trace` header.  
**Mitigation:** Aggressive scanning on 4xx/5xx responses; relax on 2xx (safe content).

### 7.8 Encoding Obfuscation
**Pitfall:** Email regex does not handle percent-encoded values (`user%40corp%2Ecom`).  
**Attack:** `X-User: user%40corp%2Ecom` (URL-encoded) bypasses regex.  
**Mitigation:** Decode common encodings (URL, Base64 if detected) before regex match; be cautious of false positives.

---

## 8. REGULATORY / STANDARDS CITATIONS

| Standard | Section | Requirement |
|----------|---------|-------------|
| [OWASP ASVS v4](https://github.com/OWASP/ASVS/blob/master/4.0/en/0x22-V14-Config.md) | V14.4 | HTTP response must not expose version info; headers must not leak details. |
| [CWE-200](https://cwe.mitre.org/data/definitions/200.html) | General | Exposure of Sensitive Information to Unauthorized Actor; banner grabbing, error detail leaks. |
| [CWE-209](https://cwe.mitre.org/data/definitions/209.html) | General | Generation of Error Message Containing Sensitive Information. |
| [RFC 9110](https://www.rfc-editor.org/rfc/rfc9110.html) | §7.6, §17.13 | Hop-by-hop headers, Disclosure of Product Information guidance. |
| [NIST SP 800-53](https://csrc.nist.gov/pubs/sp/800/53/r5/upd1/final) | SI-11 | Error Handling: Errors must not expose sensitive info; default messages in production. |
| [NIST SP 800-95](https://csrc.nist.gov/publications/detail/sp/800-95/final) | General | Guide to Secure Web Applications; recommends header scrubbing. |
| [Mozilla Web Security Guidelines](https://infosec.mozilla.org/guidelines/web_security) | HTTP | Remove Server, X-Powered-By; set security headers (CSP, HSTS). |

---

## 9. REFERENCE IMPLEMENTATIONS

| Tool | Mechanism | Source |
|------|-----------|--------|
| ModSecurity 3.x | SecRule + `del_header` action | [ModSecurity Wiki](https://github.com/owasp-modsecurity/ModSecurity/wiki/Reference-Manual-(v3.x)) |
| Nginx headers-more | `more_clear_headers` directive | [GitHub](https://github.com/openresty/headers-more-nginx-module) |
| Caddy | `header` directive with `-` prefix | [Caddyfile Docs](https://caddyserver.com/docs/caddyfile/directives/header) |
| Envoy | `response_headers_to_remove` field | [Envoy Docs](https://www.envoyproxy.io/docs/envoy/latest/configuration/http/http_conn_man/headers) |
| Cloudflare Workers | Transform Rules API | [Cloudflare Docs](https://developers.cloudflare.com/rules/transform/response-header-modification/) |
| Coraza WAF | SecLang `del_header` action | [Coraza GitHub](https://github.com/corazawaf/coraza) |

---

## 10. UNRESOLVED QUESTIONS

1. **Should WAF strip headers BEFORE or AFTER backend response body is captured for logging?**  
   - Implication: If stripping happens late, logs may include leaky headers.
   - Recommendation: Clarify whether response logging layer has access to stripped headers.

2. **For X-Forwarded-For / X-Real-IP: Should WAF distinguish between trusted (internal proxy) vs untrusted (client-controlled) values?**  
   - Implication: Stripping all instances loses legitimate debugging on internal architecture.
   - Recommendation: Consider conditional stripping (remove on external-facing response, keep on internal logs).

3. **What is the performance overhead tolerance for WAF header stripping on high-throughput deployments (10k+ RPS)?**  
   - Implication: Regex PII scanning may not be feasible on every header.
   - Recommendation: Benchmark regex vs allowlist approach; define max latency budget.

4. **Should WAF provide customizable strip lists (per-route, per-application)?**  
   - Implication: FR-035 may benefit from policy-based configuration rather than global lists.
   - Recommendation: Design extension points for policy rules.

5. **How to handle edge case where backend legitimately needs to send auth token in response header?**  
   - Implication: Blanket stripping of `Authorization` / `X-Session-Token` may break legitimate flows (rare).
   - Recommendation: Document that tokens should use Set-Cookie / response body, not headers; allow policy override if needed.

---

## SUMMARY

**Minimum Viable Implementation for FR-035:**

1. Maintain **lowercase-normalized strip list**: `["server", "x-powered-by", "x-aspnet-version", "x-runtime", ...]`
2. **Case-insensitive matching** on header names (RFC 9110 compliance)
3. **Prefix-based removal** for families (X-Debug-*, X-Internal-*, X-Error-*, X-Exception-*)
4. **Scan response headers (name + value)** for PII patterns on error responses (4xx, 5xx)
5. **Preserve security headers** (CSP, HSTS, X-Frame-Options, etc.)
6. **Avoid hop-by-hop interference** (Via, Connection, Max-Forwards handled by proxy)
7. **Test with Mozilla Observatory + OWASP ZAP** to validate no leaks; target <1ms overhead

**Maturity Risk:** Header stripping is well-established (ModSecurity, Nginx, Caddy, Envoy all support). PII pattern matching adds complexity; start with simple lists, iterate on false positives.

**Sources (Consolidated):**  
[OWASP Secure Headers](https://owasp.org/www-project-secure-headers/), [RFC 9110](https://www.rfc-editor.org/rfc/rfc9110.html), [CWE-200](https://cwe.mitre.org/data/definitions/200.html), [NIST SI-11](https://csf.tools/reference/nist-sp-800-53/r5/si/si-11/), [Cloudflare Transform Rules](https://developers.cloudflare.com/rules/transform/response-header-modification/), [Coraza WAF](https://github.com/corazawaf/coraza), [ModSecurity](https://github.com/owasp-modsecurity/ModSecurity)
