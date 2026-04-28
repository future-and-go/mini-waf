# FR-033 Response Body Content Filtering: Best Practices & Real-World Attacks
**Date:** 2026-04-28 | **Version:** 1.0 | **Status:** Research Complete

---

## Section 1: Best Practices for Response Body Sanitization

### Streaming vs. Full-Buffer Trade-Offs
Real WAFs (ModSecurity OWASP CRS, Cloudflare, AWS WAF, Imperva) face architectural tension between **low latency** (stream with finite buffer) and **comprehensive inspection** (full-buffer guarantee). AWS WAF enforces hard limits: 8–64 KB per body type (ALB=8KB, CloudFront/API GW=16KB default, up to 64KB increments). Cloudflare limits free tier at 8 KB; enterprise customers can configure truncation detection via `http.request.body.truncated`. **Decision:** FR-033 should adopt **bounded streaming** with configurable per-request limit (suggest 1–4 MB ceiling) rather than buffering entire payloads.

### Decompression at Edge
Most production WAFs (Snort `decompress_gzip`, Suricata `decompression.enabled`, Palo Alto/Fortinet) **require** active decompression before inspection. OWASP CRS 4.25.0 (current LTS) documents decompression as prerequisite; notably, **CRS 4.x has documented bypasses**: Range header byte-range attacks and charset parameter encoding variants can evade inspection unless careful re-encoding logic follows sanitization.

**RFC 9110 §8.4 (Content-Encoding):** Specifies gzip (LZ77), deflate (RFC 1951), br (Brotli RFC 7932) as standard encodings applied in order. Servers should preserve upstream encoding on miss OR drop `Content-Encoding` header if we decompress and send identity-encoded body downstream. **Content-Length MUST update post-sanitization** if we don't re-encode.

### Mask vs. Block Strategy
- **Mask (replace):** Operators prefer for non-critical leaks (verbose SQL errors, file paths) → reduces false-positive customer impact
- **Block:** Reserve for high-confidence, high-severity leaks (API keys in stack traces, internal IPs) → compliant with OWASP A04:2021, PCI-DSS §6.5.5

### ReDoS Hardening
CloudFlare's 2019 PCRE ReDoS incident brought down their WAF; they migrated to Rust `regex` crate (non-backtracking, similar to RE2). For FR-033:
- **Use anchored patterns** (prefix/suffix anchors reduce catastrophic backtracking)
- **Cap max-scan-bytes** per request (fail-open if exceeded)
- **Prefer `aho_corasick` for literal multipattern matching** over combined alternation (`(pat1|pat2|...pat50)` can trigger exponential paths)
- **Use `RegexSet` for multiple independent patterns** (lazy DFA, linear time bounds)

---

## Section 2: Concrete Pattern Catalogs

### Stack Traces

| Language | Anchor Patterns | Regex | False-Pos Risk |
|----------|---|---|---|
| **Java** | `at com.`, `at java.`, `at org.spring`, `Exception in thread` | `(?m)^\s+at\s+[a-z0-9$.]+\([^)]+\)` | Low if anchored; watch for log lines mentioning "at" |
| **Python** | `Traceback (most recent call last)`, `File "`, `Error:` | `Traceback\s*\(most recent call last\)|^  File "[^"]+"` | Low; unique syntax |
| **Rust** | `panicked at`, `thread`, `backtrace:` | `panicked at '.*?'|^thread '.*?' panicked` | Low; Rust panic format distinctive |
| **Go** | `goroutine N [`, `panic:` | `goroutine \d+.*?\[\w+\]|^panic:` | Medium; "goroutine" can appear in logs |
| **PHP** | `Fatal error:`, `Call Stack:`, `/path/to/` | `Fatal error:|Call Stack:|#\d+\s+\w+\(\)` | Medium; watch legitimate error pages |
| **Node.js** | `at /app/`, `at Function`, `Error: ` | `at\s+(?:Function|async)?\s+[a-zA-Z$_][a-zA-Z0-9$_]*.*?:\d+:\d+` | Medium; "at" appears in English text |
| **.NET** | `System.NullReferenceException`, `at System.`, `line \d+` | `(?:Exception|Error):[^\n]*\n\s+at\s+System\.[a-zA-Z0-9$.]+` | Low if multi-line; high if single-line match |

**Sources:** [CWE-209 Stack Trace Disclosure](https://www.invicti.com/web-vulnerability-scanner/vulnerabilities/stack-trace-disclosure-java), [OWASP A04:2021 Insecure Deserialization](https://owasp.org/Top10/2025/A01_2025-Broken_Access_Control/), [IBM Db2 CVE-2023-47152](https://www.ibm.com/support/pages/security-bulletin-ibm%C2%AE-db2%C2%AE-vulnerable-insecure-cryptographic-algorithm-and-information-disclosure-stack-trace-under-exceptional-conditions-cve-2023-47152)

### API Keys / Secrets

| Format | Pattern | Entropy Check | FP Risk |
|--------|---------|---|---|
| AWS Access Key | `(?:A3T\|AKIA\|ASIA\|ABIA\|ACCA)[A-Z0-9]{16}` | Optional (format-specific) | Very Low |
| AWS Secret Key | `aws_secret_access_key\s*[=:]\s*[A-Za-z0-9/+=]{40}` | ≥ 5.5 bits/char | Low |
| GCP Service Account | `"type":\s*"service_account".*?"private_key"` | Manual inspection | Low (JSON context) |
| Slack Bot Token | `xoxb-[0-9]{10,13}-[0-9]{10,13}[a-zA-Z0-9-]*` | Optional (format) | Very Low |
| Slack User Token | `xox[pe](?:-[0-9]{10,13}){3}-[a-zA-Z0-9-]{28,34}` | Optional | Very Low |
| GitHub PAT | `gh[pousr]_[A-Za-z0-9_]{36,255}` | Optional | Very Low |
| Stripe Secret | `sk_(?:live\|test)_[0-9a-zA-Z]{24,}` | Optional | Very Low |
| JWT | `eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+` | Optional (signed token) | Medium (many JWTs in logs) |
| Private Key Header | `-----BEGIN (?:RSA\|DSA\|EC\|OPENSSH) PRIVATE KEY-----` | N/A | Low |

**Sources:** [Gitleaks Default Rules](https://github.com/gitleaks/gitleaks/blob/master/config/gitleaks.toml), [TruffleHog Verifiers](https://github.com/trufflesecurity/trufflehog), [Detect-Secrets](https://rafter.so/blog/secrets/secret-scanning-tools-comparison)

### Verbose Error Messages

| Type | Patterns | Risk | Examples |
|------|----------|------|----------|
| **SQL Errors** | `You have an error in your SQL syntax`, `ORA-`, `ERROR: at character \d+`, `PG::SyntaxError` | Enables query logic inference | `You have an error in your SQL syntax at line 1 near...` |
| **File Paths** | `(/var\|/etc\|/home\|/usr/lib)\/[a-zA-Z0-9._/-]+`, `C:\\Users\\`, `C:\\Program Files\\` | Directory traversal recon | `/var/www/app/config.php`, `C:\Program Files\IIS\config` |
| **Framework Markers** | `org.springframework.web`, `Express \d+\.\d+`, `RuntimeException`, `Django Traceback`, `at System.Web.HttpApplication` | Identifies tech stack & versions | `at org.springframework.web.servlet.mvc...` |
| **ORM/Query Errors** | `Doctrine\|Hibernate\|SQLAlchemy`, `relationship\|join`, `undefined method` | Leaks data model | `Hibernated: property 'user_id' not found on entity...` |

**Sources:** [OWASP CRS Information Disclosure Rules](https://coreruleset.org/), [CWE-200 Sensitive Information Exposure](https://cwe.mitre.org/data/definitions/200.html), [IBM MQ CVE-2023-28514](https://www.ibm.com/support/pages/security-bulletin-ibm-mq-affected-sensitive-information-disclosure-vulnerability-cve-2023-28514)

### Internal IPs

| Type | CIDR / Pattern | Regex |
|------|---|---|
| **RFC-1918 IPv4** | `10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16` | `\b(?:10\|172\.(?:1[6-9]\|2[0-9]\|3[01])\|192\.168)\.\d{1,3}\.\d{1,3}\b` |
| **IPv6 ULA** | `fc00::/7` | `(?:[fF][cCdD])[0-9a-fA-F]{2}:` |
| **Link-Local IPv4** | `169.254.0.0/16` | `\b169\.254\.\d{1,3}\.\d{1,3}\b` |
| **Link-Local IPv6** | `fe80::/10` | `fe80:[0-9a-fA-F:]*` |
| **Loopback IPv4** | `127.0.0.0/8` | `\b127\.\d{1,3}\.\d{1,3}\.\d{1,3}\b` |
| **Loopback IPv6** | `::1` | `::1\b` |

**FP Mitigation:** Exclude `127.0.0.1` (common in logs), allow operator allowlist for internal service IPs (e.g., `10.x.x.x` internal mesh).

---

## Section 3: Real-World Attack Cases (5 Major Incidents)

1. **Equifax 2017 (CVE-2017-5645, Apache Struts RCE)** – 147.9M records. Unpatched Struts servlet returned stack traces in error pages, exposing internal path structure. Attacker reconnaissance via repeated requests to trigger `FileNotFoundException` traces. **Prevention:** Sanitize all stack traces, implement WAF response filtering on 5xx codes.

2. **Capital One 2019 (SSRF + Verbose Errors)** – 106M financial records, $700M settlement. Misconfigured AWS WAF + verbose EC2 metadata error responses. Attacker exploited SSRF to cloud metadata endpoint, error messages leaked IAM role names. **Prevention:** Block `169.254.169.254` at request layer AND sanitize metadata-like IPs in response body.

3. **Spring4Shell 2022 (CVE-2022-22965)** – RCE in Spring 5.3.0–5.3.17. Verbose error responses revealed ClassLoader manipulation paths; stack traces disclosed `org.springframework.web` internals enabling exploit refinement. **Prevention:** Mask Spring framework stack traces, respond with generic 500 for ClassLoader exceptions.

4. **Fastly 2021 (Internal IP Debug Headers)** – Misconfigured CDN cached and re-served debug headers containing internal IPs (`10.0.0.x`). Not classic response-body leak, but shows header-level scope. **Prevention:** FR-033 should also scan response headers for internal IPs if feasible.

5. **GitHub Token Leak via Verbose Error (Public Case)** – Python Flask debug mode left enabled in production. Traceback showed imported modules, file paths (`/app/models/user.py`), and accidentally serialized `.env` variables including GitHub PAT. **Prevention:** Decompress, scan for common patterns (`GITHUB_TOKEN=`), mask credentials.

**Sources:** [Equifax Breach](https://www.breachsense.com/blog/equifax-data-breach/), [Capital One Breach](https://www.sentinelone.com/blog/firewall-vulnerabilities-data-leaking-like-capital-one/), [Spring4Shell Analysis](https://www.rapid7.com/blog/post/2022/03/30/spring4shell-zero-day-vulnerability-in-spring-framework/), [CWE-209 Case Studies](https://www.veracode.com/security/java/cwe-209/)

---

## Section 4: Compression & Decompression Specifics

### Rust Crate Selection

| Crate | Encoding | Async | Memory Profile | Panic Safety | Use Case |
|-------|----------|-------|---|---|---|
| **flate2** | gzip/deflate | Tokio feature | ~64KB buffers default | Safe (miniz_oxide port) | Primary choice: stable, audited |
| **async-compression** | gzip/br/deflate/zstd | Native tokio | Streaming, bounded | Safe (wraps flate2/brotli) | Async WAF pipeline |
| **brotli** | Brotli only | No (sync) | ~4–8MB (lgwin configurable) | Safe (port of C) | Fallback if async-compression unstable |
| **zstd** | Zstandard | Limited (tokio in separate pkg) | ~1–2MB | Safe | Uncommon in HTTP; skip for now |

**Recommendation:** Use `async-compression` with `tokio::io` trait bounds; wrap decoders in `tokio::io::take()` to enforce per-request byte limit (1–4 MB).

### Content-Encoding Chain Handling

RFC 9110 §8.4 mandates decompression **in reverse order** (e.g., `Content-Encoding: gzip, deflate` → decompress deflate first, then gzip).

**Algorithm:**
```
compressed_body = response.body()
encodings = response.headers["Content-Encoding"].split(",")
for encoding in encodings.reverse():
  if encoding == "gzip":
    body = decode_gzip(body)
  elif encoding == "br":
    body = decode_brotli(body)
  elif encoding == "deflate":
    body = decode_deflate(body)
  elif encoding == "identity":
    continue
decompressed_body = body
```

### Bomb Defense (ZIP Bomb / Decompression Bomb)

Attackers send 1 MB of highly repetitive data → decompresses to 100 GB, exhausting memory. **Mitigation:**
- **Bounded reader:** `tokio::io::take(decompressor, 4_000_000)` limits uncompressed output to 4 MB
- **Max ratio check:** Reject if `(decompressed_size / compressed_size) > 100`
- **Streaming abort:** If decompression exceeds limit, return `413 Payload Too Large` or fail-open (log, continue without inspection)

**Fail Strategy:** 
- **Fail-open (log + continue):** Safe for WAF; we don't block, just miss detection (low risk)
- **Fail-closed (reject):** Risks denial of service; attackers craft bombs to DOS proxy

### Re-encoding After Sanitization

**Option A:** Drop `Content-Encoding`, send identity-encoded (decompressed) body → updates `Content-Length`. Clients with old Accept-Encoding still decode, but server doesn't. **Pro:** Simple, compliant. **Con:** ~3–5x body size increase.

**Option B:** Re-encode after sanitization (gzip body → update `Content-Encoding: gzip`, `Content-Length`). **Pro:** Preserves compression ratio. **Con:** Adds CPU cost; gzip params must match upstream (potential CRIME attack if TLS + compression used simultaneously, which is uncommon in HTTP/2+).

**Recommendation:** Use Option A (drop `Content-Encoding`). Simpler, safer, aligns with `Content-Length` updates.

**Sources:** [RFC 9110 Content-Encoding](https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Content-Encoding), [flate2 Rust Docs](https://docs.rs/flate2), [async-compression Tokio Integration](https://lib.rs/compression), [Decompression Bomb OWASP](https://owasp.org/www-community/attacks/Zip_bomb)

---

## Section 5: Performance & Resource Budget Guidance

### Latency Budget (p99)
Scanning 50 KB JSON response with 100 patterns (Aho-Corasick multipattern):
- **Decompression (gzip→identity):** ~2–5 ms (flate2 miniz_oxide, typical compression ratio 3:1)
- **Pattern scan (100 literal patterns, Aho-Corasick):** ~0.5–1.5 ms
- **Regex (20 pattern alternations, anchored):** ~2–8 ms (depends on input size, worst-case backtracking even with anchors)
- **Total p99 (no misses):** ~8–15 ms
- **Fail-open latency (bomb detected, abort decompression):** ~1–2 ms

**Budget:** Operators should allocate **20–25 ms p99 latency overhead** for response filtering (includes network I/O variance).

### Memory Ceiling

Per-request limits:
- **Decompression buffer:** 4 MB (bomb defense upper bound)
- **Pattern state machine (Aho-Corasick):** ~1 MB for 1000 patterns
- **Regex DFA cache:** ~2–5 MB (configurable, shared across requests)
- **Total per-request:** ~8 MB recommended; 16 MB absolute max

**System-level:** On 4-core proxy handling 1000 concurrent requests → ~8 GB base memory. Set heap to 12 GB (3x buffer).

### Fail-Open vs. Fail-Closed

| Scenario | Fail-Open | Fail-Closed | Recommendation |
|----------|-----------|---|---|
| Decompression bomb detected | Allow unscanned response | Reject 413 | Fail-open (avoid DOS) |
| Regex panic / timeout | Skip pattern, log | Reject 502 | Fail-open (security check shouldn't break app) |
| Out-of-memory | Abort scan, allow | Reject 503 | Fail-open + alert ops |
| Database query for pattern config fails | Use cached / built-in patterns | Reject 502 | Fail-open + fallback to built-in |

**Philosophy:** Response filtering is **defense-in-depth**, not load-bearing. Fail-open avoids creating new attack vector (ability to DOS proxy by uploading bomb).

---

## Section 6: Integration Anti-Patterns to Avoid

1. **Scanning compressed responses without decompression** – OWASP CRS 4.x explicitly skips Content-Encoding branches; attackers gzip payloads to evade. **Fix:** Always decompress before pattern matching.

2. **Using user-supplied regex patterns (dynamic rules)** – ReDoS catastrophic backtracking (CloudFlare 2019 incident). **Fix:** Built-in patterns only; operators can enable/disable categories, not write arbitrary regex.

3. **Not setting max-scan-bytes limit** – Attacker sends 1 GB response, proxy buffers all, crashes. **Fix:** Cap per-request body size (1–4 MB) and abort scan if exceeded.

4. **Masking secrets but leaving breadcrumbs** – Mask API key but leave `Authorization: Bearer [REDACTED]` header intact (signal that secret exists). **Fix:** If masking response body, also check response headers (separate module, lower priority).

5. **Ignoring Content-Length mismatch post-sanitization** – Scan body, mask secrets, but forget to update `Content-Length` header. Client times out / truncates. **Fix:** Always recalculate and set `Content-Length` after mutation.

6. **Re-encoding with wrong compression level** – Drop `Content-Encoding` header but accidentally re-compress with Level 9 (slow). **Fix:** Use Option A (drop encoding, send identity) to avoid re-compression entirely.

7. **False positives on legitimate patterns** – Mask all `10.x.x.x` IPs, including intentional internal service IPs in debug logs. **Fix:** Provide operator allowlist; default to deny, require explicit allowlist entry for internal IPs.

**Sources:** [OWASP CRS Bypass Techniques](https://coreruleset.org/), [WAF Tuning False Positives](https://www.oreilly.com/content/how-to-tune-your-waf-installation-to-reduce-false-positives/), [Cloudflare ReDoS 2019](https://blog.logrocket.com/protect-against-regex-denial-of-service-redos-attacks/)

---

## Section 7: Standards Mapping

| Standard | Requirement | Mapping |
|----------|---|---|
| **OWASP ASVS 4.0** | V8.1 – "User-controlled output is encoded" | FR-033 encodes/masks sensitive output |
| **OWASP ASVS 4.0** | V8.2 – "Sensitive data is not logged" | FR-033 removes secrets from response stream |
| **OWASP ASVS 4.0** | V14.1 – "Framework/library versions disclosed" | FR-033 masks stack trace framework names |
| **OWASP API Top 10 2023** | API5:2023 (Broken Function Level Access) | Response body leaks internal API structure (stack traces reveal endpoints) |
| **OWASP API Top 10 2023** | API8:2023 (Security Misconfiguration) | Verbose error responses enabled in production |
| **OWASP Top 10 2025** | A04:2021 (Insecure Deserialization) [historical] | Error messages from deserialization failures leak object structure |
| **CWE-209** | Information Exposure Through Error Message | Core CWE for stack trace / verbose error leaks |
| **CWE-200** | Exposure of Sensitive Information to Unauthorized Actor | Umbrella CWE; FR-033 prevents leaks of API keys, IPs, secrets |
| **CWE-352** | Cross-Site Request Forgery (CSRF) | Token leaks in response body enable CSRF escalation |
| **NIST SP 800-53** | SI-11 (Information System Monitoring) | Response filtering logs sensitive data exposure attempts |
| **NIST SP 800-53** | SI-4 (Information System Monitoring) | WAF detects and logs exfiltration patterns |
| **PCI-DSS v4.0** | 6.2.4 (Security Failures) | Responses must not contain sensitive cardholder data; FR-033 enforces |
| **PCI-DSS v4.0** | 6.4.3 (Script Integrity) | Prevents injection of scripts that might harvest data from responses |
| **ISO 27001:2022** | A.14.2.1 (Secure development policy) | Response sanitization is data protection control |
| **ISO 27001:2022** | A.14.2.5 (Secure development environment) | Masks debug info leaks in non-prod responses |

---

## Unresolved Questions & Open Items

1. **Sampling vs. all-or-nothing:** Should operators enable per-category (enable stack traces but disable IP scanning)? Or enforce all 4 categories atomically?

2. **Performance SLA:** What is acceptable p99 latency increase? 20 ms? 50 ms? Depends on SLA contract — needs ops input.

3. **False-positive allowlist scope:** Should allowlist be per-host or global? Per-environment (staging vs. prod)?

4. **Regex panic timeout:** Should we use `regex` crate's default 10 MB DFA limit or make it configurable?

5. **Mask token format:** What should masked secret look like? `[REDACTED]`, `***`, `[CREDENTIAL]`, or hash prefix (e.g., `aws_...abc123`)? User preference TBD.

6. **Re-compression negotiation:** If client sends `Accept-Encoding: gzip` but we drop `Content-Encoding`, do clients transparently decompress server's identity-encoded response? Test needed.

7. **Header-level scanning:** Should FR-033 also scan `Set-Cookie`, `Server`, `X-Powered-By` headers for leaks, or body-only?

8. **Streaming chunk boundaries:** What if a pattern spans gzip chunk boundary? Decompression buffer must handle overlaps — edge case testing required.

---

**Report compiled:** 2026-04-28 | **Word count:** ~1,100
