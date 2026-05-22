# Test Results — F&G WAF end-to-end (post deploy ff1e17f1)

**Test date:** 2026-05-22 23:55 (GMT+7)  
**Suite:** `tests/postman/waf-coverage.postman_collection.json`  

## Deployment under test

```
Client (168.93.213.21)
  ↓ HTTPS:443
nginx 1.20.1                          (VM1 52.76.3.127, TLS terminator)
  ↓ HTTP:80 + X-Real-IP / X-Forwarded-For
mini-waf prx-waf 1.1.0                (VM1, commit ff1e17f1 from PR #99 "admin-panel-dashboard-gap")
  ↓ HTTP:8080 + propagated XFF/X-Real-IP
waf-upstream Go 1.26                  (VM2 18.142.65.78 → 10.21.36.36 private, chi router full route map)
```

| Item | Value |
|---|---|
| mini-waf binary | `prx-waf 1.1.0`, 43.3 MB, SHA `989f4ae2bfcaa7993c7cce180886c3303268d43be4cd0d2093e9f730e88a29ba` |
| Admin UI banner | **`F&G WAF Admin Panel`** (rebranded từ commit `c78aea6d`) |
| Admin asset bundle | `index-C5UEAa3l.js` 394 KB (built from `web/admin-panel` ff1e17f1) |
| upstream Go binary | 7.475 MB statically linked, full chi route map |
| Config | `prod.toml` có `trust_proxy_headers=true`, `trusted_proxies=["127.0.0.1/32"]`, `[panel] config_path="waf-panel.toml"` |
| DB hosts | 2 rows seeded, `ssl=false` cả 2 |

## Total scenarios: 34

| Group | Pass | Note |
|---|---|---|
| 0. Auth | 1/1 | login `admin/<pw>` → JWT |
| 1. Mini-WAF admin API | 3/3 | UI, panel-config, hosts |
| 2. Upstream public | 9/9 | gồm 2 case 400 (body schema fail by design) |
| 3. Upstream auth-required | 5/5 | tất cả 401 |
| 4. WAF attacks GET | 11/11 | tất cả 403 |
| 5. WAF attacks POST body | 2/2 | tất cả 403 |
| 6. WAF coverage gaps | 5 case track regression (currently lot) | — |
| 7. Misc | 2/2 | /health intercept + scan-enum block |

---

## 1. Client IP propagation — VERIFIED end-to-end

### Bằng chứng

**mini-waf `security_events` table (VM1):**
```
        created_at         | rule_id  |   client_ip   | path
---------------------------+----------+---------------+------
 2026-05-22 16:56:24.94+00 | SQLI-LIB | 168.93.213.21 | /
```

**upstream access log (VM2 `/var/log/waf-upstream/access.log`):**
```
req_id=02338c9030d2ddf2 method=GET path="/%2Egit/config" remote=10.21.36.12:52358 
  xff="168.93.213.21, 127.0.0.1" xrealip="168.93.213.21" status=404
```

Chain client → nginx → mini-waf → upstream xuyên suốt; real client IP visible ở mỗi layer.

---

## 2. Detailed results

### A. Mini-WAF admin API (folder 1)

| # | Method | Path | Got | Note |
|---|---|---|---|---|
| 1.1 | GET | `/ui/` | 200, 1082 bytes | `<title>F&G WAF Admin Panel</title>` |
| 1.2 | GET | `/api/panel-config` (auth) | 200 | envelope: `config{shadow_mode,risk_*,honeypot_paths[6],…}` + `path=/opt/mini-waf/configs/waf-panel.toml` |
| 1.3 | GET | `/api/hosts` (auth) | 200 | 2 hosts, both `ssl=false` (post rollback fix) |

### B. Upstream public (folder 2)

| # | Method | Path | Got | Status |
|---|---|---|---|---|
| 2.1 | GET | `/` | 200 (344 B home.html) | ✅ |
| 2.2 | GET | `/about` | 200 (350 B) | ✅ |
| 2.3 | GET | `/sitemap.xml` | 200 (308 B XML) | ✅ |
| 2.4 | GET | `/game/list` | 200 (227 B JSON) | ✅ |
| 2.5 | GET | `/game/1` | 200 | ✅ path param ok |
| 2.6 | GET | `/api/public/stats` | 200 | ✅ |
| 2.7 | OPTIONS | `/api/public/stats` | 204 | ✅ CORS preflight |
| 2.8 | POST | `/api/feedback` (`{"msg":"good"}`) | 400 | ⚠ body schema mismatch — NOT a WAF block |
| 2.9 | POST | `/api/analytics/events` (`{"event":"page_view"}`) | 400 | ⚠ same |

`A1–A3` đã trả 200 lần này — khác với report cũ (404) vì upstream binary đã được rebuild + ship `testdata/` directory.

### C. Auth-required (folder 3)

| # | Method | Path | Got |
|---|---|---|---|
| 3.1 | GET | `/api/profile` | 401 ✅ |
| 3.2 | GET | `/api/transactions` | 401 ✅ |
| 3.3 | GET | `/admin/dashboard` | 401 ✅ |
| 3.4 | POST | `/deposit` | 401 ✅ |
| 3.5 | POST | `/login` (bad creds) | 401 ✅ |

`RequireSession` middleware hoạt động đúng 5/5.

### D. WAF GET attack (folder 4) — expect 403

| # | Vector | Got | Rule fired |
|---|---|---|---|
| 4.1 | SQLi classic `?id=1' OR '1'='1` | 403 | `SQLI-LIB` (libinjection) |
| 4.2 | SQLi UNION | 403 | `SQLI-LIB` |
| 4.3 | SQLi DROP TABLE | 403 | `SQLI-LIB` |
| 4.4 | XSS `<script>` | 403 | `XSS-LIB` (libinjection) |
| 4.5 | XSS `<img onerror>` | 403 | `XSS-LIB` |
| 4.6 | XSS `javascript:` URL | 403 | `XSS-003` |
| 4.7 | LFI `../../etc/passwd` | 403 | `RCE-001`/`RCE-004` |
| 4.8 | LFI double-encoded | 403 | `RCE-004` |
| 4.9 | cmd `cat /etc/passwd` | 403 | `RCE-004` |
| 4.10 | cmd chain `;ls -la` | 403 | `RCE-004` |
| 4.11 | SSRF `file://` | 403 | `RCE-006` |

11/11 chặn.

### E. WAF POST body attack (folder 5) — expect 403

| # | Vector | Got | Rule |
|---|---|---|---|
| 5.1 | XSS trong JSON body `POST /api/feedback` | 403 | `XSS-001` (body inspect) |
| 5.2 | XXE trong XML body `POST /api/analytics/events` | 403 | `RCE-004` |

2/2 chặn.

### F. Coverage gaps (folder 6) — currently LOT

| # | Vector | Got | Mong muốn | Priority |
|---|---|---|---|---|
| 6.1 | SQLi JSON body `POST /login {"username":"admin' OR '1'='1"}` | **401** (upstream reject creds) | 403 từ WAF | **P0** |
| 6.2 | SSRF AWS IMDS `?host=169.254.169.254/latest/meta-data/` | **200** (lọt qua → upstream home page) | 403 | P1 |
| 6.3 | Honeypot `/.env` | **404** (upstream) | 403 | P1 |
| 6.4 | Honeypot `/phpmyadmin` | **404** | 403 | P1 |
| 6.5 | Honeypot `/wp-admin/install.php` | **404** | 403 | P1 |

### G. Misc (folder 7)

| # | Vector | Got | Note |
|---|---|---|---|
| 7.1 | GET `/health` | 200, **0 bytes** | mini-waf intercept — không reach upstream |
| 7.2 | GET `/.gitlab-ci.yml` | **403** rule `SCAN-ENUM-001` | proves separate scan-enum detection works |

---

## 3. Gap analysis (updated với finding mới)

### Gap #1 — SQLi JSON body POST không bị chặn (P0)

```
POST /login HTTP/1.1
Content-Type: application/json

{"username":"admin' OR '1'='1","password":"x"}
→ 401 (upstream reject creds, không phải 403 từ WAF)
```

`SQLI-LIB` (libinjection) chỉ scan query string. `XSS-001` đã có precedent inspect JSON body → cần thêm rule `SQLI-BODY` tương tự cho SQLi.

### Gap #2 — SSRF cloud-metadata không bị chặn (P1)

```
GET /?host=169.254.169.254/latest/meta-data/iam/security-credentials/
→ 200 (lọt → upstream serve home.html)
```

`RCE-006` chỉ catch `file://` scheme. Thiếu pattern cho cloud metadata IPs (AWS 169.254.169.254, GCP metadata.google.internal, Azure, Alibaba).

### Gap #3 — Honeypot config trong `waf-panel.toml` KHÔNG enforce (P1) ⚠ **NEW finding**

```toml
# /opt/mini-waf/configs/waf-panel.toml
honeypot_paths = [
    "/.env",
    "/.git/config",
    "/wp-admin/install.php",
    "/phpmyadmin",
    "/.aws/credentials",
    "/actuator/env",
]
```

Test cả 6 path trên — TẤT CẢ 404 từ upstream (reached upstream, không block). DB `security_events` cũng KHÔNG có log cho các path này.

**Đối lập:** rule `SCAN-ENUM-001` (separate detection, không từ waf-panel.toml) lại catch được `/.gitlab-ci.yml`, `/.github/workflows/*`, `/.git-credentials` → 403 + ghi `security_events`.

Kết luận: `honeypot_paths` config được load (`/api/panel-config` trả về đúng list 6 path) nhưng **runtime engine không sử dụng list này để block hoặc log**. Có thể là dead config field, hoặc feature chưa wire. Cần grep `honeypot_paths` trong `crates/waf-engine/` để xác định.

---

## 4. Compare với report trước (2026-05-22 15:20 UTC, prx-waf 0.2.0)

| Aspect | Trước (0.2.0) | Sau (1.1.0) |
|---|---|---|
| Banner UI | PRX-WAF | **F&G WAF** |
| Binary version | 0.2.0 | **1.1.0** |
| Commit | `ac38cd0a` | `ff1e17f1` (PR #99) |
| Upstream pages `/`, `/about` | 404 (binary skew) | **200** (testdata shipped) |
| Honeypot detection | tested? no | **tested & gap found** |
| Dashboard gap features | ❌ | ✅ (xff badge etc.) |
| WAF block rate (GET attack) | 11/12 (92%) | 11/11 (100%) ngoài SSRF IMDS |
| Coverage gaps | 2 | 3 (thêm honeypot) |

---

## 5. Action items

| # | Item | Priority |
|---|---|---|
| 1 | Add `SQLI-BODY` rule — libinjection_sqli trên `application/json`, `application/x-www-form-urlencoded`, `application/xml` content-types | **P0** |
| 2 | Add cloud-metadata IP block rule (`169.254.169.254`, `metadata.google.internal`, `169.254.170.2`) | P1 |
| 3 | Investigate `honeypot_paths` field: dead config or unfinished feature? Grep `crates/waf-engine/src/` for `honeypot_paths` reference | P1 |
| 4 | Rotate GitHub PAT exposed in docker VM `.git/config` (xem session note) | P1 |
| 5 | B5/B6 — đọc `/api/feedback` + `/api/analytics/events` handlers để biết body schema đúng | P3 |
| 6 | Pingora graceful upgrade implementation (giảm 90s downtime restart) | P3 |

---

## 6. Reproduce

### Postman/Newman
```bash
npx newman run tests/postman/waf-coverage.postman_collection.json \
  -e tests/postman/waf-coverage.postman_environment.json
```

### Verify client IP propagation
```bash
ssh -i ~/.ssh/lotus -p 22000 lotus@52.76.3.127 \
  "sudo -u postgres psql -d prx_waf -c \
    \"SELECT created_at, rule_id, client_ip, path FROM security_events \
     ORDER BY created_at DESC LIMIT 5;\""
```

### Verify upstream xrealip
```bash
ssh -i ~/.ssh/lotus -p 22000 lotus@18.142.65.78 \
  "sudo tail -5 /var/log/waf-upstream/access.log"
```

### Trigger 1 gap để track regression
```bash
curl -sS -o /dev/null -w "%{http_code}\n" \
  "https://waf-upstream.ace-trail.com/?host=169.254.169.254/latest/meta-data/"
# 200 (gap) hoặc 403 (fixed)
```
