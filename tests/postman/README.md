# Postman tests — F&G WAF coverage

End-to-end test suite cho `mini-waf` (F&G WAF) + `waf-upstream` Go backend.

## Stack đang chạy (2026-05-22)

```
Client (your IP)
  ↓ HTTPS:443
nginx 1.20.1   (VM1 52.76.3.127, TLS terminator)
  ↓ HTTP:80
mini-waf 1.1.0 (VM1, commit ff1e17f1 from PR #99, banner "F&G WAF")
  ↓ HTTP:8080
waf-upstream (VM2 18.142.65.78, Go chi router với full route map)
```

Admin UI public: `https://mini-waf.ace-trail.com/ui/`

## Import

1. Postman → File → Import → drag cả 2 file:
   - `waf-coverage.postman_collection.json`
   - `waf-coverage.postman_environment.json`
2. Top-right dropdown → chọn environment `mini-waf prod (Singapore)`
3. Vào folder `0. Auth` → Send "Login" → JWT tự lưu vào `{{access_token}}`

## Cách chạy

- **Manual:** click từng request → Send → xem Status code + assertion tab "Test Results"
- **Batch:** click "Run" trên collection → Postman Collection Runner
- **CLI (newman):**
  ```bash
  npx newman run tests/postman/waf-coverage.postman_collection.json \
    -e tests/postman/waf-coverage.postman_environment.json
  ```

## Variables (sửa trong environment nếu khác)

| Variable | Default | Note |
|---|---|---|
| `upstream_url` | `https://waf-upstream.ace-trail.com` | Go upstream qua WAF |
| `admin_url` | `https://mini-waf.ace-trail.com` | Admin API + UI qua WAF |
| `admin_user` | `admin` | seeded admin user |
| `admin_pass` | `5ed605f0e1dc4f104624c049` | từ `summary.md` (test env only) |
| `access_token` | (auto-fill) | sau khi gọi `0. Auth/Login` |

## Folders

| Folder | Mục đích | Expected |
|---|---|---|
| `0. Auth` | Login → store JWT | 200 + token |
| `1. Mini-WAF admin API` | UI shell + panel-config + hosts CRUD | 200 |
| `2. Upstream public` | Pages, public APIs, không cần auth | 200/204, 400 cho POST schema fail |
| `3. Upstream auth-required` | Endpoints qua `RequireSession` | 401 không có cookie |
| `4. WAF attacks — GET query` | SQLi/XSS/LFI/RCE/SSRF qua URL | **403** |
| `5. WAF attacks — POST body` | XSS JSON, XXE XML | **403** |
| `6. WAF coverage gaps` | 3 vectors **lọt qua** WAF — track regression | hiện 200/401/404, mong muốn 403 |
| `7. Misc` | `/health` intercept, honeypot pattern | 200 empty / 404 |

## Upstream routes (Go chi router — `/Users/admin/lab/WAF-upstream-test`)

| Method | Path | Auth | Handler |
|---|---|---|---|
| GET | `/health` | no | nhưng bị mini-waf intercept ở gateway (200 empty) — không reach upstream |
| GET | `/`, `/about`, `/sitemap.xml`, `/static/*`, `/public/{file}`, `/assets/*` | no | pages |
| GET | `/game/list`, `/game/{id}` | no | games list/detail |
| POST | `/game/{id}/play` | yes | games play |
| POST | `/login`, `/otp` | no | auth |
| POST | `/api/feedback`, `/api/analytics/events` | no | (body schema strict — bad body → 400) |
| GET | `/api/public/stats`, OPTIONS `/api/public/stats` | no | publicapi (CORS) |
| GET | `/api/profile`, PUT `/api/profile` | yes | profile |
| GET | `/api/transactions` | yes | transactions |
| GET, PUT | `/user/settings` | yes | settings |
| POST | `/deposit`, `/withdrawal`, `/api/rewards/claim`, `/api/bet-reports/export` | yes | financial |
| GET | `/admin/dashboard`, `/admin/users` | yes | admin |
| POST | `/api/kyc/document` | yes | kyc upload |
| GET | `/ws/live`, `/api/notifications/stream` | yes | realtime (WS, SSE) |

## WAF coverage gaps đã phát hiện (2026-05-22)

| # | Vector | Hiện trạng | Mong muốn | Priority |
|---|---|---|---|---|
| 1 | `POST /login {"username":"admin' OR '1'='1"}` (SQLi JSON body) | 401 (lọt WAF, upstream reject creds) | 403 | **P0** |
| 2 | `GET /?host=169.254.169.254/latest/meta-data/` (SSRF AWS IMDS) | 200 (lọt qua → upstream home) | 403 | P1 |
| 3 | Honeypot paths trong `waf-panel.toml` (`/.env`, `/.git/config`, `/phpmyadmin`, `/wp-admin/*`, `/.aws/credentials`, `/actuator/env`) | 404 từ upstream — **không block** dù config | 403 | P1 |

Folder `6. WAF coverage gaps` test scripts accept cả status hiện tại lẫn 403 (regression check). Khi gap được fix, script log `GAP CLOSED — switch expected to 403 only`.

## Quan trọng

- `/health` qua WAF luôn **200 body rỗng** — mini-waf intercept ở `crates/gateway/src/proxy.rs:522` (built-in liveness handler). KHÔNG dùng `/health` để test upstream reachability.
- Block response có HTML `<title>403 Forbidden — Request Blocked</title>` + JSON `Request ID` + dòng "Your IP" — Postman test có thể grep title/Your-IP để xác nhận đúng nguồn block.
- Client IP propagation đã verified end-to-end: `security_events.client_ip` + upstream `xrealip` đều show real IP (`168.93.213.21` ví dụ).

## Reference

Báo cáo chi tiết test gần nhất: [`test-results.md`](./test-results.md).
