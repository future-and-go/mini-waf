# PRX-WAF — Hướng Dẫn Kỹ Thuật Toàn Diện

> **F&G WAF** · Tường Lửa Ứng Dụng Web · Phiên bản 0.2.0 · Rust 2024 Edition · Dựa trên Pingora  
> Giải pháp WAF đầy đủ: tất cả tính năng, tất cả quy tắc, hướng dẫn cài đặt hoàn chỉnh.

---

## Mục Lục

1. [Giới Thiệu](#1-giới-thiệu)
2. [Kiến Trúc Hệ Thống](#2-kiến-trúc-hệ-thống)
3. [Cài Đặt Nhanh & Triển Khai](#3-cài-đặt-nhanh--triển-khai)
4. [Hướng Dẫn Sử Dụng Admin UI](#4-hướng-dẫn-sử-dụng-admin-ui)
   - 4.1 [Đăng Nhập](#41-đăng-nhập)
   - 4.2 [Dashboard](#42-dashboard)
   - 4.3 [Hosts](#43-hosts)
   - 4.4 [IP Rules](#44-ip-rules)
   - 4.5 [URL Rules](#45-url-rules)
   - 4.6 [Security Events](#46-security-events)
   - 4.7 [Security Logs](#47-security-logs)
   - 4.8 [SSL Certificates](#48-ssl-certificates)
   - 4.9 [CC Protection & Rate Limiting](#49-cc-protection--rate-limiting)
   - 4.10 [Notifications](#410-notifications)
   - 4.11 [Settings](#411-settings)
   - 4.12 [Rule Manager](#412-rule-manager)
   - 4.13 [Custom Rules](#413-custom-rules)
   - 4.14 [Rule Sources](#414-rule-sources)
   - 4.15 [Rule Analytics](#415-rule-analytics)
   - 4.16 [Bot Management](#416-bot-management)
   - 4.17 [CrowdSec Integration](#417-crowdsec-integration)
   - 4.18 [Cache Dashboard](#418-cache-dashboard)
   - 4.19 [TX Velocity & Sequence](#419-tx-velocity--sequence)
5. [Pipeline Phát Hiện WAF](#5-pipeline-phát-hiện-waf)
6. [Danh Mục Quy Tắc Đầy Đủ](#6-danh-mục-quy-tắc-đầy-đủ)
7. [Tham Chiếu Cấu Hình](#7-tham-chiếu-cấu-hình)
8. [Phân Cụm & Khả Dụng Cao](#8-phân-cụm--khả-dụng-cao)
9. [Tham Chiếu REST API](#9-tham-chiếu-rest-api)
10. [Tham Chiếu CLI](#10-tham-chiếu-cli)
11. [Thực Hành Bảo Mật Tốt Nhất](#11-thực-hành-bảo-mật-tốt-nhất)
12. [Xử Lý Sự Cố](#12-xử-lý-sự-cố)

---

## 1. Giới Thiệu

PRX-WAF (tên thương hiệu **F&G WAF**) là Tường Lửa Ứng Dụng Web (WAF) và Reverse Proxy hiệu năng cao, sẵn sàng cho môi trường sản xuất, được xây dựng trên [Cloudflare Pingora](https://github.com/cloudflare/pingora) bằng Rust phiên bản 2024. Hệ thống cung cấp:

- **Đa giao thức**: HTTP/1.1, HTTP/2, HTTP/3 (QUIC qua quinn)
- **Pipeline phát hiện tấn công 16 giai đoạn**: SQLi, XSS, RCE, LFI/RFI, SSRF, SSTI, XXE, Deserialization, Prototype Pollution, WebShell, và nhiều hơn
- **612+ quy tắc tích hợp**: OWASP CRS, vá CVE, nâng cao, bot detection, ModSecurity, OWASP API Security
- **Engine quy tắc tùy chỉnh**: JSON DSL qua DB với cây AND/OR/NOT + ngôn ngữ kịch bản Rhai
- **Chấm điểm rủi ro tích lũy** (FR-025): L0 seed + L1 tích lũy + L2 anomaly/velocity
- **Nhận diện thiết bị** (FR-010): TLS JA3/JA4 + HTTP/2 Akamai hash
- **Phát hiện vận tốc giao dịch** (FR-012): mẫu gian lận fintech đa endpoint
- **Tích hợp CrowdSec**: Bouncer + AppSec + Log Pusher
- **Phân cụm QUIC mTLS**: bầu cử Raft-lite, đồng bộ quy tắc nén lz4
- **Admin UI React 18**: JWT + TOTP 2FA, giám sát WebSocket thời gian thực, 11 ngôn ngữ
- **Lưu trữ PostgreSQL 16+**: tất cả config, logs, rules với mã hóa AES-256-GCM at rest

### Số Liệu Thực Tế (Hệ Thống Demo)

| Chỉ số | Giá trị |
|--------|---------|
| Tổng quy tắc đang tải | **612** |
| Danh mục quy tắc | **36** |
| Security Events (demo) | **3.718** đã chặn |
| Giao thức hỗ trợ | HTTP/1.1, HTTP/2, HTTP/3 |
| Ngôn ngữ Admin UI | 11 ngôn ngữ |

---

## 2. Kiến Trúc Hệ Thống

### 2.1 Cấu Trúc Crate

PRX-WAF là workspace Rust gồm **7 crate** (~26.168 LOC tổng cộng):

| Crate | LOC | Mục Đích |
|-------|-----|----------|
| `prx-waf` | 1.552 | Binary: CLI entry point, khởi động server |
| `gateway` | 1.868 | Pingora reverse proxy, HTTP/3, TLS/ACME, cache Valkey/moka |
| `waf-engine` | 11.154 | Pipeline phát hiện 16 giai đoạn, rules engine, WASM plugins, risk scoring |
| `waf-storage` | 2.293 | Lớp PostgreSQL (sqlx), migrations, AES-256-GCM at rest |
| `waf-api` | 4.040 | Axum REST API, JWT+TOTP, WebSocket, nhúng React UI |
| `waf-common` | 1.457 | Kiểu dùng chung: RequestCtx, WafDecision, TierPolicy, config |
| `waf-cluster` | 3.804 | QUIC mTLS cluster, Raft-lite election, đồng bộ quy tắc |
| **Tổng** | **26.168** | |

### 2.2 Luồng Xử Lý Request

```mermaid
flowchart TD
    Client([Client]) --> Proto[TCP/TLS/QUIC\nHTTP 1.1 / 2 / 3]
    Proto --> Tier[Phân loại Tier FR-002\nCritical / High / Medium / CatchAll]
    Tier --> Relay[Tiền-xử lý: Phát hiện Relay FR-007\nXFF · ASN · Tor exit · ClientIdentity]
    Relay --> DevFP[Tiền-xử lý: Nhận diện Thiết Bị FR-010\nJA3/JA4 · H2 Akamai · ip_hopping]
    DevFP --> P0[Giai đoạn 0: Access Gate FR-008\nHost gate → IP blacklist → IP whitelist]
    P0 --> P14[Giai đoạn 1-4: Fast-Path IP & URL\nWhitelist / Blacklist]
    P14 --> P5[Giai đoạn 5: Giới hạn tốc độ FR-004\nToken-bucket + Sliding-window]
    P5 --> P55[Giai đoạn 5.5: DDoS FR-005\nPer-IP / Per-FP / Per-Tier]
    P55 --> P56[Giai đoạn 5.6: TX Velocity FR-012\nSequence · Withdrawal burst]
    P56 --> P57[Giai đoạn 5.7: Dị thường Hành vi FR-011\n16-slot ring · cadence · path]
    P57 --> P6[Giai đoạn 6: Phát hiện Scanner]
    P6 --> P7[Giai đoạn 7: Phát hiện Bot]
    P7 --> P8[Giai đoạn 8: SQL Injection\nlibinjection + 19 regex]
    P8 --> P9[Giai đoạn 9: XSS\nlibinjection + regex]
    P9 --> P10[Giai đoạn 10: RCE / Command Injection]
    P10 --> P11[Giai đoạn 11: Directory Traversal / SSRF]
    P11 --> P12[Giai đoạn 12: Quy tắc tùy chỉnh FR-003\nJSON DSL + Rhai]
    P12 --> P13[Giai đoạn 13: OWASP CRS\n24+ danh mục]
    P13 --> P14b[Giai đoạn 14: Dữ liệu nhạy cảm\nAho-Corasick]
    P14b --> P15[Giai đoạn 15: Anti-Hotlink\nKiểm tra Referer]
    P15 --> P16[Giai đoạn 16: CrowdSec\nBouncer + AppSec]
    P16 --> Risk[Sau: Chấm điểm rủi ro FR-025\nL0+L1+L2 · suy giảm · ngưỡng]
    Risk --> Decision{Quyết định}
    Decision -->|Cho phép| Cache[FR-009 Cache thông minh\nValkey / moka LRU]
    Cache --> Backend([Backend Upstream])
    Decision -->|Chặn| Block403([403 Forbidden\nlog → security_events])
    Decision -->|Thách thức| Challenge([429 / CAPTCHA\nJS proof-of-work])
```

### 2.3 Tương Tác Giữa Các Thành Phần

```mermaid
graph LR
    UI[React Admin UI] -->|JWT REST + WS| API[waf-api\nAxum]
    API -->|sqlx| DB[(PostgreSQL 16)]
    API -->|ArcSwap| Engine[waf-engine]
    GW[gateway\nPingora] -->|kiểm tra ctx| Engine
    Engine -->|log tấn công| DB
    GW -->|upstream| Backend[Backend]
    Cluster[waf-cluster\nQUIC mTLS] -->|đồng bộ rules| GW
    Cluster -->|Raft-lite| DB
```

### 2.4 Phân Loại Tier (FR-002)

Mỗi request được phân loại vào một trong bốn tier **trước** bất kỳ giai đoạn WAF nào:

```mermaid
flowchart LR
    Req([Request]) --> TierReg{TierPolicyRegistry\n.classify}
    TierReg -->|path /login POST| Crit[Critical\nfail-close\n50 RPS\nkhông cache]
    TierReg -->|path /api/*| High[High\nfail-close\n200 RPS\nTTL ngắn]
    TierReg -->|trang người dùng| Med[Medium\nfail-open\n1000 RPS\nTTL mặc định]
    TierReg -->|tất cả còn lại| CA[CatchAll\nfail-open\nkhông giới hạn\ncache tích cực]
    Crit & High & Med & CA --> WAF[WAF Giai đoạn 1-16]
```

| Tier | Lưu Lượng Điển Hình | Fail-Mode | Ngưỡng DDoS | Cache |
|------|---------------------|-----------|-------------|-------|
| **Critical** | Login, thanh toán, auth | Close (chặn khi lỗi) | 50 RPS | Không cache |
| **High** | API surfaces, microservices | Close | 200 RPS | TTL ngắn (30s) |
| **Medium** | Trang người dùng đã auth, assets | Open (cho phép khi lỗi) | 1.000 RPS | Mặc định (300s) |
| **CatchAll** | Tất cả còn lại | Open | Không giới hạn | Tích cực (3600s) |

---

## 3. Cài Đặt Nhanh & Triển Khai

### 3.1 Docker Compose (Khuyến Nghị)

**Yêu cầu:** Docker Compose v1.3+, 4 GB RAM, cổng 80/443/16827 trống.

```bash
git clone https://github.com/openprx/prx-waf
cd prx-waf

# (Tùy chọn) Chỉnh sửa docker-compose.yml để đặt mật khẩu DB, cổng
nano docker-compose.yml

# Khởi động tất cả dịch vụ
docker compose up -d

# Kiểm tra sức khỏe
curl http://localhost:16827/health

# Truy cập Admin UI
open http://localhost:16827/ui/
# Thông tin mặc định: admin / admin123  ← ĐỔI NGAY
```

**Mapping cổng:**

| Cổng Host | Cổng Container | Dịch vụ |
|-----------|---------------|---------|
| `16880` | `80` | HTTP proxy (lưu lượng đến) |
| `16843` | `443` | HTTPS proxy (kết thúc TLS) |
| `16827` | `9527` | Admin API + UI |
| `15432` | `5432` | PostgreSQL (tùy chọn truy cập trực tiếp) |

### 3.2 Build Thủ Công (Rust)

**Yêu cầu:** Rust 1.86+, PostgreSQL 16+

```bash
# Build binary release
cargo build --release

# Cài đặt database
createdb prx_waf
createuser prx_waf
psql -c "GRANT ALL ON DATABASE prx_waf TO prx_waf;"

# Chạy migrations
./target/release/prx-waf -c configs/default.toml migrate

# Tạo admin mặc định
./target/release/prx-waf -c configs/default.toml seed-admin

# Khởi động server
./target/release/prx-waf -c configs/default.toml run
```

### 3.3 Dịch Vụ Systemd

```bash
# Cài đặt binary
sudo install -m 0755 target/release/prx-waf /usr/local/bin/prx-waf
sudo useradd -r -s /sbin/nologin prx-waf
sudo mkdir -p /etc/prx-waf /var/lib/prx-waf /var/log/prx-waf
sudo install -m 0640 -o prx-waf configs/default.toml /etc/prx-waf/config.toml
```

Tạo `/etc/systemd/system/prx-waf.service`:

```ini
[Unit]
Description=PRX-WAF (F&G WAF) Reverse Proxy và WAF
After=network-online.target postgresql.service
Wants=network-online.target

[Service]
Type=simple
User=prx-waf
ExecStart=/usr/local/bin/prx-waf -c /etc/prx-waf/config.toml run
Restart=on-failure
RestartSec=10s
AmbientCapabilities=CAP_NET_BIND_SERVICE
LimitNOFILE=65535
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user.target
```

```bash
sudo systemctl daemon-reload
sudo systemctl enable --now prx-waf
sudo systemctl status prx-waf
```

---

## 4. Hướng Dẫn Sử Dụng Admin UI

Admin Panel là SPA **React 18.3 + Refine + Ant Design 5** phục vụ tại `http://<host>:16827/ui/`.  
Xác thực: **JWT** + **TOTP 2FA** tùy chọn.  
Tất cả trang hỗ trợ cập nhật thời gian thực qua **WebSocket**.

### 4.1 Đăng Nhập

![Trang đăng nhập](screenshots/screencapture-localhost-16827-ui-login-2026-05-22-22_29_46.png)

*Hình 4.1 — Màn hình đăng nhập F&G WAF Admin*

- Nhập **Tên đăng nhập** và **Mật khẩu**
- Nếu cấu hình TOTP, nhập mã OTP 6 chữ số sau mật khẩu
- JWT token lưu trong trình duyệt; phiên hết hạn theo TTL cấu hình
- Thông tin mặc định (đổi ngay): `admin` / `admin123`

---

### 4.2 Dashboard

![Dashboard](screenshots/screencapture-localhost-16827-ui-login-2026-05-22-22_30_23.png)

*Hình 4.2 — Dashboard WAF thời gian thực hiển thị toàn bộ số liệu*

Dashboard là giao diện giám sát trung tâm, hiển thị:

**Thẻ số liệu chính:**
| Số liệu | Mô tả |
|---------|-------|
| Total Requests | Tổng số request được xử lý |
| Blocked | Số request bị chặn |
| Allowed | Số request được phép qua |
| Block Rate | % Bị chặn / Tổng |
| Hosts | Số host proxy đang hoạt động |
| Unique Attackers | Số IP kẻ tấn công riêng biệt |
| Rules Loaded | Tổng quy tắc đang hoạt động (612) |
| Categories | Số danh mục quy tắc (35) |
| Challenged | Request được trả về thách thức |
| Honeypot Hits | Request khớp với đường dẫn honeypot |

**Biểu đồ:**
- **Lưu lượng (24h qua)**: Biểu đồ đường — Hợp lệ (xanh) vs Bị chặn (đỏ)
- **Danh mục tấn công**: Biểu đồ cột — phân tích theo loại tấn công (scanner, rce, ssrf, sqli, xss, ...)
- **Hành động thực thi**: Biểu đồ tròn — phân bố block vs allow
- **Phân bố điểm rủi ro**: Dải màu — Cho phép / Thách thức / Chặn
- **Heatmap tấn công Endpoint**: Heatmap thời gian × đường dẫn
- **Top quốc gia tấn công**: Bản đồ địa lý
- **Top 20% kẻ tấn công**: IP tấn công tích cực nhất
- **Top IP tấn công**: Danh sách IP xếp hạng với số lần chặn
- **Top quy tắc được kích hoạt**: Rule ID bị bắn nhiều nhất
- **Top IP theo rủi ro**: Điểm rủi ro tích lũy cao nhất
- **Detection Engines**: Trạng thái 12 hệ thống phát hiện
- **Recent Security Events**: Feed thời gian thực 20 sự kiện gần nhất
- **Live Security Events**: Luồng WebSocket thời gian thực

**Bộ lọc:** Chọn host, lọc hành động, cửa sổ thời gian (1h/6h/24h/7d), Reset.

---

### 4.3 Hosts

![Trang Hosts với dialog New Host](screenshots/screencapture-localhost-16827-ui-login-2026-05-22-22_30_42.png)

*Hình 4.3 — Quản lý Proxy Hosts (dialog New Host đang mở)*

**Hosts** định nghĩa ánh xạ backend upstream cho reverse proxy.

**Phần sidebar hiển thị:** Dashboard, Hosts, IP Rules, URL Rules, Security Events, Security Logs, SSL Certificates, CC Protection, Notifications, Settings, **Rules** (Rule Manager, Custom Rules, Rule Sources, Rule Analytics, Bot Detection), **Cluster** (Overview, Join Tokens, Sync Status), **CrowdSec** (CS Settings, CS Decisions, CS Stats), **Cache** (Cache Dashboard), **Fraud Detection** (TX Velocity)

**Các trường trong dialog New Host:**

| Trường | Mô tả | Ví dụ |
|--------|-------|-------|
| Host | Domain/hostname cần khớp | `api.example.com` |
| Port | Cổng lắng nghe cho vhost này | `80` |
| Upstream | IP/hostname backend | `127.0.0.1` |
| Upstream Port | Cổng backend | `8080` |
| Remarks | Mô tả tùy chọn | `Production API` |
| SSL | Bật kết thúc TLS | toggle |
| Guard | Bật kiểm tra WAF | toggle (mặc định BẬT) |
| Start | Bật host này | toggle (mặc định BẬT) |
| Log only | Chế độ chỉ log (không chặn) | toggle |

> **Hot-reload:** Thay đổi host có hiệu lực ngay lập tức, không cần khởi động lại.

---

### 4.4 IP Rules

![Trang IP Rules](screenshots/screencapture-localhost-16827-ui-login-2026-05-22-22_31_06.png)

*Hình 4.4 — IP Rules: Allow List (trái) và Block List (phải)*

IP Rules cung cấp **kiểm soát truy cập theo CIDR per-host**:

- **Allow List** — IP/CIDR bỏ qua kiểm tra (tùy theo whitelist mode của tier)
- **Block List** — IP/CIDR bị chặn ngay lập tức với 403

Định dạng hỗ trợ: `192.168.1.5`, `10.0.0.0/8`, `2001:db8::/32` (IPv4 và IPv6)

> **Mapping giai đoạn:** Allow List → Giai đoạn 1 (cho phép nhanh), Block List → Giai đoạn 2 (chặn nhanh)

---

### 4.5 URL Rules

![Trang URL Rules](screenshots/screencapture-localhost-16827-ui-login-2026-05-22-22_31_23.png)

*Hình 4.5 — URL Rules: Allow URLs (trái) và Block URLs (phải)*

URL Rules cung cấp **kiểm soát truy cập theo đường dẫn**:

- **Allow URLs** — đường dẫn bỏ qua toàn bộ pipeline WAF (Giai đoạn 3)
- **Block URLs** — đường dẫn bị chặn ngay lập tức (Giai đoạn 4)

Mẫu hỗ trợ:
- Literal: `/health`, `/api/public`
- Regex: `^/admin/.*`, `\.(jpg|png|gif)$`
- Wildcard: `/static/*`

> **Lưu ý:** URL allowlist bỏ qua TẤT CẢ giai đoạn WAF tiếp theo — dùng cẩn thận.

---

### 4.6 Security Events

![Trang Security Events](screenshots/screencapture-localhost-16827-ui-login-2026-05-22-22_31_37.png)

*Hình 4.6 — Security Events: log tấn công với 3.718 sự kiện*

Security Events là **log tấn công chính**. Mỗi sự kiện ghi lại:

| Trường | Mô tả |
|--------|-------|
| Time | Timestamp của request bị chặn |
| Client IP | Địa chỉ IP nguồn |
| Method | HTTP method (GET, POST, ...) |
| Path | URI path của request |
| Rule | Danh mục quy tắc kích hoạt |
| Rule ID | Định danh quy tắc cụ thể (vd: `SSRF-006`) |
| Action | Quyết định: block / allow / challenged |

**Tab:** All actions · Block · Allow · Challenged · Honeypot

**Bộ lọc:** Host code, Client IP, Rule ID, Tên rule, Path, Action, Country

**Tổng sự kiện:** 3.718 (186 trang × 20/trang)

#### Panel Chi Tiết Sự Kiện

![Chi tiết Security Event](screenshots/screencapture-localhost-16827-ui-login-2026-05-22-22_34_04.png)

*Hình 4.6b — Event Detail: Request Info, Rule Info, Attack Payload*

Nhấp vào bất kỳ sự kiện nào để mở panel chi tiết:
- **Request Info**: Thời gian, Host code, Client IP, Method, Path, Action
- **Rule Info**: Tên rule, Rule ID
- **Attack Payload**: Payload thực tế kích hoạt quy tắc (vd: `localhost / loopback hostname |localhost| referenced from cookie`)
- **Hành động nhanh**: Nút "Create Custom Rule from This Event"

#### Tạo Quy Tắc Tùy Chỉnh Từ Sự Kiện

![Tạo Custom Rule từ sự kiện](screenshots/screencapture-localhost-16827-ui-login-2026-05-22-22_34_17.png)

*Hình 4.6c — Tự động tạo quy tắc tùy chỉnh từ sự kiện tấn công*

Trình hướng dẫn tự điền:
- Tên: `Block SSRF from 151.101.2.137`
- Host: mã host tự phát hiện
- Mô tả: tự tạo với UUID và timestamp sự kiện
- Priority: 1 (ưu tiên cao nhất)
- Điều kiện: cây AND với ip eq, method eq, OR header:referer contains
- Action: block / 403

---

### 4.7 Security Logs

![Trang Security Logs](screenshots/screencapture-localhost-16827-ui-login-2026-05-22-22_31_57.png)

*Hình 4.7 — Security Logs: access log đầy đủ với bộ lọc nâng cao*

Security Logs hiển thị **tất cả request** (cả cho phép và bị chặn):

- **Panel bộ lọc nâng cao**: Rule, ip, ct_scan_id, khoảng thời gian, chọn cột
- **Chọn cột**: Bật/tắt cột hiển thị
- **Xuất**: Export CSV của logs đã lọc
- **100 trang** log (lưu lượng lớn)

---

### 4.8 SSL Certificates

![Trang SSL Certificates](screenshots/screencapture-localhost-16827-ui-login-2026-05-22-22_32_08.png)

*Hình 4.8 — Quản lý SSL Certificates (dialog Upload Certificate đang mở)*

**SSL Certificates** quản lý chứng chỉ TLS cho kết thúc HTTPS:

**Các trường dialog Upload Certificate:**
| Trường | Mô tả |
|--------|-------|
| Host | Entry host áp dụng cert này |
| Domain | Tên domain (vd: `example.com`) |
| Certificate PEM | Chuỗi chứng chỉ PEM |
| Private Key PEM | Khóa riêng tư PEM |

**Tính năng bổ sung:**
- **Upload Cert**: upload thủ công PEM
- **Let's Encrypt ACME**: cấp chứng chỉ tự động qua instant-acme (ACME v2)
- **Tự động gia hạn**: gia hạn nền 30 ngày trước khi hết hạn
- Bảng hiển thị: Domain, Ngày hết hạn, Trạng thái (valid/expired/pending)

---

### 4.9 CC Protection & Rate Limiting

![Trang CC Protection](screenshots/screencapture-localhost-16827-ui-login-2026-05-22-22_32_26.png)

*Hình 4.9 — CC Protection & Rate Limiting + Anti-Hotlink Config*

Trang này bao gồm hai hệ thống con:

**Load Balancer Backends (panel trái):**
- Thêm server upstream cho cân bằng tải
- Mỗi backend: IP/hostname + cổng + weight
- Cấu hình health check

**Anti-Hotlink Config (panel phải):**
| Trường | Mô tả |
|--------|-------|
| Host code | Áp dụng cho host cụ thể hoặc `*` toàn cục |
| Enabled | Bật/tắt bảo vệ hotlink |
| Allow empty referer | Cho phép request không có header Referer |
| Redirect URL | URL chuyển hướng tùy chọn cho tài nguyên bị hotlink |

> **Giới hạn tốc độ** cấu hình qua `configs/rate-limit.yaml` (hot-reload). Xem §7.3 để biết schema đầy đủ.

---

### 4.10 Notifications

![Trang Notifications](screenshots/screencapture-localhost-16827-ui-login-2026-05-22-22_32_40.png)

*Hình 4.10 — Notifications: dialog New Notification Config*

Cấu hình kênh cảnh báo cho sự kiện bảo mật:

**Các trường dialog New Notification Config:**
| Trường | Tùy chọn | Mô tả |
|--------|---------|-------|
| Name | (văn bản) | Tên cấu hình |
| Channel | Webhook / Email / Telegram | Kênh gửi |
| Event | Attack Detected / Rate Limited / ... | Điều kiện kích hoạt |
| Host code | (văn bản) | Giới hạn phạm vi host cụ thể |
| Channel Config (JSON) | `{}` | Cài đặt đặc thù kênh |

**Ví dụ cấu hình Webhook:**
```json
{
  "url": "https://hooks.slack.com/services/...",
  "method": "POST",
  "headers": {"Content-Type": "application/json"}
}
```

**Ví dụ cấu hình Telegram:**
```json
{
  "bot_token": "123456:ABC-DEF",
  "chat_id": "-100123456789"
}
```

---

### 4.11 Settings

![Trang Settings](screenshots/screencapture-localhost-16827-ui-login-2026-05-22-22_32_55.png)

*Hình 4.11 — System Settings: panel cấu hình đầy đủ*

Trang Settings hiển thị cấu hình runtime cho WAF engine:

**System Status:**
- Version, Active Visitors, Total Requests
- Đường dẫn config file, rate config, panel TOML

**Shadow Mode (dry-run):**
- Khi bật: tính toán quyết định chặn nhưng không thực thi — chỉ log
- Hữu ích để test quy tắc mới không ảnh hưởng traffic

**Risk Thresholds (Ngưỡng rủi ro):**
- Allow (0): slider → mặc định 31
- Challenge (1): slider → mặc định 74
- Block from score: → 75
- Dải ngưỡng trực quan (xanh → cam → đỏ)

**Challenge Engine:**
- Loại thách thức: `JS challenge` (JavaScript proof-of-work phía client)

**Honeypot Paths:**
- Đường dẫn được đánh dấu là honeypot (mọi request → ghi nhận honeypot hit)
- Mặc định: `/env`, `/pCloud/config`, `/.git/config`, `/passwd/credentials`, `/.aws/credentials`

**Response Filtering:**
- Chặn stack trace trong phản hồi: toggle (mặc định BẬT)
- Redact JSON fields: `password`, `token`, `secret`, `api_key`

**Trusted IPs/CIDRs (danh sách bypass):**
- IP bỏ qua kiểm tra tự động
- Mặc định: `127.0.0.1/32`, `::1/128`, `90.181.2.131`

**Rate Limits & Session:**
| Cài đặt | Mặc định | Mô tả |
|---------|---------|-------|
| Default rate limit (reqs) | 100 | Giới hạn request per-IP |
| Burst limit | 200 | Dung lượng token-bucket burst |
| Session expiry (seconds) | 3600 | TTL phiên |
| Global rate limit (reqs, 0=off) | 0 | Giới hạn tốc độ toàn cục |
| Request timeout (seconds, 0=off) | 30 | Timeout per-request |
| Fail open (upstream unavailable) | toggle | Fail-open khi backend down |

**Auto-block:**
- Enabled: toggle
- Minimum events: 6
- Window (seconds): 60

**Threat Intelligence:**
Tab: Tor Exit Nodes · Blocked ASNs

Bảng Feed Status hiển thị nguồn quy tắc với số lượng:
| Nguồn | Quy Tắc Được Bật |
|-------|-----------------|
| advanced | 77 |
| owasp-crs | 328/636 |
| modsecurity | 46 |
| cve-patches | 43 |
| bot-detection | 42 |
| owasp-api | 64 |
| custom | 10 |

---

### 4.12 Rule Manager

![Trang Rule Management](screenshots/screencapture-localhost-16827-ui-login-2026-05-22-22_33_06.png)

*Hình 4.12 — Rule Management: 612 quy tắc trong 36 danh mục*

Rule Manager hiển thị **tất cả 612 quy tắc tích hợp** với đầy đủ chi tiết:

**Thanh thống kê:**
- Tổng quy tắc: **612**
- Được bật: **612**
- Bị tắt: **0**
- Danh mục: **36**

**Cột bảng:**
| Cột | Mô tả |
|-----|-------|
| Rule ID | Định danh duy nhất (vd: `ADV-SSTI-001`) |
| Name | Tên dễ đọc của quy tắc |
| Category | Danh mục phát hiện (ssti, prototype-pollution, sqli, ...) |
| Source | Bộ quy tắc (advanced, owasp-crs, cve-patches, ...) |
| Severity | critical / high / medium / low |
| Action | block / log / allow |
| Status | Toggle Enable / Disable |

**Bộ lọc:** Tìm kiếm theo tên, lọc theo danh mục, nguồn, trạng thái

**Mẫu quy tắc hiển thị (trang đầu):**
- `ADV-SSTI-001` — SSTI - Generic Expression Evaluation Test (`${7*7}`)
- `ADV-SSTI-002` — SSTI - Jinja2 Config Object Access
- `ADV-SSTI-003` — SSTI - Jinja2 Class Traversal for RCE
- `ADV-SSTI-004` — SSTI - Twig Template Engine Exploitation
- ... (612 tổng, 31 trang)
- `ADV-PROTO-001..007` — Prototype Pollution (`__proto__`, `constructor.prototype`, ...)

#### Dialog Import Rules

![Dialog Import Rules](screenshots/screencapture-localhost-16827-ui-login-2026-05-22-22_33_33.png)

*Hình 4.12b — Import Rules: tải từ file path hoặc URL*

- **Source**: đường dẫn file (`rules/custom.yaml`) hoặc URL (`https://...`)
- **Format**: YAML (mặc định) hoặc JSON

---

### 4.13 Custom Rules

![Trang Custom Rules](screenshots/screencapture-localhost-16827-ui-login-2026-05-22-22_33_48.png)

*Hình 4.13 — Custom Rules: drawer Create Custom Rule*

Custom Rules là **quy tắc lưu trong DB** được quản lý hoàn toàn qua UI.

**Các trường drawer Create Custom Rule:**

| Trường | Kiểu | Mô tả |
|--------|------|-------|
| Name | văn bản | Tên quy tắc |
| Host | dropdown | Host mục tiêu hoặc `*` toàn cục |
| Description | textarea | Mô tả quy tắc |
| Priority | số | Thấp hơn = ưu tiên cao hơn (mặc định: 100) |
| Action | dropdown | block / allow / log / challenge |
| Action status | số | HTTP status code (mặc định: 403) |
| Action message | văn bản | Thông điệp phản hồi tùy chỉnh |
| Enabled | toggle | Đang hoạt động hay không |
| Visual / JSON | tab | Chế độ xây dựng điều kiện |
| + Add AND group | nút | Thêm nhóm điều kiện AND |
| + Add OR group | nút | Thêm nhóm điều kiện OR |
| Rhai Script | textarea | Ghi đè bằng biểu thức Rhai |

**Trường điều kiện hỗ trợ:** `ip`, `path`, `query`, `method`, `body`, `host`, `user_agent`, `content_type`, `content_length`, `header:<tên>`, `cookie:<tên>`, `geo_country`, `geo_iso`

**Toán tử:** `eq`, `ne`, `contains`, `not_contains`, `starts_with`, `ends_with`, `regex`, `wildcard`, `in_list`, `not_in_list`, `cidr_match`, `gt`, `lt`, `gte`, `lte`, `detect_sqli`, `detect_xss`

**Ví dụ quy tắc (chế độ JSON):**
```json
{
  "name": "Chặn admin từ IP không tin cậy",
  "host_code": "myapp",
  "priority": 10,
  "action": "block",
  "action_status": 403,
  "risk_delta": 50,
  "match_tree": {
    "and": [
      { "field": "path", "operator": "starts_with", "value": "/admin/" },
      { "not": { "field": "ip", "operator": "cidr_match", "value": "10.0.0.0/8" } }
    ]
  }
}
```

---

### 4.14 Rule Sources

![Trang Rule Sources](screenshots/screencapture-localhost-16827-ui-login-2026-05-22-22_34_31.png)

*Hình 4.14 — Rule Sources: nguồn tích hợp và dialog Add Rule Source*

**Built-in Sources** (chỉ đọc, luôn có sẵn):

| Nguồn | Quy Tắc | Loại |
|-------|---------|------|
| advanced | 77 | builtin |
| bot-detection | 42 | builtin |
| custom | 10 | builtin |
| cve-patches | 43 | builtin |
| geoip | 2 | builtin |
| modsecurity | 46 | builtin |
| owasp-api | 64 | builtin |
| owasp-crs | 328 | builtin |

**Dialog Add Rule Source:**
| Trường | Mô tả |
|--------|-------|
| Source Name | Định danh nguồn này |
| Type | Remote URL |
| URL | `https://example.com/rules.yaml` |
| Format | YAML / JSON |
| Update Interval | Giây giữa các lần đồng bộ (mặc định: 86400 = 24h) |

---

### 4.15 Rule Analytics

![Trang Rule Analytics](screenshots/screencapture-localhost-16827-ui-login-2026-05-22-22_34_43.png)

*Hình 4.15 — Rule Analytics: phân bố tấn công, top quy tắc, timeline lưu lượng*

**Biểu đồ:**
- **Tổng WAF Requests theo Rule Group** (donut): scanner, rce, ssrf, owasp-crs, advanced, sqli, xss, api-security, mass-assignment, data-leakage, lxe, txd, path-traversal, other
- **WAF Actions** (donut): phân bố block

**Top Blocked Request URIs:** Treemap các đường dẫn bị tấn công nhiều nhất:
- `/favicon.ico` — 22 lần
- `/` — 22 lần
- `/gpanel/` — 19 lần
- `/api/dashboard/stats` — 10 lần
- `/api/feedbacks` — 10 lần
- `/login` — 1 lần
- ... và nhiều đường dẫn khác

**Top Triggered Rules:**
| Quy tắc | Số lần |
|---------|--------|
| Scanner | 1.836 |
| RCE | 400 |
| SSRF | 389 |
| SQL Injection | 193 |
| XSS | (số lượng) |
| SSTI - Generic Expression Evaluation Test | 47 |
| SSRF - Dangerous URL Schemes | 41 |
| PHP Injection - Script File Upload | 43 |
| PHP Injection - Variable Access | 43 |
| Node.js Injection Attack V2 | 40 |

**Bộ lọc:** Khoảng thời gian (1h/6h/24h/7d), lọc host, Export CSV, Refresh

---

### 4.16 Bot Management

![Trang Bot Management](screenshots/screencapture-localhost-16827-ui-login-2026-05-22-22_34_52.png)

*Hình 4.16 — Bot Management: mẫu phát hiện bot theo danh mục*

Bot Management tổ chức mẫu phát hiện thành các tab:

**Tab: Good Bots (Allow) — 8 mẫu**
Googlebot, Bingbot, DuckDuckBot, Slurp, Baiduspider, YandexBot, facebot, ia_archiver — crawler được phép.

**Tab: Bad Bots (Block) — 3 mẫu đang hoạt động:**

| ID | Tên | Mẫu | Hành động |
|----|-----|-----|-----------|
| BOT-BAD-001 | Scrapy web scraper | `(?i)\bscrapy\b` | block |
| BOT-BAD-007 | Generic crawler/spider/scraper UA | `(?i)\b(crawler\|spider\|scraper)\b` | block |
| BOT-BAD-008 | Harvester / extractor tool | `(?i)\b(harvest\|extractor)\b` | block |

**Tab: AI Crawlers — 8 mẫu**
GPTBot, Claude-Web, CCBot, anthropic-ai, Bytespider, PetalBot, ...

**Tab: SEO Tools — 3 mẫu**
Ahrefs, Semrush, Moz

**Tab: Custom — 0 mẫu** (do người dùng định nghĩa)

**Công cụ Test User-Agent:** Nhập chuỗi UA bất kỳ và nhấn Test để kiểm tra khớp mẫu nào.

#### Dialog Add Bot Pattern

![Dialog Add Bot Pattern](screenshots/screencapture-localhost-16827-ui-login-2026-05-22-22_34_59.png)

*Hình 4.16b — Add Bot Pattern: regex + tên + hành động*

| Trường | Mô tả |
|--------|-------|
| Pattern (regex) | vd: `(?i)\bMyBot\b` |
| Name | Tên dễ đọc |
| Action | Block / Allow |
| Description | Mô tả tùy chọn |

---

### 4.17 CrowdSec Integration

#### CS Settings

![CrowdSec Settings](screenshots/screencapture-localhost-16827-ui-login-2026-05-22-22_35_43.png)

*Hình 4.17a — Cài đặt Tích Hợp CrowdSec*

| Trường | Mô tả |
|--------|-------|
| Enable CrowdSec Integration | Toggle master |
| Mode | Bouncer (pull decisions from LAPI) |
| Fallback Action | Allow (fail open) / Block (fail close) |
| LAPI URL | `http://127.0.0.1:8080` |
| Bouncer API Key | API key từ CrowdSec LAPI |
| Update Frequency | Giây giữa các lần đồng bộ quyết định (mặc định: 10) |

Hành động: **Save Configuration**, **Test Connection**

**Trạng thái hiện tại:** CrowdSec Inactive (chưa cấu hình)

#### CS Decisions

![CrowdSec Decisions](screenshots/screencapture-localhost-16827-ui-login-2026-05-22-22_35_58.png)

*Hình 4.17b — CrowdSec Decisions: các quyết định ban/captcha đang hoạt động từ LAPI*

Cột bảng: Value (IP/CIDR), Type (ban/captcha), Scenario, Origin, Scope, Duration

Bộ lọc: IP/value, type, scenario

#### CS Stats

![CrowdSec Statistics](screenshots/screencapture-localhost-16827-ui-login-2026-05-22-22_36_08.png)

*Hình 4.17c — CrowdSec Statistics: hiệu suất cache*

| Số liệu | Giá trị |
|---------|---------|
| Cached Decisions | 0 |
| Cache Hits | 0 |
| Cache Hit Rate | 0,0% |

Biểu đồ: Decisions by Type (tròn), Top Scenarios (cột)

---

### 4.18 Cache Dashboard

![Cache Dashboard](screenshots/screencapture-localhost-16827-ui-login-2026-05-22-22_36_17.png)

*Hình 4.18 — Cache Dashboard: số liệu hiệu suất cache thời gian thực*

**Số liệu:**
| Số liệu | Giá trị |
|---------|---------|
| Hit Ratio | 0,0% |
| Entries | 0 |
| Memory Used | 1,0 MB |
| Ops / sec | 0 |

**Hit / Miss Timeline (60 min):** Biểu đồ đường tỷ lệ hit/miss

**Top Cached Routes:** Bảng — Route, Hits, Entries

**Backend Info:**
| Trường | Giá trị |
|--------|---------|
| Mode | Standalone |
| Version | 8.1.6 |
| Circuit Breaker | closed ✓ |
| Connected | ✓ |
| Memory Used | 1,1 MB / 256,0 MB (0,4%) |

**Cache Actions:**
- **Purge by Tag** — xóa cache theo tag
- **Purge by Route** — xóa cache theo route cụ thể
- **Flush All Cache** — xóa toàn bộ cache (nguy hiểm)

---

### 4.19 TX Velocity & Sequence

![Trang TX Velocity](screenshots/screencapture-localhost-16827-ui-login-2026-05-22-22_36_26.png)

*Hình 4.19 — TX Velocity & Sequence: FR-012 phát hiện gian lận đa endpoint*

**FR-012** phát hiện mẫu gian lận kiểu fintech qua nhiều endpoint.

**Số liệu:**
| Số liệu | Mô tả |
|---------|-------|
| Sequence Violations | Login→OTP→Deposit hoàn thành < 1500ms |
| Withdrawal Bursts | ≥5 rút tiền trong cửa sổ 60 giây |
| Limit-Change Storms | ≥3 yêu cầu thay đổi giới hạn trong 5 phút |
| Total TX Events | Tổng sự kiện giao dịch được theo dõi |

**Ngưỡng phát hiện** (từ `configs/tx-velocity.yaml`):

| Tín hiệu | Điều kiện |
|----------|-----------|
| `TX-SEQ-*` | Chuỗi Login → OTP → Deposit hoàn thành < 1500 ms |
| `TX-WITHDRAW-*` | ≥ 5 lần rút tiền trong cửa sổ 60 giây |
| `TX-LIMIT-*` | ≥ 3 yêu cầu thay đổi giới hạn trong 5 phút |

**Signal Distribution:** Biểu đồ phân bố loại tín hiệu

**Bảng Recent TX Events:** Thời gian, Signal Type, Rule ID, Client IP, Action, Rule

---

## 5. Pipeline Phát Hiện WAF

### 5.1 Sơ Đồ Pipeline Đầy Đủ

```mermaid
flowchart LR
    subgraph PRE ["Tiền-Xử Lý"]
        direction TB
        FR007[Phát hiện Relay FR-007\nXFF · ASN · Tor exit\n→ ClientIdentity]
        FR010[Nhận diện Thiết Bị FR-010\nJA3/JA4 · H2 Akamai\n→ DeviceIdentity]
    end

    subgraph GATE ["Giai Đoạn 0: Access Gate FR-008"]
        HG[Host Gate\nFQDN allowlist per-tier]
        BL[IP Blacklist\nPatricia-trie CIDR]
        WL[IP Whitelist\nCIDR → full_bypass hoặc blacklist_only]
        HG --> BL --> WL
    end

    subgraph FAST ["Giai Đoạn 1-4: Fast-Path"]
        P1[GĐ 1: IP Whitelist]
        P2[GĐ 2: IP Blacklist]
        P3[GĐ 3: URL Whitelist\n→ bỏ qua tất cả]
        P4[GĐ 4: URL Blocklist]
    end

    subgraph RATE ["Giai Đoạn 5-5.7: Tốc độ & Hành vi"]
        P5[GĐ 5: Rate Limit FR-004\nToken-bucket + Sliding-window\nkhóa IP + Session]
        P55[GĐ 5.5: DDoS FR-005\nPer-IP · Per-FP · Per-Tier\nBan TTL 60s · RiskBump]
        P56[GĐ 5.6: TX Velocity FR-012\nSequence · Withdrawal · LimitChange]
        P57[GĐ 5.7: Dị thường Hành vi FR-011\n16-slot ring · cadence · path]
    end

    subgraph ATK ["Giai Đoạn 6-11: Phát Hiện Tấn Công"]
        P6[GĐ 6: Phát hiện Scanner\nNikto · Nessus · OpenVAS UA]
        P7[GĐ 7: Phát hiện Bot\nHeadless · credential-stuffing]
        P8[GĐ 8: SQL Injection\nlibinjection + 19 regex\nURL-decode 3 vòng]
        P9[GĐ 9: XSS\nlibinjection + regex]
        P10[GĐ 10: RCE\nShell metachar · EL · Log4Shell]
        P11[GĐ 11: Traversal + SSRF\n../ · RFC1918 · DNS rebinding]
    end

    subgraph RULES ["Giai Đoạn 12-16: Rule Engines"]
        P12[GĐ 12: Quy tắc tùy chỉnh FR-003\nCây AND/OR/NOT\nJSON DSL + Rhai]
        P13[GĐ 13: OWASP CRS\n24+ danh mục]
        P14[GĐ 14: Dữ liệu nhạy cảm\nAho-Corasick PII]
        P15[GĐ 15: Anti-Hotlink\nKiểm tra Referer]
        P16[GĐ 16: CrowdSec\nBouncer + AppSec]
    end

    subgraph POST ["Sau Quyết Định"]
        RS[Chấm điểm rủi ro FR-025\nL0 seed + L1 tích lũy + L2 anomaly+velocity\nSuy giảm · Ngưỡng]
        Cache[FR-009 Cache thông minh\nValkey / moka LRU\nTTL theo tier · Xóa theo tag]
    end

    PRE --> GATE --> FAST --> RATE --> ATK --> RULES --> POST
```

### 5.2 Tham Chiếu Từng Giai Đoạn

| Giai Đoạn | Tên | FR | Cơ Chế | Điều Kiện Chặn |
|-----------|-----|-----|---------|----------------|
| 0 | Access Gate | FR-008 | Patricia-trie CIDR, Host gate | host không trong allowlist / IP trong blacklist |
| 1 | IP Whitelist | — | Tra cứu bảng CIDR | — (đường dẫn cho phép) |
| 2 | IP Blacklist | — | Tra cứu bảng CIDR | IP khớp CIDR blocklist |
| 3 | URL Whitelist | — | Khớp path regex + literal | — (bỏ qua toàn bộ) |
| 4 | URL Blocklist | — | Khớp path regex + literal | path khớp blocklist |
| 5 | Giới hạn tốc độ | FR-004 | Token-bucket + sliding-window | vượt giới hạn IP hoặc session |
| 5.5 | Phát hiện DDoS | FR-005 | Sliding-window per-IP/FP/Tier | HardBurst → Ban hoặc RiskBump |
| 5.6 | TX Velocity | FR-012 | Sequence FSM + ring buffer | dị thường chuỗi → tín hiệu rủi ro |
| 5.7 | Dị thường Hành vi | FR-011 | 16-slot ring, giới hạn tín hiệu ≤40 | dị thường → tín hiệu rủi ro |
| 6 | Phát hiện Scanner | — | UA fingerprint + mẫu request | khớp chữ ký scanner |
| 7 | Phát hiện Bot | — | Phân tích UA + marker headless | khớp UA bot xấu |
| 8 | Phát hiện SQLi | — | libinjection + 19 regex | phát hiện payload SQLi |
| 9 | Phát hiện XSS | — | libinjection + regex | phát hiện payload XSS |
| 10 | Phát hiện RCE | — | Shell metachar + mẫu EL | phát hiện payload RCE |
| 11 | Traversal/SSRF | FR-016 | Chuẩn hóa path + RFC1918 | phát hiện traversal hoặc SSRF |
| 12 | Quy tắc tùy chỉnh | FR-003 | Cây điều kiện AND/OR/NOT | điều kiện quy tắc khớp |
| 13 | OWASP CRS | — | 24+ bộ mẫu đã biên dịch | khớp quy tắc CRS |
| 14 | Dữ liệu nhạy cảm | — | Aho-Corasick đa mẫu | từ khóa nhạy cảm trong request |
| 15 | Anti-Hotlink | — | Kiểm tra header Referer | Referer không trong allowlist |
| 16 | CrowdSec | — | Cache quyết định LAPI + AppSec | IP có quyết định ban/captcha |
| Sau | Chấm điểm rủi ro | FR-025 | Tích lũy L0+L1+L2 | điểm ≥ ngưỡng challenge/block |

---

## 6. Danh Mục Quy Tắc Đầy Đủ

### 6.1 OWASP Core Rule Set (`rules/owasp-crs/`) — 328 quy tắc

| File | Rule IDs | Danh Mục | Mô Tả |
|------|----------|----------|-------|
| `sqli.yaml` | CRS-942100..942551 | sqli | SQL injection qua libinjection + mẫu function/keyword |
| `xss.yaml` | CRS-941100..941999 | xss | Cross-site scripting (DOM, reflected, stored) |
| `lfi.yaml` | CRS-930100..930999 | lfi | Local file inclusion, path traversal |
| `rfi.yaml` | CRS-931100..931999 | rfi | Remote file inclusion qua HTTP/FTP/PHP |
| `rce.yaml` | CRS-932100..932999 | rce | OS command injection, shell metacharacter |
| `generic-attack.yaml` | CRS-950100..950999 | generic | Mẫu tấn công chung và phát hiện dị thường |
| `protocol-enforcement.yaml` | CRS-920100..920999 | protocol | Kiểm tra tuân thủ giao thức HTTP |
| `method-enforcement.yaml` | CRS-911100..911999 | protocol | Hạn chế HTTP method |
| `scanner-detection.yaml` | CRS-913100..913999 | scanner | Chữ ký UA scanner lỗ hổng |
| `session-fixation.yaml` | CRS-943100..943999 | session | Mẫu tấn công session fixation |
| `multipart-attack.yaml` | CRS-922100..922999 | upload | Vector tấn công multipart body |
| `php-injection.yaml` | CRS-933100..933999 | php | Mẫu injection PHP code |
| `java-injection.yaml` | CRS-944100..944999 | java | Injection biểu thức Java/Spring |
| `web-shells.yaml` | CRS-955100..955999 | webshell | Chữ ký upload/truy cập web shell |
| `data-leakage.yaml` | CRS-950900..950999 | outbound | Phát hiện rò rỉ dữ liệu phản hồi |
| `data-leakage-sql.yaml` | CRS-951100..951999 | outbound | Thông điệp lỗi SQL trong phản hồi |
| `data-leakage-java.yaml` | CRS-952100..952999 | outbound | Rò rỉ exception Java |
| `response-web-shells.yaml` | CRS-955200..955999 | outbound | Chỉ báo web shell trong phản hồi |
| `response-iis-errors.yaml` | CRS-950120..950199 | outbound | Phát hiện lỗi IIS |
| `response-php-errors.yaml` | CRS-953100..953999 | outbound | Lộ chi tiết lỗi PHP |
| `response-sql-errors.yaml` | CRS-951200..951999 | outbound | Chi tiết lỗi SQL trong phản hồi |
| `response-ruby-errors.yaml` | CRS-954100..954999 | outbound | Lộ exception Ruby |
| `protocol-attack.yaml` | CRS-921100..921999 | protocol | HTTP request smuggling, header injection |
| `response-data-leakage.yaml` | CRS-950100..950199 | outbound | Dữ liệu nhạy cảm chung trong phản hồi |

### 6.2 Vá Lỗi CVE (`rules/cve-patches/`) — 43 quy tắc

| File | CVE | Danh Mục | Mô Tả |
|------|-----|----------|-------|
| `2021-log4shell.yaml` | CVE-2021-44228, -45046, -45105 | rce | Log4Shell JNDI injection — nhiều biến thể mã hóa |
| `2022-spring4shell.yaml` | CVE-2022-22965, -22963 | rce | Spring Framework khai thác `class.module.classLoader` |
| `2022-text4shell.yaml` | CVE-2022-42889 | rce | Apache Commons Text string interpolation RCE |
| `2023-moveit.yaml` | CVE-2023-34362, -35036 | sqli/rce | MOVEit Transfer SQL injection + bypass xác thực |
| `2024-xz-backdoor.yaml` | CVE-2024-3094 | backdoor | Phát hiện backdoor XZ Utils |
| `2024-recent.yaml` | Nhiều CVE 2024 | mixed | Vá lỗi lỗ hổng nghiêm trọng 2024 |
| `2025-recent.yaml` | Nhiều CVE 2025 | mixed | Vá lỗi lỗ hổng nghiêm trọng 2025 |

### 6.3 Quy Tắc Nâng Cao (`rules/advanced/`) — 77 quy tắc

| File | Danh Mục | Quy Tắc | Mô Tả |
|------|----------|---------|-------|
| `ssrf.yaml` | ssrf | ~15 | SSRF — dải RFC1918, DNS rebinding, loopback, cloud metadata IP |
| `ssti.yaml` | ssti | 13 | SSTI — Jinja2, Twig, Freemarker, Velocity, Smarty, Pebble, Mako, ERB, Handlebars, SpEL |
| `xxe.yaml` | xxe | ~10 | XXE — DOCTYPE SYSTEM/PUBLIC, entity references |
| `deserialization.yaml` | deserialization | ~12 | Java/PHP/Python payload deserialization, gadget chain ysoserial |
| `prototype-pollution.yaml` | prototype-pollution | 7 | JS `__proto__`, `constructor.prototype`, `Object.prototype` |
| `webshell-upload.yaml` | webshell | ~20 | Upload web shell: .php/.asp/.jsp với chữ ký code |

**Chi tiết 13 quy tắc SSTI:**
- `ADV-SSTI-001`: Generic `${7*7}` expression evaluation
- `ADV-SSTI-002`: Jinja2 `config` object access
- `ADV-SSTI-003`: Jinja2 class traversal for RCE (`__class__.__mro__`)
- `ADV-SSTI-004`: Twig `{{7*'7'}}` exploitation
- `ADV-SSTI-005`: Freemarker `<#assign>` injection
- `ADV-SSTI-006`: Velocity `#set($x=...)` injection
- `ADV-SSTI-007`: Smarty PHP template injection
- `ADV-SSTI-008`: Pebble Java template injection
- `ADV-SSTI-009`: Mako Python template injection
- `ADV-SSTI-010`: ERB Ruby `<%= %>` injection
- `ADV-SSTI-011`: Handlebars/Mustache injection
- `ADV-SSTI-012`: Spring EL (SpEL) injection
- `ADV-SSTI-013`: Generic polyglot detection probe

### 6.4 Quy Tắc Bot Detection (`rules/bot-detection/`) — 42 quy tắc

| File | Danh Mục | Mô Tả |
|------|----------|-------|
| `credential-stuffing.yaml` | credential-stuffing | SentryMBA, Storm, Apex, SNIPR, BlackBullet, SilverBullet, Woxy, Lauth |
| `crawlers.yaml` | crawler | Web crawler, scraper bot UA không được ủy quyền |
| `scraping.yaml` | scraping | Mẫu hành vi data scraping và chữ ký công cụ |

### 6.5 Quy Tắc OWASP API Security (`rules/owasp-api/`) — 64 quy tắc

| File | Danh Mục OWASP API | Mô Tả |
|------|-------------------|-------|
| `broken-auth.yaml` | API2:2023 Broken Authentication | JWT none algorithm, nhầm lẫn thuật toán, token yếu |
| `data-exposure.yaml` | API3:2023 Excessive Data Exposure | Mẫu trường nhạy cảm trong phản hồi API |
| `injection.yaml` | API8:2023 Injection | GraphQL injection, REST/SOAP-specific |
| `mass-assignment.yaml` | API6:2023 Mass Assignment | Gán tham số hàng loạt đáng ngờ |
| `rate-abuse.yaml` | API4:2023 Rate Limiting | Mẫu lạm dụng tốc độ API endpoint |

### 6.6 Quy Tắc ModSecurity (`rules/modsecurity/`) — 46 quy tắc

| File | Danh Mục | Mô Tả |
|------|----------|-------|
| `ip-reputation.yaml` | ip-reputation | Header Tor exit, UA trống, tín hiệu IP xấu |
| `dos-protection.yaml` | dos | Dị thường tốc độ request, chữ ký HTTP flood |
| `data-leakage.yaml` | data-leakage | Mẫu rò rỉ dữ liệu outbound |
| `response-checks.yaml` | response | Phát hiện dị thường HTTP response |

### 6.7 GeoIP & Threat Intel

| File | Danh Mục | Mô Tả |
|------|----------|-------|
| `geoip/country-blocklist.yaml` | geoip | Chặn lưu lượng từ quốc gia cụ thể (mã ISO) |
| `threat-intel/hyperscaler-asn-seed.yaml` | asn | Danh sách seed ASN AWS, GCP, Azure, Cloudflare |

### 6.8 Quy Tắc Custom File-Based (`rules/custom/`) — 10 quy tắc

Quy tắc trong `rules/custom/*.yaml` theo schema `custom_rule_v1`:

```yaml
kind: custom_rule_v1
id: CUSTOM-001
name: "Chặn admin từ IP không tin cậy"
enabled: true
priority: 100
host_code: "myapp"           # hoặc "*" cho toàn cục
action: block
action_status: 403
action_msg: "Blocked by WAF"
risk_delta: 50               # Đóng góp điểm rủi ro FR-025

# Cây khớp (ưu tiên)
match_tree:
  and:
    - field: path
      operator: starts_with
      value: /admin/
    - not:
        field: ip
        operator: cidr_match
        value: 10.0.0.0/8

# Hoặc kịch bản Rhai (nâng cao)
script: |
  ctx.path.starts_with("/api/") && ctx.method == "DELETE"
```

**Quy tắc mẫu có sẵn:**
- `example.yaml` — ví dụ cơ bản
- `fr003-sample-cookie-session.yaml` — chặn theo session cookie
- `fr003-sample-nested-blacklist.yaml` — ví dụ AND/OR/NOT lồng nhau
- `fr003-sample-wildcard-admin.yaml` — bảo vệ đường dẫn wildcard

---

## 7. Tham Chiếu Cấu Hình

### 7.1 Cấu Hình Chính (`configs/default.toml`)

```toml
# ── Proxy listener ────────────────────────────────────────────────────────────
[proxy]
listen_addr     = "0.0.0.0:80"
listen_addr_tls = "0.0.0.0:443"

# ── Admin API + UI ────────────────────────────────────────────────────────────
[api]
listen_addr = "0.0.0.0:9527"

# ── Lưu trữ PostgreSQL ────────────────────────────────────────────────────────
[storage]
database_url    = "postgresql://prx_waf:prx_waf@postgres:5432/prx_waf"
max_connections = 20

# ── Cache phản hồi (FR-009) ───────────────────────────────────────────────────
[cache]
enabled          = true
max_size_mb      = 256
default_ttl_secs = 60
max_ttl_secs     = 3600
rules_path       = "rules/cache.yaml"
backend          = "memory"    # memory | embedded | standalone | cluster

# ── Bảo vệ DDoS (FR-005) ─────────────────────────────────────────────────────
[ddos]
enabled = true
store   = "memory"

[ddos.per_ip]
threshold_rps = 1000
window_secs   = 1
ban_ttl_secs  = 60

[ddos.per_tier]
critical_threshold_rps  = 50
high_threshold_rps      = 200
medium_threshold_rps    = 1000
catchall_threshold_rps  = 5000

# ── Giới hạn tốc độ (FR-004) ─────────────────────────────────────────────────
[rate_limit]
config_path = "configs/rate-limit.yaml"

# ── Cấu hình admin panel runtime ─────────────────────────────────────────────
[panel]
config_path = "waf-panel.toml"

# ── Host proxy ────────────────────────────────────────────────────────────────
[[hosts]]
host        = "example.com"
port        = 80
remote_host = "127.0.0.1"
remote_port = 8080
guard_status = true
```

### 7.2 Bảo Vệ Theo Tier (`[tiered_protection]`)

```toml
[tiered_protection]
default_tier = "catch_all"

[[tiered_protection.classifier_rules]]
priority = 100
tier     = "critical"
path     = { kind = "exact", value = "/login" }
method   = ["POST"]

[[tiered_protection.classifier_rules]]
priority = 90
tier     = "high"
path     = { kind = "prefix", value = "/api/" }

[tiered_protection.policies.critical]
fail_mode          = "close"
ddos_threshold_rps = 50
cache_policy       = { mode = "no_cache" }
risk_thresholds    = { allow = 10, challenge = 40, block = 70 }

[tiered_protection.policies.catch_all]
fail_mode          = "open"
ddos_threshold_rps = 4294967295
cache_policy       = { mode = "aggressive", ttl_seconds = 3600 }
risk_thresholds    = { allow = 35, challenge = 65, block = 90 }
```

### 7.3 Giới Hạn Tốc Độ (`configs/rate-limit.yaml`)

```yaml
version: 1
tiers:
  critical:
    ip:
      burst_capacity: 10         # burst tối đa 10 request
      burst_refill_per_s: 5.0    # nạp lại 5 req/giây
      window_secs: 60
      window_limit: 100          # tối đa 100 req trong 60 giây
  high:
    ip:
      burst_capacity: 50
      burst_refill_per_s: 20.0
      window_secs: 60
      window_limit: 500
  catch_all:
    ip:
      burst_capacity: 200
      burst_refill_per_s: 100.0
      window_secs: 60
      window_limit: 5000
```

### 7.4 Danh Sách Truy Cập (`rules/access-lists.yaml`)

```yaml
version: 1
dry_run: false          # true = chỉ log, không chặn

ip_whitelist:
  - 10.0.0.0/8
  - 192.168.1.5

ip_blacklist:
  - 203.0.113.0/24

host_whitelist:         # FQDN allowlist per-tier
  critical:
    - api.example.com
  high: []
  medium: []
  catch_all: []

tier_whitelist_mode:    # full_bypass | blacklist_only
  critical:  blacklist_only
  high:      blacklist_only
  medium:    full_bypass
  catch_all: full_bypass
```

### 7.5 TX Velocity (`configs/tx-velocity.yaml`)

```yaml
tx_velocity:
  schema_version: 1
  enabled: false        # đặt true để kích hoạt
  session_cookie: SESSIONID
  signal_cooldown_ms: 5000
  session_ttl_secs: 600

  role_patterns:
    - role: Login
      pattern: "(?i)^/(?:login|signin|auth/login)$"
    - role: Withdrawal
      pattern: "(?i)^/(?:withdraw|payout|cashout)$"
    - role: LimitChange
      pattern: "(?i)^/(?:limit|settings/transfer)$"

  classifiers:
    sequence_timing:
      enabled: true
      roles: [Login, Otp, Deposit]
      max_duration_ms: 1500
    withdrawal_velocity:
      enabled: true
      max_count: 5
      window_secs: 60
    limit_change_burst:
      enabled: true
      max_count: 3
      window_secs: 300
```

---

## 8. Phân Cụm & Khả Dụng Cao

### 8.1 Topology Phân Cụm

```mermaid
graph TD
    subgraph Main ["Node Chính (Control Plane)"]
        DB[(PostgreSQL)]
        Rules[Registry quy tắc + Changelog]
        AdminUI[Admin UI]
        Raft[Raft-lite Leader]
    end

    subgraph W1 ["Node Worker B"]
        Cache1[In-memory Rule Cache]
        Proxy1[Pingora Proxy]
    end

    subgraph W2 ["Node Worker C"]
        Cache2[In-memory Rule Cache]
        Proxy2[Pingora Proxy]
    end

    Main -->|đồng bộ quy tắc lz4\nQUIC mTLS :16851| W1
    Main -->|đồng bộ quy tắc lz4\nQUIC mTLS :16851| W2
    W1 -->|chuyển tiếp ghi\nQUIC mTLS| Main
    W2 -->|chuyển tiếp ghi\nQUIC mTLS| Main
    LB[Load Balancer] --> Proxy1
    LB --> Proxy2
    LB --> Main
```

### 8.2 Khởi Động Nhanh — 3 Node Docker

```bash
# 1. Tạo certificate cluster (một lần)
podman-compose -f docker-compose.cluster.yml run --rm cluster-init

# 2. Khởi động 3 node
podman-compose -f docker-compose.cluster.yml up -d

# 3. Kiểm tra sức khỏe
curl http://localhost:16827/health    # node-a (main)
curl http://localhost:16828/health    # node-b (worker)
curl http://localhost:16829/health    # node-c (worker)

# 4. Kiểm tra trạng thái cluster
curl http://localhost:16827/api/cluster/status | python3 -m json.tool

# 5. Chạy E2E tests
./tests/e2e-cluster.sh
```

### 8.3 Cấu Hình Node

**Node chính:**
```toml
[cluster]
enabled     = true
node_id     = "node-a"
role        = "main"
listen_addr = "0.0.0.0:16851"
seeds       = []

[cluster.crypto]
ca_cert   = "/certs/cluster-ca.pem"
ca_key    = "/certs/cluster-ca.key"  # chỉ main cần
node_cert = "/certs/node-a.pem"
node_key  = "/certs/node-a.key"
```

**Node worker:**
```toml
[cluster]
enabled     = true
node_id     = "node-b"
role        = "worker"
listen_addr = "0.0.0.0:16851"
seeds       = ["node-a:16851"]

[cluster.crypto]
ca_cert   = "/certs/cluster-ca.pem"
ca_key    = ""   # worker không cần CA key
node_cert = "/certs/node-b.pem"
node_key  = "/certs/node-b.key"
```

---

## 9. Tham Chiếu REST API

Base URL: `http://<host>:16827/api/`  
Xác thực: `Authorization: Bearer <jwt_token>` (ngoại trừ `/api/auth/login` và `/health`)

### 9.1 Bảng Endpoint Đầy Đủ

| Method | Endpoint | Mô Tả |
|--------|----------|-------|
| POST | `/api/auth/login` | Lấy JWT token |
| POST | `/api/auth/refresh` | Làm mới JWT token |
| GET | `/api/hosts` | Danh sách proxy hosts |
| POST | `/api/hosts` | Tạo host |
| GET/PUT/DELETE | `/api/hosts/:id` | Lấy / cập nhật / xóa host |
| GET/POST | `/api/block-ips` | Quản lý IP blocklist |
| DELETE | `/api/block-ips/:id` | Xóa IP |
| GET/POST | `/api/block-urls` | Quản lý URL blocklist |
| DELETE | `/api/block-urls/:id` | Xóa URL pattern |
| GET | `/api/attack-logs` | Log tấn công (phân trang) |
| GET | `/api/security-events` | Sự kiện bảo mật (phân trang, lọc) |
| GET | `/api/security-events/:id` | Chi tiết sự kiện |
| GET | `/api/stats/timeseries-by-category` | Số lượng theo giờ per-category |
| POST | `/api/reload` | Hot-reload tất cả quy tắc |
| GET | `/api/cluster/status` | Topology + sức khỏe cluster |
| POST | `/api/cluster/tokens` | Tạo token tham gia cluster |
| GET/POST | `/api/custom-rules` | CRUD quy tắc tùy chỉnh |
| GET/PUT/DELETE | `/api/custom-rules/:id` | Quản lý quy tắc tùy chỉnh |
| GET | `/api/rules` | Danh sách quy tắc tích hợp |
| PUT | `/api/rules/:id/toggle` | Bật/tắt quy tắc |
| GET/POST | `/api/rule-sources` | Quản lý nguồn quy tắc |
| GET/POST | `/api/ssl` | Quản lý chứng chỉ |
| GET/PUT | `/api/crowdsec/settings` | Cấu hình CrowdSec |
| GET | `/api/crowdsec/decisions` | Quyết định đang hoạt động |
| GET | `/api/crowdsec/stats` | Thống kê CrowdSec |
| GET | `/api/cache/stats` | Thống kê cache |
| POST | `/api/cache/purge/tag` | Xóa cache theo tag |
| POST | `/api/cache/flush` | Xóa toàn bộ cache |
| GET/POST | `/api/notifications` | Quản lý cấu hình thông báo |
| GET | `/health` | Kiểm tra sức khỏe (không xác thực) |
| WS | `/ws/events` | Luồng sự kiện bảo mật thời gian thực |
| WS | `/ws/logs` | Luồng access log thời gian thực |

---

## 10. Tham Chiếu CLI

```
prx-waf [OPTIONS] <LỆNH>

Tùy chọn:
  -c, --config <FILE>   Đường dẫn file cấu hình [mặc định: configs/default.toml]
  -h, --help            In trợ giúp
  -V, --version         In phiên bản

Lệnh:
  run          Khởi động proxy + API server (tất cả hệ thống con)
  migrate      Chạy database migrations PostgreSQL
  seed-admin   Tạo admin mặc định (admin/admin123)
  crowdsec     Quản lý tích hợp CrowdSec
  rules        Quản lý quy tắc
  sources      Quản lý nguồn quy tắc từ xa
  bot          Quản lý phát hiện bot
  cluster      Quản lý phân cụm
```

**Lệnh con rules:**
```bash
prx-waf rules list                     # Liệt kê tất cả quy tắc
prx-waf rules list --category sqli     # Lọc theo danh mục
prx-waf rules list --source owasp-crs  # Lọc theo nguồn
prx-waf rules reload                   # Hot-reload từ disk + DB
prx-waf rules validate                 # Xác thực file YAML
```

**Lệnh con cluster:**
```bash
prx-waf cluster status                   # Topology node
prx-waf cluster token generate --ttl 24h # Tạo token tham gia
```

**Các ví dụ thường dùng:**
```bash
prx-waf rules list --category sqli
prx-waf rules reload
prx-waf cluster token generate --ttl 24h
prx-waf crowdsec status
prx-waf -c /etc/prx-waf/config.toml run
```

---

## 11. Thực Hành Bảo Mật Tốt Nhất

1. **Đổi thông tin đăng nhập mặc định ngay lập tức** — `admin / admin123` phải đổi khi đăng nhập lần đầu.
2. **Hạn chế truy cập Admin API** — Đặt `admin_ip_allowlist` chỉ cho CIDR quản lý.
3. **Bật TOTP 2FA** — Cấu hình qua Settings → System Settings cho tài khoản admin.
4. **Dùng TLS cho Admin API** — Đặt sau nginx/Caddy với cert hợp lệ trong production.
5. **Mật khẩu DB mạnh** — Không dùng mặc định `prx_waf` trong production.
6. **Bật mã hóa AES-256-GCM** — Các giá trị config nhạy cảm được mã hóa at rest mặc định.
7. **Cấu hình Let's Encrypt** — Bật tự động gia hạn ACME cho HTTPS proxy certificate.
8. **Dùng chế độ `blacklist_only`** — Mặc định an toàn hơn; chỉ dùng `full_bypass` cho IP hoàn toàn tin cậy.
9. **Test với `dry_run: true`** — Kiểm tra quy tắc access list mới trước khi thực thi.
10. **Theo dõi Dashboard thường xuyên** — Chú ý đột biến tỷ lệ chặn và danh mục tấn công bất thường.
11. **Cấu hình thông báo cảnh báo** — Đặt Telegram/Webhook cho sự kiện tier Critical.
12. **Tối thiểu 3 node cho HA** — 1 Main + 2 Worker đảm bảo quorum khi một node lỗi.
13. **Đặt `max_request_body_bytes`** — Giới hạn kích thước body để tránh cạn kiệt bộ nhớ.
14. **Xem xét honeypot hits** — Kích hoạt honeypot chỉ ra trinh sát đang diễn ra; điều tra IP.
15. **Cập nhật quy tắc định kỳ** — Đồng bộ nguồn quy tắc từ xa để có vá CVE mới nhất.

---

## 12. Xử Lý Sự Cố

| Triệu Chứng | Nguyên Nhân Có Thể | Giải Pháp |
|-------------|-------------------|-----------|
| 403 tất cả request | IP trong blacklist hoặc access-list chặn | Kiểm tra `rules/access-lists.yaml` và IP Rules trong Admin UI |
| Admin UI không truy cập được | API server chưa khởi động hoặc cổng bị chặn | `curl http://localhost:16827/health` |
| Quy tắc không cập nhật | Hot-reload chưa kích hoạt | `POST /api/reload` hoặc `kill -HUP <pid>` |
| Tỷ lệ false-positive cao | Quy tắc quá chặt | Xem Security Events, dùng `dry_run: true` |
| Node cluster ngắt kết nối | Certificate không khớp hoặc lỗi mạng | Kiểm tra `/api/cluster/status`, xác minh CA cert |
| False positive rate limit | Ngưỡng quá thấp cho lưu lượng | Tăng `ddos_threshold_rps` hoặc điều chỉnh rate-limit YAML |
| Cache không hoạt động | Valkey không truy cập được | Kiểm tra `backend` trong `[cache]`, trạng thái circuit breaker |
| Đăng nhập thất bại | Sai thông tin hoặc TOTP lệch đồng hồ | `prx-waf seed-admin` để reset; kiểm tra đồng bộ clock TOTP |
| Bộ nhớ cao | `max_size_mb` cache quá lớn | Giảm `max_size_mb` trong `[cache]` |
| CrowdSec không hoạt động | Chưa cấu hình | Đặt LAPI URL + API key trong CS Settings |
| TX Velocity không phát hiện | `enabled: false` | Đặt `enabled: true` trong `configs/tx-velocity.yaml` |

**Kiểm tra sức khỏe:**
```bash
curl http://localhost:16827/health
# {"status":"ok","version":"0.2.0","uptime_secs":12345}
```

**Xem log:**
```bash
# Docker Compose
docker compose logs -f prx-waf

# Systemd
journalctl -u prx-waf -f
```

**Hot-reload quy tắc:**
```bash
# Qua API
curl -X POST http://localhost:16827/api/reload \
  -H "Authorization: Bearer <token>"

# Qua signal
kill -HUP $(pgrep prx-waf)

# Qua CLI
prx-waf rules reload
```

---

*PRX-WAF (F&G WAF) · Phiên bản 0.2.0 · Rust 2024 · Pingora · © OpenPRX Community*
