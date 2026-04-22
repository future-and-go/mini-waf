# PRX-WAF: Phân tích Gap & Hướng dẫn Implementation cho Hackathon

**Ngày:** 2026-04-21
**Phiên bản hiện tại:** 0.2.0
**Tổng LOC:** ~26,168 Rust + Vue 3 Dashboard
**Mức độ sẵn sàng:** ~75% (24/39 P0 hoàn thành, 6 partial, 9 thiếu)

---

## 1. Tổng quan Repository & Công nghệ hiện có

### 1.1 Kiến trúc Crate

```
Cargo.toml (workspace)
├── crates/prx-waf/        # Binary entry point, CLI (clap), server bootstrap
├── crates/gateway/         # Pingora reverse proxy, HTTP/3 (quinn), SSL (instant-acme), LB, cache (moka)
├── crates/waf-engine/      # Detection pipeline 18 phase, rules engine, plugins (WASM/Rhai)
├── crates/waf-storage/     # PostgreSQL (sqlx), migrations, models
├── crates/waf-api/         # Axum REST API, JWT/TOTP auth, WebSocket, embedded Vue UI
├── crates/waf-common/      # Shared types: RequestCtx, WafDecision, AppConfig, HostConfig
└── crates/waf-cluster/     # Cluster consensus (QUIC/mTLS), Raft-lite election, rule sync
```

### 1.2 Tech Stack chi tiết

| Layer | Công nghệ | Ghi chú |
|-------|-----------|---------|
| Reverse Proxy | **Pingora** 0.8 (Cloudflare) | HTTP/1.1, HTTP/2 native |
| HTTP/3 | **quinn** 0.11 + **h3** 0.0.8 | QUIC transport |
| TLS | **rustls** 0.23 + **instant-acme** 0.7 | Let's Encrypt auto-renewal |
| API Framework | **Axum** 0.8 | REST + WebSocket |
| Database | **PostgreSQL** 16+ via **sqlx** 0.8 | Async, compile-time checked queries |
| Cache | **moka** 0.12 | LRU cache with TTL, async |
| Concurrent State | **DashMap** 6 + **parking_lot** 0.12 | Lock-free concurrent maps |
| Rules Format | YAML (**serde_yaml_ng**), JSON, ModSecurity subset | Hot-reload via **notify** 6 |
| Scripting | **Rhai** 1.x (sandboxed) | Custom detection rules |
| Plugins | **wasmtime** 43 | WASM sandboxed plugins |
| SQLi/XSS Detection | **libinjectionrs** 0.1 | Port của libinjection (C) |
| Pattern Matching | **aho-corasick** 1 + **regex** 1 | Multi-pattern, sensitive word |
| GeoIP | **ip2region** (git) | Offline IP→Country/ISP lookup |
| Crypto | **aes-gcm** 0.10, **argon2** 0.5, **ed25519-dalek** 2 | Encryption at rest, password hash, signatures |
| Cluster Transport | **quinn** (QUIC) + **rustls** (mTLS) | Encrypted inter-node communication |
| Compression | **lz4_flex** 0.11, **zstd** 0.13 | Rule sync compression |
| Dashboard | **Vue 3** + embedded via **rust-embed** 8 | 11 locales, JWT+TOTP |

### 1.3 Request Pipeline hiện tại (18 Phase)

```
Client → TCP/TLS/QUIC → Pingora Session
  │
  ├─ gateway/proxy.rs::upstream_peer()     → Host routing (HostRouter)
  ├─ gateway/proxy.rs::request_filter()    → WAF inspect (header-only)
  ├─ gateway/proxy.rs::request_body_filter() → WAF inspect (with body, max 64KB preview)
  │
  └─ waf-engine/engine.rs::inspect()  ← CORE PIPELINE
       │
       ├─ GeoIP enrichment (ctx.geo)
       ├─ Phase 1:  IP Whitelist          (checker.rs)
       ├─ Phase 2:  IP Blacklist          (checker.rs)
       ├─ Phase 3:  URL Whitelist         (checker.rs)
       ├─ Phase 4:  URL Blacklist         (checker.rs)
       ├─ Phase 16a: CrowdSec Bouncer     (crowdsec/checker.rs) — cache lookup
       ├─ Phase 18: Community Blocklist    (community/checker.rs)
       ├─ Phase 17: GeoIP Access Control   (checks/geo.rs)
       ├─ Phase 5-11: Attack Detection     (checks/*.rs) — loop qua Vec<Box<dyn Check>>
       │    ├─ Phase 5:  SQL Injection     (checks/sql_injection.rs) — libinjection
       │    ├─ Phase 6:  XSS              (checks/xss.rs) — libinjection
       │    ├─ Phase 7:  RCE              (checks/rce.rs)
       │    ├─ Phase 8:  Scanner          (checks/scanner.rs)
       │    ├─ Phase 9:  Dir Traversal    (checks/dir_traversal.rs)
       │    ├─ Phase 10: Bot              (checks/bot.rs)
       │    └─ Phase 11: Rate Limit/CC    (checks/cc.rs) — token bucket per IP
       ├─ Phase 16b: CrowdSec AppSec      (crowdsec/appsec.rs) — async HTTP
       ├─ Phase 12: Custom Rules Engine    (rules/engine.rs) — Rhai scripting
       ├─ Phase 13: OWASP CRS             (checks/owasp.rs)
       ├─ Phase 14: Sensitive Data         (checks/sensitive.rs) — Aho-Corasick
       └─ Phase 15: Anti-Hotlink          (checks/anti_hotlink.rs)
       │
       └─ WafDecision { action: Allow | Block | LogOnly | Redirect }
```

### 1.4 Core Data Types (waf-common/src/types.rs)

```rust
// Request context — truyền qua toàn bộ pipeline
pub struct RequestCtx {
    pub req_id: String,
    pub client_ip: IpAddr,
    pub client_port: u16,
    pub method: String,
    pub host: String,
    pub port: u16,
    pub path: String,
    pub query: String,
    pub headers: HashMap<String, String>,
    pub body_preview: Bytes,       // max 64KB
    pub content_length: u64,
    pub is_tls: bool,
    pub host_config: Arc<HostConfig>,
    pub geo: Option<GeoIpInfo>,    // GeoIP enrichment
    // ⚠️ THIẾU: device_fingerprint, session_id, risk_score, tier
}

// Decision — chỉ có Allow/Block/LogOnly/Redirect
pub enum WafAction {
    Allow,
    Block { status: u16, body: Option<String> },
    LogOnly,
    Redirect { url: String },
    // ⚠️ THIẾU: Challenge { challenge_type: ChallengeType }
}

// Phase enum — 18 phase hiện tại
pub enum Phase {
    IpWhitelist = 1, IpBlacklist = 2, UrlWhitelist = 3, UrlBlacklist = 4,
    SqlInjection = 5, Xss = 6, Rce = 7, Scanner = 8, DirTraversal = 9,
    Bot = 10, RateLimit = 11, CustomRule = 12, Owasp = 13,
    Sensitive = 14, AntiHotlink = 15, CrowdSec = 16, GeoIp = 17, Community = 18,
    // ⚠️ THIẾU: RiskScore, Challenge, DeviceFingerprint, Behavioral, TransactionVelocity,
    //           Canary, OutboundFilter, HeaderLeak, SensitiveRedaction
}
```

### 1.5 Host & Defense Config (waf-common/src/types.rs)

```rust
pub struct DefenseConfig {
    pub bot: bool,
    pub sqli: bool,
    pub xss: bool,
    pub scan: bool,
    pub rce: bool,
    pub sensitive: bool,
    pub dir_traversal: bool,
    pub owasp_set: bool,
    pub cc: bool,
    pub cc_rps: f64,           // token bucket refill rate
    pub cc_burst: u32,         // burst capacity
    pub cc_ban_threshold: u32, // violations before auto-ban
    pub cc_ban_duration_secs: u64,
    pub owasp_paranoia: u8,    // 1-4
    // ⚠️ THIẾU: tier (CRITICAL/HIGH/MEDIUM/CATCH-ALL), fail_mode, risk thresholds,
    //           challenge config, behavioral config, transaction velocity config
}
```


---

## 2. Phân tích Gap chi tiết — 9 Feature P0 THIẾU HOÀN TOÀN

### 2.1 🔴 FR-025/026/027: Cumulative Risk Scoring Engine

**Yêu cầu:**
- Risk score tích lũy per {IP + device fingerprint + session}, KHÔNG reset mỗi request
- Tăng khi: rule match, failed challenge, anomaly, suspicious ASN, fingerprint conflict
- Giảm khi: successful challenge, sustained normal behavior
- Thresholds: <30 Allow, 30-70 Challenge, >70 Block (configurable)

**Hiện trạng:** Hoàn toàn không có. Pipeline hiện tại là binary Allow/Block per-request, không có state tích lũy.

**Cần tra cứu:**
- Paper: "Adaptive Risk Scoring for Web Application Firewalls" — mô hình decay function
- Cloudflare Bot Management scoring model
- OWASP Coraza WAF anomaly scoring mode (CRS anomaly scoring)
- Exponential decay vs sliding window cho risk score aging

**Nơi thêm vào code:**

```
crates/waf-engine/src/risk/           ← TẠO MỚI module
├── mod.rs                            # pub mod score_manager, decay, thresholds
├── score_manager.rs                  # RiskScoreManager — DashMap<RiskKey, RiskState>
├── decay.rs                          # Exponential decay / time-based decrease
└── thresholds.rs                     # Configurable threshold → action mapping
```

**Cách merge vào pipeline:**

1. Thêm field vào `RequestCtx` (waf-common/src/types.rs):
```rust
pub struct RequestCtx {
    // ... existing fields ...
    pub risk_score: f64,              // accumulated score for this session
    pub risk_key: Option<String>,     // composite key: "{ip}:{device_fp}:{session_id}"
}
```

2. Thêm `RiskScoreManager` vào `WafEngine` struct (waf-engine/src/engine.rs):
```rust
pub struct WafEngine {
    // ... existing fields ...
    risk_manager: Arc<RiskScoreManager>,  // NEW
}
```

3. Sửa `inspect()` flow — thay vì return Block ngay, tích lũy score:
```rust
// TRƯỚC (hiện tại): mỗi check match → return Block ngay
if let Some(result) = checker.check(ctx) {
    return WafDecision::block(403, ...);
}

// SAU (mới): mỗi check match → cộng risk score → quyết định cuối
for checker in &self.checkers {
    if let Some(result) = checker.check(ctx) {
        self.risk_manager.add_score(&ctx.risk_key, result.risk_delta);
    }
}
let total_score = self.risk_manager.get_score(&ctx.risk_key);
match self.risk_manager.decide(total_score) {
    RiskDecision::Allow => WafDecision::allow(),
    RiskDecision::Challenge(kind) => WafDecision::challenge(kind),
    RiskDecision::Block => WafDecision::block(403, ...),
}
```

4. Thêm config vào `DefenseConfig`:
```rust
pub risk_scoring_enabled: bool,
pub risk_allow_threshold: f64,      // default 30.0
pub risk_challenge_threshold: f64,  // default 70.0
pub risk_decay_rate: f64,           // per-second decay
pub risk_max_score: f64,            // cap at 100.0
```

5. Background task: decay scores periodically (tokio::spawn interval)

**State management:** DashMap<String, RiskState> in-memory. Cluster sync qua existing QUIC transport nếu cần.

---

### 2.2 🔴 FR-010: Device Fingerprinting (JA3/JA4)

**Yêu cầu:**
- TLS fingerprint: JA3 hash (MD5 of TLS ClientHello params) và JA4 (improved version)
- HTTP/2 settings fingerprint (SETTINGS frame order + values)
- User-Agent entropy analysis
- Detect cùng device đổi IP

**Hiện trạng:** Không có. Gateway layer (Pingora) không extract TLS ClientHello info.

**Cần tra cứu:**
- Paper gốc JA3: "JA3 - A Method for Profiling SSL/TLS Clients" (Salesforce, 2017)
- JA4+ specification: https://github.com/FoxIO-LLC/ja4 (2023, cải tiến JA3)
- Pingora TLS callback API — có thể hook vào `ssl_handshake` không?
- rustls `ClientHello` inspection — rustls 0.23 có expose raw ClientHello?
- HTTP/2 fingerprinting: Akamai paper "HTTP/2 Fingerprinting"
- Open source: ja3-rs crate, tls-parser crate

**Nơi thêm vào code:**

```
crates/gateway/src/fingerprint/       ← TẠO MỚI module
├── mod.rs
├── ja3.rs                            # JA3 hash computation từ ClientHello
├── ja4.rs                            # JA4+ fingerprint
├── http2.rs                          # HTTP/2 SETTINGS frame fingerprint
└── ua_entropy.rs                     # User-Agent entropy scoring
```

**Cách merge:**

1. Hook vào Pingora TLS layer (gateway/src/ssl.rs hoặc proxy.rs):
   - Pingora's `ProxyHttp::connected_to_upstream` hoặc custom TLS callback
   - Extract raw ClientHello bytes trước khi TLS handshake hoàn tất
   - Tính JA3/JA4 hash → lưu vào session context

2. Thêm field vào `RequestCtx`:
```rust
pub struct RequestCtx {
    // ... existing ...
    pub device_fingerprint: Option<DeviceFingerprint>,  // NEW
}

pub struct DeviceFingerprint {
    pub ja3_hash: String,          // MD5 hex
    pub ja4_hash: Option<String>,  // JA4+ string
    pub h2_fingerprint: Option<String>,  // HTTP/2 settings hash
    pub ua_entropy: f64,           // Shannon entropy of User-Agent
    pub composite_id: String,      // combined fingerprint ID
}
```

3. Thêm vào `GatewayCtx` (proxy.rs) để truyền từ TLS layer → RequestCtx:
```rust
pub struct GatewayCtx {
    // ... existing ...
    pub tls_fingerprint: Option<String>,  // JA3/JA4 from TLS callback
}
```

4. Dùng fingerprint trong Risk Scoring: cùng fingerprint + khác IP → suspicious

**Thách thức kỹ thuật:**
- Pingora dùng OpenSSL (hoặc BoringSSL) internally, không phải rustls cho proxy connections
- Cần check Pingora API có expose `SSL_CTX_set_client_hello_cb` không
- Nếu không, có thể cần patch Pingora hoặc dùng raw socket layer trước Pingora
- HTTP/2 SETTINGS: Pingora có thể expose qua `h2` crate internals

---

### 2.3 🔴 FR-006: Challenge Engine (JS Challenge, Proof-of-Work)

**Yêu cầu:**
- JS Challenge: serve trang JavaScript, client phải execute JS để prove là browser thật
- Proof-of-Work: client phải giải bài toán crypto (hashcash-style) trước khi được phục vụ
- Adaptive: dựa trên risk score → chọn loại challenge phù hợp

**Hiện trạng:** Chỉ có block page tĩnh (block_page.rs). Không có cơ chế challenge.

**Cần tra cứu:**
- Cloudflare JS Challenge implementation (public docs)
- Hashcash algorithm (Adam Back, 1997) — PoW cho anti-spam
- Friendly Captcha (open source PoW captcha)
- hCaptcha / Turnstile architecture
- Paper: "Proof-of-Work as Anonymous Micropayment" — ứng dụng cho anti-DDoS

**Nơi thêm vào code:**

```
crates/waf-engine/src/challenge/      ← TẠO MỚI module
├── mod.rs
├── js_challenge.rs                   # JS challenge page generation + verification
├── pow.rs                            # Proof-of-Work challenge (hashcash variant)
├── token.rs                          # Challenge token generation + validation (HMAC)
└── templates/                        # HTML/JS templates
    ├── js_challenge.html             # JS challenge page
    └── pow_challenge.html            # PoW challenge page
```

**Cách merge:**

1. Thêm `WafAction::Challenge` variant:
```rust
pub enum WafAction {
    Allow,
    Block { status: u16, body: Option<String> },
    LogOnly,
    Redirect { url: String },
    Challenge { kind: ChallengeKind },  // NEW
}

pub enum ChallengeKind {
    JsChallenge,
    ProofOfWork { difficulty: u8 },
}
```

2. Thêm challenge verification endpoint vào waf-api:
```rust
// crates/waf-api/src/challenge_api.rs  ← TẠO MỚI
POST /api/challenge/verify   → verify challenge token
```

3. Sửa `proxy.rs::request_filter()` để handle Challenge action:
```rust
WafAction::Challenge { kind } => {
    // Kiểm tra cookie/header có challenge token hợp lệ không
    if self.challenge_store.verify_token(session) {
        // Token valid → cho qua
        return Ok(false);
    }
    // Serve challenge page
    let page = render_challenge_page(kind, &challenge_token);
    session.write_response_header(...).await?;
    session.write_response_body(page).await?;
    return Ok(true);
}
```

4. Challenge flow:
```
Request → Risk Score = 45 (Challenge zone)
  → Serve JS Challenge page (HTTP 200 with JS)
  → Client executes JS → POST /challenge/verify với solution
  → Server verify → Set cookie "__prx_challenge=<signed_token>"
  → Client retry original request với cookie
  → Cookie valid → Allow through
```

5. Token: HMAC-SHA256(secret, ip + timestamp + nonce), TTL 30 phút

---

### 2.4 🔴 FR-011: Behavioral Anomaly Detection

**Yêu cầu:**
- Bot timing detection: inter-request interval < 50ms = suspicious
- Zero-depth sessions: chỉ hit 1 URL, không navigate
- Missing Referer trên internal navigation
- Request pattern analysis (quá đều đặn = bot)

**Hiện trạng:** Có `checks/bot.rs` nhưng chỉ check User-Agent patterns, không có behavioral analysis.

**Cần tra cứu:**
- Paper: "Detecting Web Bots through Behavioral Analysis" (IEEE, 2019)
- Paper: "Bot or Not? A Behavioral Analysis of Web Crawlers" (WWW Conference)
- Akamai Bot Manager behavioral signals
- Statistical methods: coefficient of variation cho request timing
- Markov chain cho navigation pattern analysis

**Nơi thêm vào code:**

```
crates/waf-engine/src/behavioral/     ← TẠO MỚI module
├── mod.rs
├── timing.rs                         # Inter-request timing analysis
├── session_depth.rs                  # Session navigation depth tracking
├── referer_chain.rs                  # Referer consistency validation
└── pattern.rs                        # Request pattern regularity detection
```

**Cách merge:**

1. Cần session state tracking — DashMap<SessionKey, SessionState>:
```rust
pub struct SessionState {
    pub request_timestamps: VecDeque<Instant>,  // last N request times
    pub paths_visited: HashSet<String>,          // unique paths
    pub has_referer_chain: bool,                 // có navigation chain không
    pub request_count: u64,
    pub first_seen: Instant,
}
```

2. Thêm `BehavioralCheck` implement trait `Check`:
```rust
impl Check for BehavioralCheck {
    fn check(&self, ctx: &RequestCtx) -> Option<DetectionResult> {
        let session_key = format!("{}:{}", ctx.client_ip, ctx.device_fingerprint);
        let mut state = self.sessions.entry(session_key).or_default();
        
        // Check 1: Inter-request timing < 50ms
        // Check 2: Zero-depth session (1 path after N requests)
        // Check 3: Missing Referer on non-entry pages
        // Check 4: Request timing regularity (low coefficient of variation)
        
        // Return risk_delta thay vì block trực tiếp
    }
}
```

3. Đăng ký vào `WafEngine.checkers` vector (engine.rs line ~90):
```rust
checkers.push(Box::new(BehavioralCheck::new()));
```

4. Output: không block trực tiếp mà return `risk_delta` để cộng vào Risk Score

---

### 2.5 🔴 FR-012: Transaction Velocity & Sequence Tracking

**Yêu cầu:**
- Cross-endpoint tracking: Login → OTP → Deposit timing
- Withdrawal velocity: quá nhiều withdrawal trong thời gian ngắn
- Rapid limit-change detection
- State machine per user session

**Hiện trạng:** Không có. Mỗi request được xử lý độc lập.

**Cần tra cứu:**
- Paper: "Detecting Fraudulent Transactions using Sequence Analysis" (ACM)
- Finite State Machine (FSM) cho transaction flow validation
- Temporal pattern mining cho fraud detection
- Open source: Apache Flink CEP (Complex Event Processing) — concept, không dùng trực tiếp

**Nơi thêm vào code:**

```
crates/waf-engine/src/transaction/    ← TẠO MỚI module
├── mod.rs
├── velocity.rs                       # Rate tracking per endpoint per session
├── sequence.rs                       # Expected sequence validation (FSM)
└── config.rs                         # Transaction rules configuration
```

**Cách merge:**

1. Config trong TOML hoặc YAML rules:
```yaml
transaction_rules:
  - name: "login_to_deposit_too_fast"
    sequence: ["POST /api/login", "POST /api/otp/verify", "POST /api/deposit"]
    max_duration_secs: 5        # toàn bộ sequence < 5s = suspicious
    risk_delta: 40

  - name: "rapid_withdrawal"
    endpoint: "POST /api/withdrawal"
    max_count: 5
    window_secs: 60
    risk_delta: 50
```

2. State: DashMap<SessionKey, TransactionState> với sliding window
3. Integrate vào pipeline sau Phase 11 (Rate Limit), trước Phase 12 (Custom Rules)
4. Output: risk_delta → cộng vào Risk Score Manager

---

### 2.6 🔴 FR-028: Canary / Honeypot

**Yêu cầu:**
- Decoy paths: /admin-test, /api-debug, /.env, /wp-admin
- Hit canary → auto max risk score + block IP

**Hiện trạng:** Không có.

**Cần tra cứu:**
- OWASP Honeypot Project
- Common honeypot paths list (SecLists)
- Canary token concept (Thinkst Canary)

**Nơi thêm vào code:**

```
crates/waf-engine/src/canary.rs       ← TẠO MỚI file đơn giản
```

**Cách merge:**

1. Config:
```toml
[canary]
enabled = true
paths = ["/admin-test", "/api-debug", "/.env", "/wp-admin", "/phpinfo.php"]
risk_delta = 100    # instant max score
auto_block = true
block_duration_secs = 3600
```

2. Implement `Check` trait, đặt TRƯỚC Phase 5 trong pipeline (sau URL blacklist)
3. Khi match: set risk_score = max → auto block IP qua RiskScoreManager
4. Đây là feature đơn giản nhất, có thể implement trong 1-2 giờ

---

### 2.7 🔴 FR-034/035: Sensitive Field Redaction + Header Leak Prevention

**Yêu cầu:**
- FR-034: Mask fields trong response JSON (card_number, bank_account, etc.)
- FR-035: Detect và block PII leaks trong response headers (X-Debug, X-Internal-*)

**Hiện trạng:** Chỉ có inbound inspection. Không có outbound filtering.

**Cần tra cứu:**
- Pingora `response_filter` / `upstream_response_filter` API
- OWASP Data Loss Prevention guidelines
- Regex patterns cho credit card (Luhn), SSN, email, phone
- Paper: "Preventing Data Leakage through Web Application Firewalls"

**Nơi thêm vào code:**

```
crates/waf-engine/src/outbound/       ← TẠO MỚI module
├── mod.rs
├── response_filter.rs                # Response body inspection + redaction
├── header_filter.rs                  # Response header leak prevention
└── patterns.rs                       # PII regex patterns (credit card, SSN, etc.)
```

**Cách merge:**

1. Hook vào Pingora `upstream_response_filter` (gateway/src/proxy.rs):
```rust
// Thêm method mới vào impl ProxyHttp for WafProxy
async fn upstream_response_filter(
    &self,
    session: &mut Session,
    upstream_response: &mut ResponseHeader,
    ctx: &mut GatewayCtx,
) -> Result<()> {
    // Header leak prevention
    self.engine.filter_response_headers(upstream_response);
    Ok(())
}

// Và response_body_filter cho body redaction
async fn response_body_filter(
    &self,
    session: &mut Session,
    body: &mut Option<Bytes>,
    end_of_stream: bool,
    ctx: &mut GatewayCtx,
) -> Result<Option<Duration>> {
    if let Some(body_bytes) = body {
        *body_bytes = self.engine.redact_response_body(body_bytes);
    }
    Ok(None)
}
```

2. Header filter: remove headers matching patterns:
```rust
const LEAK_HEADERS: &[&str] = &[
    "x-debug", "x-internal-", "x-powered-by", "server",
    "x-aspnet-version", "x-runtime", "x-request-id-internal",
];
```

3. Body redaction: regex replace sensitive patterns trong JSON response


---

## 3. Phân tích Gap — 6 Feature P0 CẦN CẢI THIỆN (Partial)

### 3.1 🟡 FR-002: Tiered Protection (4 Tiers)

**Yêu cầu:** 4 tier: CRITICAL, HIGH, MEDIUM, CATCH-ALL với policies riêng biệt per tier.

**Hiện trạng:** Chỉ có 1 `DefenseConfig` per host. Không có concept "tier" per route.

**Cần tra cứu:**
- Cloudflare Security Levels (Essentially Off → I'm Under Attack)
- AWS WAF Rule Groups + priority
- Route-based policy pattern trong reverse proxy (Envoy, Nginx)

**Cách sửa:**

1. Thêm `Tier` enum vào waf-common/src/types.rs:
```rust
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
pub enum SecurityTier {
    Critical,   // /login, /otp, /withdrawal — fail-close, no cache
    High,       // /api/*, /deposit — strict checks
    Medium,     // /user/*, /game/* — moderate
    CatchAll,   // /static/*, /assets/* — minimal checks, aggressive cache
}
```

2. Thêm route→tier mapping vào `HostConfig`:
```rust
pub struct HostConfig {
    // ... existing ...
    pub tier_routes: Vec<TierRoute>,  // NEW
    pub tier_policies: HashMap<SecurityTier, TierPolicy>,  // NEW
}

pub struct TierRoute {
    pub pattern: String,       // "/api/*", "/login"
    pub tier: SecurityTier,
}

pub struct TierPolicy {
    pub fail_mode: FailMode,           // FailClose | FailOpen
    pub cache_enabled: bool,
    pub risk_thresholds: RiskThresholds,
    pub checks_enabled: Vec<Phase>,    // which checks to run
}
```

3. Trong `inspect()`, resolve tier từ path trước khi chạy checks:
```rust
let tier = resolve_tier(&ctx.path, &ctx.host_config.tier_routes);
// Skip checks not enabled for this tier
// Apply tier-specific thresholds
```

4. Database migration: thêm bảng `tier_routes` và `tier_policies`

---

### 3.2 🟡 FR-007: Relay & Proxy Detection (cải thiện)

**Hiện trạng:** Có GeoIP + Tor exit list rules. Thiếu ASN classification và X-Forwarded-For chain validation.

**Cần tra cứu:**
- MaxMind ASN database (GeoLite2-ASN) — free
- ASN classification: residential vs datacenter vs hosting vs Tor
- Paper: "Detecting Proxy and VPN Usage" (NDSS)
- X-Forwarded-For spoofing detection techniques
- ip2asn.com database (free, daily updates)

**Cách sửa:**

1. Mở rộng `GeoIpInfo` (waf-common/src/types.rs):
```rust
pub struct GeoIpInfo {
    // ... existing ...
    pub asn: Option<u32>,              // NEW: AS Number
    pub asn_org: Option<String>,       // NEW: AS Organization
    pub asn_type: Option<AsnType>,     // NEW: residential/datacenter/hosting/tor
}

pub enum AsnType {
    Residential,
    Datacenter,
    Hosting,
    Tor,
    VPN,
    Unknown,
}
```

2. Thêm ASN lookup vào GeoIP service (waf-engine/src/geoip.rs)
3. Thêm X-Forwarded-For chain validation vào Phase 1-2 area:
   - Validate chain length hợp lý
   - Detect private IPs trong chain (spoofing indicator)
   - Cross-check với trusted_proxies config

---

### 3.3 🟡 FR-023/024: Rule Scoping & Priority (cải thiện)

**Hiện trạng:** Rules scoped per host (global + per-host). Thiếu per-tier, per-route, per-device scoping. Priority là implicit (order in file).

**Cần tra cứu:**
- ModSecurity rule phases + chain concept
- AWS WAF Rule Group priority model
- Cloudflare Firewall Rules priority

**Cách sửa:**

1. Thêm fields vào `CustomRule` (waf-engine/src/rules/engine.rs):
```rust
pub struct CustomRule {
    // ... existing ...
    pub priority: i32,                    // NEW: explicit numeric priority
    pub scope: RuleScope,                 // NEW
}

pub struct RuleScope {
    pub tiers: Option<Vec<SecurityTier>>,     // apply to specific tiers
    pub route_patterns: Option<Vec<String>>,  // apply to specific routes
    pub device_fingerprints: Option<Vec<String>>,  // apply to specific devices
}
```

2. Sort rules by priority trước khi evaluate
3. Filter rules by scope match trước khi evaluate conditions

---

### 3.4 🟡 FR-033: Response Filtering (cải thiện)

**Hiện trạng:** OWASP rules detect SQL errors trong response (inbound check). Thiếu active blocking outbound.

**Cách sửa:** Xem mục 2.7 ở trên (FR-034/035) — cùng module `outbound/`.

Thêm patterns cho:
- Stack traces: Java, Python, Node.js, PHP, .NET patterns
- Internal IPs: 10.x, 172.16.x, 192.168.x trong response body
- API keys: patterns cho AWS, GCP, Stripe, etc.
- Verbose error messages: SQL error details, file paths

---

## 4. Non-Functional Gap: Bidirectional Inspection

**Hiện trạng:** Chỉ inspect inbound (request). Không inspect outbound (response).

**Cần tra cứu:**
- Pingora `ProxyHttp` trait: `upstream_response_filter`, `response_body_filter`
- Performance impact của response body scanning
- Streaming vs buffered response inspection

**Cách sửa:**

Implement 2 Pingora hooks trong gateway/src/proxy.rs:

```rust
impl ProxyHttp for WafProxy {
    // ... existing methods ...

    // NEW: Response header filtering
    async fn upstream_response_filter(
        &self, _session: &mut Session,
        upstream_response: &mut ResponseHeader,
        _ctx: &mut GatewayCtx,
    ) -> Result<()> {
        // Remove leak headers
        // Check for suspicious response codes
        Ok(())
    }

    // NEW: Response body filtering  
    fn response_body_filter(
        &self, _session: &mut Session,
        body: &mut Option<Bytes>,
        end_of_stream: bool,
        ctx: &mut GatewayCtx,
    ) -> Result<Option<Duration>> {
        // Scan for sensitive data leaks
        // Redact PII fields
        Ok(None)
    }
}
```

---

## 5. Tổng hợp: Thứ tự Implementation & Dependency Graph

```
                    ┌─────────────────────┐
                    │  FR-025/026/027     │
                    │  Risk Score Engine  │ ← NỀN TẢNG, làm đầu tiên
                    └────────┬────────────┘
                             │
              ┌──────────────┼──────────────┐
              │              │              │
    ┌─────────▼──────┐ ┌────▼─────┐ ┌──────▼──────────┐
    │ FR-010         │ │ FR-006   │ │ FR-011          │
    │ Device         │ │ Challenge│ │ Behavioral      │
    │ Fingerprint    │ │ Engine   │ │ Anomaly         │
    └─────────┬──────┘ └────┬─────┘ └──────┬──────────┘
              │              │              │
              └──────────────┼──────────────┘
                             │
                    ┌────────▼────────────┐
                    │  FR-002             │
                    │  Tiered Protection  │ ← Cần risk score + challenge
                    └────────┬────────────┘
                             │
              ┌──────────────┼──────────────┐
              │              │              │
    ┌─────────▼──────┐ ┌────▼─────┐ ┌──────▼──────────┐
    │ FR-012         │ │ FR-028   │ │ FR-033/034/035  │
    │ Transaction    │ │ Canary   │ │ Outbound        │
    │ Velocity       │ │ Honeypot │ │ Filtering       │
    └────────────────┘ └──────────┘ └─────────────────┘
```

### Đề xuất Sprint Plan (4 tuần)

| Tuần | Feature | Effort | Điểm ảnh hưởng |
|------|---------|--------|-----------------|
| **1** | Risk Score Engine (FR-025/026/027) | 3-4 ngày | 20 pts (Intelligence) |
| **1** | Canary/Honeypot (FR-028) | 0.5 ngày | 5 pts (Security) |
| **1** | Tiered Protection (FR-002) | 1-2 ngày | 10 pts (Architecture) |
| **2** | Challenge Engine (FR-006) | 3-4 ngày | 15 pts (Security) |
| **2** | Behavioral Anomaly (FR-011) | 2-3 ngày | 10 pts (Security) |
| **3** | Device Fingerprinting (FR-010) | 3-4 ngày | 10 pts (Security) |
| **3** | Transaction Velocity (FR-012) | 2-3 ngày | 10 pts (Intelligence) |
| **4** | Outbound Filtering (FR-033/034/035) | 2-3 ngày | 5 pts (Security) |
| **4** | Rule Scoping + Priority (FR-023/024) | 1-2 ngày | 5 pts (Extensibility) |
| **4** | Relay Detection improve (FR-007) | 1 ngày | 5 pts (Security) |

---

## 6. Danh sách tra cứu tổng hợp

### 6.1 Papers & Research

| Chủ đề | Tài liệu | Mục đích |
|--------|-----------|----------|
| Risk Scoring | "Anomaly Scoring in ModSecurity/CRS" — OWASP CRS docs | Mô hình scoring tham khảo |
| Risk Scoring | "Adaptive Risk-Based Access Control" (NIST SP 800-162) | Framework risk-based decisions |
| JA3/JA4 | "JA3 - A Method for Profiling SSL/TLS Clients" (Salesforce) | Thuật toán JA3 gốc |
| JA4+ | FoxIO JA4+ specification (GitHub) | Cải tiến JA3, thêm JA4S, JA4H |
| HTTP/2 FP | "Passive Fingerprinting of HTTP/2 Clients" (Akamai) | HTTP/2 SETTINGS fingerprint |
| Bot Detection | "Detecting Web Bots through Behavioral Analysis" (IEEE 2019) | Timing + navigation patterns |
| Bot Detection | "Are You a Robot?" (USENIX Security) | Browser fingerprinting techniques |
| PoW Challenge | Hashcash paper (Adam Back, 1997) | Proof-of-Work algorithm |
| Fraud Detection | "Sequence-based Fraud Detection" (ACM KDD) | Transaction sequence analysis |
| DLP | "Data Loss Prevention in WAF" (OWASP) | Outbound filtering patterns |

### 6.2 Open Source tham khảo

| Project | URL | Tham khảo cho |
|---------|-----|---------------|
| OWASP Coraza WAF | github.com/corazawaf/coraza | Anomaly scoring mode, rule engine |
| ModSecurity v3 | github.com/owasp-modsecurity/ModSecurity | CRS anomaly scoring |
| Cloudflare Pingora | github.com/cloudflare/pingora | Proxy hooks, TLS callbacks |
| JA3 (Go) | github.com/dreadl0ck/ja3 | JA3 implementation reference |
| JA4+ | github.com/FoxIO-LLC/ja4 | JA4 specification + implementations |
| Friendly Captcha | github.com/nicbarker/friendly-captcha | PoW challenge reference |
| CrowdSec | github.com/crowdsecurity/crowdsec | Community threat intel model |
| ip2asn | iptoasn.com | Free ASN database |
| SecLists | github.com/danielmiessler/SecLists | Honeypot paths, attack patterns |

### 6.3 Crate Rust cần đánh giá

| Crate | Mục đích | Ghi chú |
|-------|----------|---------|
| `tls-parser` | Parse TLS ClientHello cho JA3 | Cần check compatibility với Pingora |
| `ja3-rs` | JA3 hash computation | Có thể dùng trực tiếp hoặc tham khảo |
| `maxminddb` | MaxMind GeoLite2-ASN reader | Cho ASN classification |
| `statistical` | Statistical functions | Coefficient of variation cho timing analysis |

---

## 7. File Map: Tất cả files cần tạo mới & sửa đổi

### 7.1 Files TẠO MỚI

```
crates/waf-engine/src/
├── risk/
│   ├── mod.rs                    # Risk scoring module
│   ├── score_manager.rs          # DashMap<RiskKey, RiskState>, add/get/decay
│   ├── decay.rs                  # Exponential decay function
│   └── thresholds.rs             # Threshold → Action mapping
├── challenge/
│   ├── mod.rs                    # Challenge engine module
│   ├── js_challenge.rs           # JS challenge generation + verification
│   ├── pow.rs                    # Proof-of-Work (hashcash)
│   └── token.rs                  # HMAC token for challenge verification
├── behavioral/
│   ├── mod.rs                    # Behavioral analysis module
│   ├── timing.rs                 # Inter-request timing
│   ├── session_depth.rs          # Navigation depth tracking
│   └── referer_chain.rs          # Referer consistency
├── transaction/
│   ├── mod.rs                    # Transaction tracking module
│   ├── velocity.rs               # Per-endpoint rate tracking
│   └── sequence.rs               # FSM sequence validation
├── outbound/
│   ├── mod.rs                    # Outbound filtering module
│   ├── response_filter.rs        # Response body scanning
│   ├── header_filter.rs          # Response header leak prevention
│   └── patterns.rs               # PII regex patterns
└── canary.rs                     # Honeypot/canary check

crates/gateway/src/
└── fingerprint/
    ├── mod.rs                    # Device fingerprinting module
    ├── ja3.rs                    # JA3 hash
    ├── ja4.rs                    # JA4+ fingerprint
    └── http2.rs                  # HTTP/2 SETTINGS fingerprint

crates/waf-api/src/
└── challenge_api.rs              # Challenge verification endpoint
```

### 7.2 Files CẦN SỬA ĐỔI

| File | Thay đổi |
|------|----------|
| `crates/waf-common/src/types.rs` | Thêm: `SecurityTier`, `DeviceFingerprint`, `ChallengeKind`, `AsnType`; Mở rộng: `RequestCtx` (risk_score, device_fp, tier), `WafAction` (+Challenge), `Phase` (+new phases), `DefenseConfig` (+tier config) |
| `crates/waf-common/src/config.rs` | Thêm: `RiskConfig`, `ChallengeConfig`, `BehavioralConfig`, `TransactionConfig`, `CanaryConfig`, `OutboundConfig`, `TierConfig` vào `AppConfig` |
| `crates/waf-engine/src/engine.rs` | Thêm fields: `risk_manager`, `behavioral`, `transaction`, `canary`, `outbound_filter`; Sửa `inspect()`: tích lũy risk score thay vì block ngay; Thêm outbound methods |
| `crates/waf-engine/src/lib.rs` | Thêm: `pub mod risk`, `pub mod challenge`, `pub mod behavioral`, `pub mod transaction`, `pub mod outbound`, `pub mod canary` |
| `crates/waf-engine/src/checks/mod.rs` | Có thể thêm `pub mod behavioral` nếu dùng Check trait |
| `crates/gateway/src/proxy.rs` | Thêm: `upstream_response_filter()`, `response_body_filter()` cho outbound; Sửa `request_filter()` để handle `WafAction::Challenge`; Thêm fingerprint extraction |
| `crates/gateway/src/lib.rs` | Thêm: `pub mod fingerprint` |
| `crates/gateway/src/ssl.rs` | Hook TLS ClientHello callback cho JA3/JA4 |
| `crates/waf-api/src/server.rs` | Thêm route: `/api/challenge/verify` |
| `crates/waf-api/src/lib.rs` | Thêm: `pub mod challenge_api` |
| `crates/waf-storage/` | Migration mới: bảng `risk_scores`, `tier_routes`, `tier_policies`, `canary_hits` |

---

## 8. Lưu ý kiến trúc quan trọng

### 8.1 Risk Score thay đổi flow inspect() cơ bản

Thay đổi lớn nhất là chuyển từ **"first match → block"** sang **"accumulate score → decide"**:

```
HIỆN TẠI:
  for checker in checkers {
      if match → return Block     // short-circuit
  }
  return Allow

SAU KHI SỬA:
  let mut risk_delta_total = 0.0;
  for checker in checkers {
      if match → risk_delta_total += result.risk_delta
      if risk_delta_total > instant_block_threshold → return Block  // vẫn short-circuit cho critical
  }
  let accumulated = risk_manager.add_and_get(risk_key, risk_delta_total);
  match decide(accumulated) {
      Allow → return Allow
      Challenge → return Challenge
      Block → return Block
  }
```

Cần giữ backward compatibility: nếu `risk_scoring_enabled = false` → giữ behavior cũ (first match block).

### 8.2 State Management

Tất cả state mới (risk scores, session tracking, transaction state) dùng **DashMap in-memory**:
- Ưu điểm: zero latency, không cần Redis
- Nhược điểm: mất khi restart, không share giữa cluster nodes
- Giải pháp cluster: sync qua existing QUIC transport (waf-cluster/src/sync/)
- Giải pháp persistence: periodic snapshot to PostgreSQL (optional)

### 8.3 Performance Budget

Yêu cầu: p99 ≤ 5ms overhead. Mỗi feature mới cần benchmark:
- Risk score lookup/update: ~100ns (DashMap)
- Behavioral timing check: ~200ns
- JA3 hash: ~1μs (one-time per connection)
- Response body scan: ~50μs per KB (regex)
- Tổng budget cho tất cả feature mới: < 1ms

### 8.4 Cluster Sync cho State mới

Existing cluster sync (waf-cluster/src/sync/) hỗ trợ:
- Rule sync: incremental + full snapshot
- Config sync: periodic
- Event forwarding: batch + flush

Cần thêm sync type cho:
- Risk scores: periodic snapshot (không cần real-time, eventual consistency OK)
- Canary hits: event-based (forward to main node)
- Transaction state: KHÔNG sync (per-node, vì request routing thường sticky)
