# Tech Stack: WAF Mini Hackathon 2026

**Date:** 2026-04-10
**Constraint:** Rust only (competition mandate). Dashboard may use any language but we embed it in the same binary for simplicity.

---

## 1. Stack Summary

| Layer | Technology | Rationale |
|-------|-----------|-----------|
| **Language** | Rust (stable) | Mandatory. Zero-cost abstractions, memory safety, predictable latency |
| **Async Runtime** | Tokio | De facto Rust async runtime; battle-tested for network services |
| **HTTP Proxy** | Hyper + Tower | Hyper for HTTP/1.1 & HTTP/2; Tower for middleware/service layers |
| **TLS** | Rustls + tokio-rustls | Pure-Rust TLS; access to TLS ClientHello for JA3/JA4 fingerprinting |
| **Rule Config** | TOML (serde + toml crate) | Simpler than YAML in Rust ecosystem; first-class serde support |
| **Rule Hot-Reload** | notify + Arc\<RwLock\> | File watcher triggers reload; RwLock for concurrent read access |
| **Risk Scoring** | In-memory (DashMap) | Lock-free concurrent hashmap; per-{IP+device+session} state |
| **Rate Limiting** | In-memory (sliding window) | Token bucket + sliding window; no external deps |
| **Regex Engine** | regex crate | Fast, safe, no catastrophic backtracking; for OWASP pattern matching |
| **IP/ASN Lookup** | maxminddb crate | MaxMind GeoLite2 for ASN classification (residential/datacenter/Tor) |
| **Dashboard** | Embedded static files + WebSocket | Rust serves React SPA via rust-embed; live feed via tokio-tungstenite |
| **Dashboard UI** | React + Vite + Tailwind | Lightweight SPA; bundled into binary at compile time |
| **Audit Log** | serde_json + append-only file | JSON lines format; buffered async writes |
| **CLI** | clap | `./waf run` command parsing, config path flags |
| **Testing** | cargo test + criterion | Unit tests + benchmarks for latency validation |
| **Build** | cargo build --release | Single binary output, LTO enabled for size/speed |

---

## 2. Core WAF Stack (Rust)

### 2.1 Networking & Proxy

| Crate | Version | Purpose |
|-------|---------|---------|
| `tokio` | 1.x | Async runtime — multi-threaded work-stealing scheduler |
| `hyper` | 1.x | HTTP/1.1 + HTTP/2 server and client (low-level, fast) |
| `hyper-util` | 0.1.x | Service utilities for hyper (TowerToHyperService) |
| `tower` | 0.4.x | Middleware stack: timeout, rate limit, load shed, layers |
| `tower-http` | 0.5.x | HTTP-specific Tower middleware (cors, compression, tracing) |
| `http` | 1.x | HTTP types (Request, Response, StatusCode) |
| `bytes` | 1.x | Zero-copy byte buffer for request/response body inspection |

**Why Hyper + Tower (not Axum/Actix):** We need a reverse proxy, not an application framework. Hyper gives direct control over connection handling, request/response streaming, and body inspection. Tower provides composable middleware for the security pipeline. Axum/Actix add routing abstractions we don't need — every request goes through the same pipeline.

### 2.2 TLS & Fingerprinting

| Crate | Purpose |
|-------|---------|
| `rustls` | TLS 1.2/1.3 termination; pure Rust, no OpenSSL dependency |
| `tokio-rustls` | Async TLS acceptor for Tokio |
| `rustls-pemfile` | Parse PEM certificate files |
| Custom `ja3/ja4` module | Extract TLS ClientHello fields for JA3/JA4 fingerprint generation |

**JA3/JA4 approach:** Hook into `rustls` ClientHello callback to capture cipher suites, extensions, supported groups, EC point formats. Hash to generate fingerprint. No external crate — implement in ~200 lines.

### 2.3 Security & Detection

| Crate | Purpose |
|-------|---------|
| `regex` | OWASP pattern matching (SQLi, XSS, path traversal, SSRF) |
| `aho-corasick` | Multi-pattern matching for blacklists/signatures (faster than regex for many patterns) |
| `maxminddb` | GeoLite2 ASN database lookup — classify IP as residential/datacenter/Tor |
| `ipnet` | IP network/range matching for SSRF detection (10.x, 172.16.x, etc.) |
| `uuid` | Request ID generation for tracing |

**Detection architecture:** Pre-compile regex patterns at startup into a `RegexSet` for O(1) multi-pattern matching. Use `aho-corasick` for payload signature scanning (SQL keywords, XSS payloads).

### 2.4 State Management

| Crate | Purpose |
|-------|---------|
| `dashmap` | Concurrent hashmap for risk scores, session state, rate limit counters |
| `parking_lot` | Faster RwLock/Mutex than std (for rule config hot-reload) |
| `moka` | TTL-aware concurrent cache for smart caching (MEDIUM tier routes) |

**Why in-memory (no Redis):** Single binary constraint. In-memory state is sufficient for single-node WAF. DashMap provides lock-free concurrent access. Moka handles TTL expiration for cache entries automatically.

### 2.5 Configuration & Rules

| Crate | Purpose |
|-------|---------|
| `serde` + `serde_derive` | Serialization/deserialization for rule configs |
| `toml` | Parse TOML rule files |
| `notify` | File system watcher for hot-reload (inotify on Linux, FSEvents on macOS) |
| `clap` + `clap_derive` | CLI argument parsing (`./waf run --config ./rules/`) |

**Hot-reload flow:**
```
notify watches rules/ dir → file change detected → parse new TOML
→ validate → swap Arc<RwLock<Config>> → log reload event
```

### 2.6 Logging & Observability

| Crate | Purpose |
|-------|---------|
| `tracing` | Structured logging & spans (async-aware) |
| `tracing-subscriber` | Log formatters and filters |
| `serde_json` | JSON serialization for audit log entries |
| `tokio::fs` | Async file I/O for audit log writes |

---

## 3. Dashboard Stack

### 3.1 Approach: Embedded SPA

The dashboard is a React SPA compiled at build time and embedded into the Rust binary using `rust-embed`. The WAF serves it on a configurable port (e.g., `:9090`). Live data streams via WebSocket.

| Component | Technology | Rationale |
|-----------|-----------|-----------|
| **Framework** | React 19 | Lightweight, fast rendering for live data |
| **Build** | Vite | Fast dev/build; outputs static files for embedding |
| **Styling** | Tailwind CSS | Utility-first; small bundle; rapid UI development |
| **Charts** | Recharts or Lightweight Charts | Attack visualization, request timeline |
| **WebSocket** | Native WebSocket API | Live request feed from WAF |
| **State** | React hooks (useState/useReducer) | Simple enough — no need for Zustand/Redux |
| **Embed** | `rust-embed` crate | Compile static files into binary at build time |

### 3.2 WebSocket Protocol

```
WAF binary serves:
  GET /dashboard/*  → static SPA files (rust-embed)
  WS  /ws/live-feed → realtime request events (JSON)
  POST /api/rules   → CRUD rules (hot-reload trigger)
  GET  /api/stats   → aggregated metrics
```

### 3.3 Dashboard Build Pipeline

```bash
# Build dashboard SPA
cd dashboard && npm run build  # outputs dist/

# Build WAF (embeds dashboard dist/ at compile time)
cargo build --release  # rust-embed includes dashboard/dist/*

# Result: single binary with embedded dashboard
./waf run --dashboard-port 9090
```

---

## 4. Project Structure

```
waf/
├── src/
│   ├── main.rs                    # Entry point, CLI parsing
│   ├── proxy/
│   │   ├── mod.rs                 # Reverse proxy core
│   │   ├── handler.rs             # Request/response handler
│   │   └── upstream.rs            # Backend connection + circuit breaker
│   ├── security/
│   │   ├── mod.rs
│   │   ├── owasp.rs               # SQLi, XSS, SSRF, path traversal detection
│   │   ├── rate_limiter.rs        # Sliding window + token bucket
│   │   ├── ddos.rs                # Burst detection + auto block
│   │   ├── fingerprint.rs         # JA3/JA4 TLS + HTTP fingerprinting
│   │   ├── behavioral.rs          # Anomaly detection (timing, depth, referer)
│   │   ├── transaction.rs         # Velocity & sequence tracking
│   │   ├── relay.rs               # Proxy/relay detection, ASN classification
│   │   └── challenge.rs           # JS challenge + proof-of-work
│   ├── rules/
│   │   ├── mod.rs
│   │   ├── engine.rs              # Rule matching engine
│   │   ├── loader.rs              # TOML parser + hot-reload (notify)
│   │   └── types.rs               # Rule structs, tier enum, action enum
│   ├── risk/
│   │   ├── mod.rs
│   │   ├── scorer.rs              # Cumulative risk score per {IP+device+session}
│   │   ├── canary.rs              # Honeypot endpoint detection
│   │   └── decision.rs            # Allow / Challenge / Block thresholds
│   ├── cache/
│   │   └── mod.rs                 # Smart caching (moka) with tier-aware TTL
│   ├── outbound/
│   │   └── mod.rs                 # Response filtering, PII redaction, header cleanup
│   ├── lists/
│   │   └── mod.rs                 # Whitelist/blacklist + threat intel loader
│   ├── dashboard/
│   │   ├── mod.rs                 # Embedded SPA server + WebSocket
│   │   ├── websocket.rs           # Live feed broadcaster
│   │   └── api.rs                 # REST API for rules CRUD + stats
│   ├── audit/
│   │   └── mod.rs                 # JSON audit log writer (async, buffered)
│   └── config.rs                  # Global config struct, CLI args
├── rules/
│   ├── default.toml               # Default rule set
│   ├── owasp.toml                 # OWASP detection patterns
│   └── tiers.toml                 # Tier definitions (CRITICAL/HIGH/MEDIUM/CATCH-ALL)
├── data/
│   ├── tor-exit-nodes.txt         # Tor exit node list
│   ├── bad-asn.txt                # Known-bad ASN list
│   └── GeoLite2-ASN.mmdb         # MaxMind ASN database
├── dashboard/                     # React SPA source
│   ├── src/
│   ├── package.json
│   └── vite.config.ts
├── Cargo.toml
├── Cargo.lock
└── README.md
```

---

## 5. Build & Deployment

### 5.1 Build Configuration

```toml
# Cargo.toml — key settings
[profile.release]
opt-level = 3
lto = "fat"            # Link-Time Optimization for smaller, faster binary
codegen-units = 1       # Single codegen unit for maximum optimization
strip = true            # Strip debug symbols
panic = "abort"         # No unwinding — smaller binary

[features]
default = ["dashboard"]
dashboard = ["rust-embed"]
tls = ["rustls", "tokio-rustls"]  # Optional HTTPS termination (bonus)
```

### 5.2 Target Output

```bash
$ cargo build --release
$ ls -la target/release/waf
-rwxr-xr-x 1 user user ~15-25MB waf    # Single binary

$ ./waf run --config ./rules/ --upstream http://backend:8080
# WAF listening on :8080 (proxy)
# Dashboard on :9090
```

### 5.3 Performance Budget

| Component | Latency Budget | Approach |
|-----------|---------------|----------|
| TLS handshake parsing (JA3) | ~0.1ms | Extract from ClientHello callback |
| Rule engine matching | ~0.5ms | Pre-compiled RegexSet + Aho-Corasick |
| Risk score lookup | ~0.01ms | DashMap O(1) |
| Rate limit check | ~0.01ms | DashMap O(1) |
| Behavioral check | ~0.1ms | In-memory session state lookup |
| Response filtering | ~0.2ms | Streaming body scan |
| **Total overhead** | **~1ms typical** | Well under 5ms p99 budget |

---

## 6. Alternatives Considered

| Decision | Chosen | Alternative | Why Not |
|----------|--------|-------------|---------|
| HTTP framework | Hyper + Tower | Axum | Axum adds routing abstraction; we need raw proxy control, not app routing |
| HTTP framework | Hyper + Tower | Actix-web | Actix uses its own runtime; Tokio ecosystem is broader |
| TLS | Rustls | OpenSSL (via openssl crate) | Rustls is pure Rust — no system dependency, simpler for single binary |
| Concurrent map | DashMap | std RwLock\<HashMap\> | DashMap is sharded, lower contention under high concurrency |
| Cache | Moka | Mini-redis / custom | Moka is production-grade TTL cache, no network overhead |
| Config format | TOML | YAML | TOML has better Rust support (serde_toml); YAML needs serde_yaml which is less maintained |
| Dashboard embed | rust-embed | Separate process | Single binary constraint; embedding eliminates deployment complexity |
| Dashboard framework | React + Vite | Leptos/Yew (Rust WASM) | React is faster to build UI in 4-week timeline; WASM adds compile complexity |
| Fingerprinting | Custom JA3/JA4 | ja3-rs crate | No mature crate; ~200 lines to implement from rustls ClientHello |
| Regex | regex crate | fancy-regex | regex crate guarantees no backtracking (O(n)); fancy-regex allows backtracking |

---

## 7. Dependency Risk Assessment

| Crate | Maturity | Risk | Mitigation |
|-------|----------|------|-----------|
| tokio | Very High | None | De facto standard |
| hyper | Very High | None | Used by Cloudflare, AWS |
| rustls | High | Low | Used by many production systems |
| dashmap | High | Low | Well-maintained, widely used |
| moka | High | Low | Production cache by many Rust services |
| regex | Very High | None | Rust ecosystem staple |
| maxminddb | Medium | Low | Stable API, GeoLite2 format unlikely to change |
| rust-embed | Medium | Low | Simple macro; fallback: serve from disk |
| notify | High | Low | Cross-platform file watcher |

All crates are MIT/Apache-2.0 licensed. No GPL dependencies.
