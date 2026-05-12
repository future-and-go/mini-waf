# Changelog

All notable changes to this project will be documented in this file.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.0.0/).
Version numbers follow [Semantic Versioning](https://semver.org/).

---

## [Unreleased]

### Added

- **FR-005 DDoS protection** — L7 burst detection with auto-block. Three
  detection layers evaluated in parallel: **PerIpDetector** (sliding-window
  counter per client IP, threshold: `ddos.per_ip.threshold_rps`),
  **PerFingerPrintDetector** (groups requests by device fingerprint from FR-010
  JA3/JA4 + HTTP/2 hash to detect botnet attacks across rotating IPs; fallback
  to per-IP if fingerprint unavailable), and **PerTierDetector** (adaptive
  threshold per tier: Critical/High/Medium/CatchAll, detects tier-wide bursts).
  TTL-escalating bans (60s → 5m → 1h) via `access::ip_table` plus risk bump to
  FR-025 risk scorer. Store backends: MemoryStore (100K cap, 10min idle eviction)
  or RedisStore (single Lua script roundtrip, 50ms timeout; feature `redis-store`).
  BreakerStore circuit-breaker (5 failure threshold) routes to memory fallback on
  Redis errors. Graceful degradation honours per-tier `fail_mode` policy
  (Close=block, Open=pass on store error). Hot-reloadable via
  `configs/default.toml` `[ddos]` section. Metrics: `ddos_detector_evaluations_total`,
  `ddos_hard_burst_total`, `ddos_bans_issued_total`, `ddos_ban_table_size`,
  `ddos_store_errors_total`, `ddos_degrade_events_total`, `ddos_detector_latency_us`.
  Operator guide: [`docs/ddos-protection.md`](docs/ddos-protection.md). Module:
  `crates/waf-engine/src/checks/ddos/`. Plan:
  `plans/260505-0954-fr-005-ddos-protection/`. Rule IDs: `DDOS-BAN`, `DDOS-RISK`,
  `DDOS-DEGRADE`.

- **FR-012 transaction velocity & sequence detection** — Cross-endpoint
  behavioral fraud detection that flags rapid `login → OTP → deposit`
  sequences, withdrawal velocity bursts, and limit-change storms. Signal-only:
  emits `Signal::TxSequenceTooFast` / `WithdrawalVelocity` / `LimitChangeBurst`
  to the shared `RiskAggregator` (FR-025 plug-in point), never blocks directly.
  Per-session state in `DashMap<SessionKey, ActorTx>` with a 16-slot `ArrayVec`
  ring (~256 B/session, alloc-free after first record); identity priority is
  session cookie → device-fp `FpKey` fallback. Three classifiers run under one
  registry: `SequenceTiming` (Login→OTP / OTP→Deposit / Login→Deposit faster
  than `min_human_ms`), `WithdrawalVelocityClassifier`, and
  `LimitChangeBurstClassifier`. Per-session cooldown (`signal_cooldown_ms`)
  suppresses signal flooding; TTL janitor purges idle sessions. Hot-reload via
  `ArcSwap<TxVelocityConfig>` driven by a `notify` watcher on
  `configs/tx-velocity.yaml` — bad YAML retains the previous snapshot with
  `tracing::warn!`. Pipeline position: Phase 5.5, after `RateLimitCheck` and
  before `ScannerCheck`. Bench (Apple Silicon, Criterion): ~94 ns hot path,
  ~1.5 µs cold-path session creation, constant scaling to 50k sessions.
  Operator guide: [`docs/transaction-velocity.md`](docs/transaction-velocity.md).
  Module: `crates/waf-engine/src/checks/tx_velocity/`. Plan:
  `plans/260504-1632-fr-012-transaction-velocity/`. Deferred follow-ups:
  response-side `ok` enrichment (failed-login signal), Redis-backed `TxStore`
  for cluster-shared state.
- **FR-014 XSS enhance** — iterative JSON walker (hard depth cap 64 so the
  engine cannot stack-overflow on malicious nesting), form-urlencoded
  scanner, Content-Type-aware dispatch. `text/markdown` body-skip mitigates
  false positives on code-block snippets.
- **FR-015 path traversal enhance** — adopts shared `request_targets()` so
  recursive-decoded variants are covered (`%252e%252e` no longer slips
  past); new anchored patterns for `/etc/<sensitive>`, `/proc/<pid>/…`,
  `\windows\system32`, `boot.ini` / `win.ini`.
- **FR-016 SSRF detection (NEW)** — RFC1918 / loopback / link-local / cloud
  metadata (AWS `169.254.169.254`, GCP, Alibaba `100.100.100.200`, Consul);
  obfuscated IPs (hex, octal, decimal dword, IPv6-mapped). Userinfo bypass
  `http://google.com@169.254.169.254/` resolves to the metadata IP via
  `url::Url::host()`. Opt-in allowlist via
  `defense_config.ssrf_outbound_host_allowlist`.
- **FR-017 header injection (NEW)** — raw + `%0d%0a` / `%250d%250a` CRLF in
  header values and names; `Host` header whitelist (`host_inbound_whitelist`)
  with IPv6-bracket awareness; `X-Forwarded-For` leftmost-private + max-hops.
- **FR-018 brute force + credential stuffing (NEW)** — consumes the
  `Check::on_response` default hook. BF-001: `(user_hash, ip)` failure
  counter ≥ `bf_max_per_user`. BF-002: password sprayed against ≥
  `bf_spray_threshold` distinct users from same IP. Status-code-only v1
  (401/403); body-regex deferred. Credentials hashed via keyed `ahash`
  (stronger against precomputation than unkeyed SHA-256-truncated) — never
  plaintext in state. **Wired-but-inert in v1**: `WafEngine::on_response`
  dispatcher ships, but the gateway's Pingora `response_filter` does not yet
  invoke it (cross-crate edit deferred to a follow-up PR). FR-018 detection
  is dormant in production until that wiring lands; the periodic
  `BfState::prune_older_than` task is also deferred to the same follow-up.
- **FR-019 scanner recon enhance** — per-IP sliding-window state with
  endpoint enumeration (distinct-path threshold) and OPTIONS preflight
  abuse. Bounded at `scanner_max_ips` (default 100k) with oldest-10%
  eviction against IPv6-rotating OOM vector.
- **FR-020 request body abuse (NEW)** — declared `Content-Length` size
  gate (64 KiB to match gateway `BODY_PREVIEW_LIMIT`), magic-byte
  Content-Type mismatch (JSON/XML/HTML/ZIP/GZIP), iterative byte-scan JSON
  depth pre-check (bails before any parser allocation), key-count explosion
  via iterative `Value` walker.
- **Detection framework** — `Phase` enum gets 4 new variants (`Ssrf`,
  `HeaderInjection`, `BruteForce`, `RequestBodyAbuse`). `Check` trait
  extended with default-impl `on_response(&self, _ctx, _status)` hook.
  `WafEngine::on_response(ctx, status)` dispatcher for gateway wiring.
  `Clock` trait + `SystemClock` + `MockClock` test fixture so stateful
  checks advance time deterministically without sleeping.
- **Coverage infra** — `Dockerfile.coverage` (rust:1.91 + `cargo-llvm-cov`
  0.8.5 pinned), `scripts/coverage-gate.sh` + smoke fixtures,
  `scripts/create-worktrees.sh` + `setup-worktree-env.sh`, CI `coverage`
  job (informational — gate flips to enforcing after the waf-engine
  baseline-raise follow-up lands).

- **FR-008 access lists** — Phase-0 gate ahead of the 16-phase rule pipeline:
  per-tier IP whitelist (Patricia trie via `ip_network_table`), IP blacklist,
  and per-tier Host (FQDN) whitelist. Runs Host gate → IP blacklist →
  IP whitelist with deny-wins-over-allow semantics; per-tier `whitelist_mode`
  dispatches between `full_bypass` (skip all later phases) and `blacklist_only`
  (defense-in-depth, default). Configuration in `rules/access-lists.yaml`,
  hot-reloaded via `notify` + `ArcSwap` with ~250 ms debounce; bad YAML keeps
  the previous snapshot live with a `tracing::warn!`. Audit fields
  `access_decision` / `access_reason` / `access_match` stamp every request.
  Operator guide: [`docs/access-lists.md`](docs/access-lists.md).
  Tor exit list, bad-ASN classification, and validated XFF `ctx.client_ip`
  are deferred to FR-042 and FR-007.

- **FR-033 response body content filtering (NEW)** — built-in streaming
  scanner over upstream response bodies for four leak categories: stack
  traces (Aho-Corasick distinctive literals + line-anchored multiline
  regex per language for Java, Python, Rust, Node, .NET, Go, PHP),
  verbose error messages (Spring, ASP.NET, Oracle, Postgres SQL syntax
  markers), API keys / secrets (AWS, GCP, GitHub PAT, JWT, Slack,
  Stripe, OpenAI, Anthropic, Twilio, private-key blocks), and strict-
  parsed internal IPv4 RFC-1918 / loopback / link-local + IPv6 ULA.
  Single redact action — matched span replaced with `[redacted]` —
  because Pingora `response_body_filter` cannot rewrite the status code
  post-headers; whole-body block stays FR-005's request-time
  responsibility. gzip decompression in a companion
  `response_body_decompressor` module with 10000:1 bomb-ratio guard;
  non-gzip / non-identity Content-Encoding skipped with
  `tracing::debug!` (brotli / deflate deferred to FR-033b). ReDoS
  bounded by construction: per-pattern `{min,max}` quantifiers,
  `RegexBuilder::dfa_size_limit`, `Vec<Regex>` instead of `RegexSet`
  (offsets required for span-aware redaction), no combined alternation
  (Cloudflare 2019 outage class). `Content-Length` + `Transfer-Encoding`
  dropped unconditionally on scanner enable to defend against framing
  desync / response smuggling. Content-Type allowlist at
  `response_filter` excludes `application/grpc*`, `text/event-stream`,
  `application/octet-stream` so gRPC trailers and streaming endpoints
  aren't corrupted. Compiled catalogs cached by `(host_name,
  xxhash64(body_scan_*))` rather than `Arc::as_ptr` to avoid cross-host
  pattern bleed on config reload. Filter chain order: FR-033 → FR-034 →
  AC-17 so downstream layers see plaintext. `HostConfig` gains two opt-
  in fields (`body_scan_enabled`, `body_scan_max_body_bytes`), both
  `#[serde(default)]` — existing TOMLs / DB rows parse unchanged.
  Modules: `crates/gateway/src/filters/response_body_content_scanner.rs`,
  `crates/gateway/src/filters/response_body_decompressor.rs`. Plan:
  `plans/260428-2311-fr-033-response-body-content-filter/`. Standards:
  OWASP ASVS V8 / V14, API Top 10 (2023) API5 / API8, CWE-200 / 209 /
  552, NIST SP 800-53 SI-11, PCI-DSS 3.4 / 6.5.5. 18 unit + 6
  integration tests including chunk-boundary splits at offsets 1023 and
  1024 per category, gzip bomb-defense, and `BodyScanState: Send`
  compile-time check. `body_scan_hits_total` counter recorded
  internally; `/metrics` surface wiring deferred to FR-033b once
  `waf-api::stats` gains a generic counter registry.

- **FR-034 sensitive field redaction in JSON bodies (NEW)** — per-host
  outbound filter that masks JSON values whose keys match a configured
  catalog before the response leaves the gateway. Six opt-in family
  toggles on `HostConfig`: `redact_pci` (`card_number`, `cvv`, `cvc`,
  `pin`, `expiration_date`, `cc_*`, `creditcard`), `redact_banking`
  (`bank_account`, `account_number`, `routing_number`, `iban`, `bic`,
  `swift_code`), `redact_identity` (`ssn`, `tax_id`, `passport_number`,
  `driver_license`, `national_id`), `redact_secrets` (`password`,
  `token`, `api_key`, `secret`, `client_secret`, `refresh_token`,
  `access_token`, `private_key`), `redact_pii` (`email`,
  `phone_number`, `dob`, `mother_maiden_name` — off by default, high
  false-positive surface on legitimate user-listing APIs), `redact_phi`
  (HIPAA scope: `patient_id`, `medical_record_number`, `insurance_id`,
  `health_record`). `redact_extra_fields` extends every active family;
  `redact_mask_token` defaults to `***REDACTED***`; `redact_max_bytes`
  hard ceiling 256 KiB (fail-open + `tracing::warn!` on overflow);
  `redact_case_insensitive` default `true`. Streaming dispatch in
  `gateway::filters::response_json_field_redactor`: buffers chunks
  until EOS or cap overflow, parses via `serde_json::from_slice`, walks
  `Object` keys + `Array` items recursively, replaces matches in place,
  re-serialises into `*body`. `is_noop()` short-circuit when no
  families on AND no extras → entire filter is zero-cost. Per-host
  `CompiledRedactor` lazy-built and cached on `WafProxy`
  (`body_redact_cache: Arc<DashMap<usize, Arc<CompiledRedactor>>>`,
  key `Arc::as_ptr(hc)`) mirroring the AC-17 body-mask cache.
  `response_filter` opt-in gate: Content-Encoding identity AND
  Content-Type JSON (`application/json`, `application/problem+json`,
  `application/vnd.api+json` — `text/event-stream`,
  `application/x-ndjson`, `application/xml` rejected) AND redactor is
  non-noop; drops `Content-Length` for chunked re-encode. Composes
  with AC-17: FR-034 emits the full redacted body on EOS, AC-17 then
  runs over the redacted bytes in a single-chunk pass. All `redact_*`
  toggles default `false` and `#[serde(default)]` → zero behaviour
  change for hosts that don't opt in; existing TOMLs / DB rows parse
  unchanged. Module:
  `crates/gateway/src/filters/response_json_field_redactor.rs`. Plan:
  `plans/260428-1357-GH-034-sensitive-field-redaction/`. Standards:
  PCI-DSS Req 3.4, HIPAA §164.514(b), OWASP API Security Top 10 (2023)
  API3:2023, CWE-200. 21 unit + 7 integration tests including AC-17
  composition (response with both `card_number` and `10.0.0.5`-class
  internal IPs ends with both `***REDACTED***` and `[redacted-ip]`
  tokens, neither raw value present). Compressed-body redaction,
  JSONPath rules, type-preserving masks, partial masks
  (`****-****-****-1234`), and per-route policy deferred.

- **FR-035 response header leak prevention (NEW)** — Pingora
  `response_filter` hook that strips response headers leaking server
  fingerprint, debug / internal context, error detail, or PII before
  they reach the downstream client. Design contract: detection cases
  live in code (`outbound::header_filter`), activation lives in
  `[outbound.headers]` config. Built-in family toggles (default `true`
  when outbound is on): `strip_server_info` (`Server`, `X-Powered-By`,
  `X-AspNet-Version`); `strip_debug_headers` (`X-Debug-*`,
  `X-Internal-*`, `X-Backend-*`); `strip_error_headers`
  (`X-Error-Message`, `X-Exception-Type`, `X-Stack-Trace`);
  `strip_php_fingerprint` (CVE-2024-4577 PHP-CGI argument injection
  class); `strip_aspnet_fingerprint` (CVE-2017-7269 IIS WebDAV /
  ViewState attacks; covers `X-AspNetMvc-Version`, `X-SourceFiles`);
  `strip_framework_fingerprint` (Drupal CVE-2014-3704 / CVE-2018-7600
  Drupalgeddon, Spring4Shell CVE-2022-22965, plus `X-Magento-*`,
  `X-Rack-Cache`, `X-Application-Context`, `X-Pingback`);
  `strip_cdn_internal` (`X-Varnish`, `X-Amz-Cf-Id`, `X-Amz-Cf-Pop`,
  `X-Akamai-*`, `X-Fastly-Request-Id`, `X-Served-By` — since the WAF
  is the public edge, upstream CDN headers are topology disclosure
  from a layer behind the backend). Operator `strip_headers` /
  `strip_prefixes` extend the built-ins case-insensitively (RFC 9110
  §5.1). `preserve_headers` / `preserve_prefixes` allowlist beats
  every strip rule except two unconditional guards: CRLF in any header
  value → strip + `tracing::warn!` (RFC 9110 §5.5, CWE-93,
  CVE-2017-1000026 Tomcat response-splitting class) and the RFC 9110
  §7.6.1 hop-by-hop pin (`Connection`, `Keep-Alive`,
  `Proxy-Authenticate`, `Proxy-Authorization`, `TE`, `Trailer`,
  `Transfer-Encoding`, `Upgrade`). Security-header allowlist (HSTS,
  CSP, X-Frame-Options, X-Content-Type-Options, Referrer-Policy,
  Permissions-Policy) and cache / content header families never
  stripped — covered by unit test. `[outbound.headers.pii]` table:
  `detect_pii_in_values` (off by default) flags `email`, `credit_card`,
  `ssn`, `phone`, `ipv4_private`, `jwt`, `aws_key`, `google_api_key`,
  `slack_token`, `github_pat`; `disable_builtin` drops named patterns
  (unknown name → startup error); `extra_patterns` adds operator
  regexes compiled at startup (invalid regex → startup error;
  detection logs surface them as `custom_<index>` so the regex source
  never reaches the log line); `max_scan_bytes` tunes the
  previously hard-coded `MAX_PII_SCAN_LEN = 8 KiB` ReDoS cap (`0`
  disables with warn). `strip_session_headers_on_pii_match`
  (`Set-Cookie`, `ETag`, `Authorization`) operator opt-in only — off
  by default to avoid killing a user session on a regex false-
  positive. Empty header name guard. `outbound.enabled = false`
  default → `response_filter` short-circuits, zero overhead for
  existing deployments. `HeaderFilter::try_new(&cfg) -> Result<Self,
  OutboundConfigError>` fail-soft: gateway logs and disables outbound
  filtering on construction error so a misconfigured filter never
  aborts the proxy. All new keys `#[serde(default)]` — existing TOMLs
  parse unchanged. Module:
  `crates/waf-engine/src/outbound/header_filter.rs`; gateway hook in
  `crates/gateway/src/proxy.rs`. Plans:
  `plans/260426-1553-fr035-header-leak-prevention/`,
  `plans/260426-1919-GH-035-detection-hardening/`,
  `plans/260428-1312-GH-035-header-config-granularity/`. Standards:
  OWASP ASVS V14.4, CWE-93 / 200 / 209, RFC 9110 §5.1 / §5.5 /
  §7.6.1, NIST SP 800-53 SI-11. 52 unit tests; each new test name
  cites the CVE or incident class it guards
  (`test_php_fingerprint_stripped`,
  `test_drupal_fingerprint_stripped`,
  `test_spring_actuator_fingerprint_stripped`,
  `test_crlf_in_value_stripped`, `test_pii_scan_skipped_above_cap`,
  `test_hop_by_hop_never_stripped`,
  `test_setcookie_preserved_on_pii_match_by_default`, etc.).
  Stripped-header metrics counter nominated for the v0.3.0 metrics
  phase.

---

## [0.2.0] — 2026-03-27

### Security

- Eliminate 8 `panic!` calls in LazyLock regex initializers — replaced with
  `tracing::error!` + safe degradation (`RegexSet::empty()`) so a malformed
  compiled-in pattern never crashes the process.
- Add SSRF protection for Webhook and CrowdSec URLs with dual-mode validation
  (`url_validator.rs`): `validate_public_url()` resolves DNS and rejects RFC-1918
  / loopback / link-local / multicast addresses; `validate_scheme_only()` for
  contexts where DNS resolution is not yet available.
- Implement DNS rebinding guard using `resolve_to_addrs()` IP pinning — the
  resolved address set is cached and re-validated on each outbound connection to
  defeat time-of-check / time-of-use DNS rebinding attacks.
- Add iterative URL decoding (`url_decode_recursive`) to prevent double / triple
  encoding bypass of WAF rules (e.g., `%2527` → `%27` → `'`).
- Harden remote rule fetching: redirect following disabled, 30 s connect/read
  timeout enforced, response body capped at 10 MB.
- Add Admin API security middleware: IP allowlist enforcement, per-IP rate
  limiting, and strict security response headers (`X-Frame-Options`,
  `X-Content-Type-Options`, `Referrer-Policy`, `Content-Security-Policy`).
- Add login rate limiting (per-IP, configurable) and WebSocket upgrade IP
  allowlist to the Admin UI server.
- Fix cluster peer registration fencing: stale peer records are evicted before a
  new node with the same ID is accepted, preventing split-brain from rapid
  restart cycles.
- Fix XFF trusted-proxy CIDR validation: malformed CIDR strings in
  `trusted_proxies` now produce a config error at startup instead of a runtime
  panic.
- Fix rule deletion memory sync: rule removal now performs an atomic swap of the
  in-memory `RuleRegistry` so in-flight requests never observe a partially
  updated rule set.

### Added

- `detect_sqli` and `detect_xss` operators via the `libinjectionrs` pure-Rust
  crate — OWASP CRS core rules `CRS-942100` (SQL injection) and `CRS-941100`
  (XSS) are now fully evaluated at runtime instead of being silently skipped.
- Async `load_remote_sources()` method on `RuleRegistry` / `RemoteUrl` rule
  sources: remote rule sets are fetched in the background after startup so cold
  boot latency is unaffected.
- `url_validator` module (`waf-engine/src/security/url_validator.rs`) exposing
  `validate_public_url()` and `validate_scheme_only()`.
- `.cargo/audit.toml` policy file that suppresses known upstream transitive
  dependency advisories originating from the Pingora crate family (documented
  with justification comments).
- 116 new regression tests (suite total: 243) covering SSRF validation, encoding
  bypass, SQLi/XSS detection, cluster fencing, and dependency-upgrade
  compatibility.

### Changed

#### Dependency Upgrades

- **wasmtime**: 23.0.3 → 43.0.0 — resolves 5 published CVEs in the WASM
  runtime.
- **axum**: 0.7 → 0.8.8; **axum-extra**: 0.9 → 0.12 — aligns with the current
  stable axum ecosystem.
- **tower**: 0.4 → 0.5.3; **tower-http**: 0.5 → 0.6.8.
- **jsonwebtoken**: 9 → 10, switching to the `rust_crypto` backend to remove
  the OpenSSL dependency from the JWT path.
- **reqwest**: 0.12 → 0.13.
- **tokio-tungstenite**: 0.23 → 0.26.
- **toml**: 0.8 → 1.1.
- **serde_yaml**: deprecated 0.9 → **serde_yaml_ng** 0.10.
- **rustls-pemfile**: unmaintained crate replaced with the built-in PEM parser
  from **rustls-pki-types**.
- **sqlx**: set `default-features = false` to drop the unused `rsa` transitive
  dependency from the build graph.

### Fixed

- Remote URL rule sources were silently skipped in `load_all()` due to a missing
  async dispatch path — they are now loaded via `load_remote_sources()` after
  startup and on each scheduled refresh.
- OWASP CRS rules that use the `detect_sqli` / `detect_xss` operators were
  silently skipped because the operator was unregistered — the `libinjectionrs`
  integration now registers both operators at engine initialisation.
- Dead peer automatic eviction in cluster mode: peers that fail the phi-accrual
  threshold and do not reconnect within the configured grace period are now
  removed from the peer table and from the Admin UI node list.

---

## [0.1.0-rc.1] — 2026-03-16

### Added

#### Cluster — Full QUIC mTLS mesh (P1–P5 complete)

- **waf-cluster crate**: New crate implementing the full cluster protocol.

- **P1 — Transport & Certificates**
  - QUIC mTLS server/client (`transport/server.rs`, `transport/client.rs`) using
    quinn 0.11 + rustls 0.23 + rcgen 0.13 — reusing patterns from `gateway/http3.rs`.
  - Ed25519 cluster CA generation via `rcgen` (`crypto/ca.rs`).
  - Per-node certificate signing (`crypto/node_cert.rs`).
  - AES-GCM CA key storage for encrypted replication to workers (`crypto/store.rs`).
  - HMAC-SHA256 join token generation and validation (`crypto/token.rs`).
  - Length-prefixed JSON frame codec over QUIC streams (`transport/frame.rs`).
  - Static seed discovery from `ClusterConfig.seeds` (`discovery.rs`).
  - Heartbeat sender (periodic) and heartbeat tracker per peer (`health/`).

- **P2 — Rule & Config Sync**
  - `RuleChangelog` ring buffer (500-entry VecDeque) on main for incremental sync.
  - Full rule snapshot: serialize `RuleRegistry` → lz4-compressed JSON.
  - Incremental sync: workers send `RuleSyncRequest { current_version }` and receive
    only changed entries since their last known version.
  - Config sync protocol (TOML string) over a dedicated stream.
  - Attack event batching on workers with periodic flush to main.
  - `StorageMode` enum: `Full` (DB available) / `ForwardOnly` (writes forwarded).
  - `PendingForwards` for in-flight API write forwarding from workers to main.

- **P3 — Raft-lite Election & Failover**
  - `ElectionManager`: in-memory Raft-lite state machine (term, vote, timeout).
  - Phi-accrual failure detector (Cassandra-style) per-peer (`health/detector.rs`).
  - Role transitions: `Worker → Candidate → Main` and `Main → Worker`.
  - Split-brain prevention: fencing tokens + quorum requirement (N/2+1 votes).
  - CA key replication: encrypted CA key distributed to workers in `JoinResponse`.
  - CLI subcommands: `status`, `nodes`, `token generate`, `promote`, `demote`, `remove`.
  - 20 cluster tests across election, heartbeat, mTLS, and sync scenarios.

- **P4 — Admin UI Cluster Panel**
  - REST API under `/api/cluster/*` (5 endpoints: status, nodes, node detail,
    token generate, node remove).
  - `AppState.cluster_state: Option<Arc<NodeState>>` (None = standalone mode).
  - Four Vue 3 + Tailwind cluster views: Overview, Node Detail, Tokens, Sync Status.
  - i18n keys for English, Chinese, Russian, and Georgian.

- **P5 — Integration Test & Docker (this release)**
  - `docker-compose.cluster.yml`: 3-node cluster (1 main + 2 workers) using
    the existing `Dockerfile.prebuilt` pattern. Nodes communicate on port 16851
    via an internal `cluster_net` Docker network.
  - `tests/e2e-cluster.sh`: end-to-end test script verifying:
    - All 3 nodes healthy
    - Rule created on main syncs to workers within 15s
    - Election completes after stopping the main (new main elected)
    - Node rejoin after restart
  - `configs/cluster-node-{a,b,c}.toml`: per-node configuration files for the
    3-node docker-compose setup.
  - `docs/cluster-guide.md`: quick-start guide, full configuration reference,
    certificate management, troubleshooting, and architecture notes.
  - `cluster cert-init` CLI command: generates cluster CA + per-node certs
    offline for pre-provisioned deployments (`prx-waf cluster cert-init --nodes
    node-a,node-b,node-c --output-dir /certs`).
  - `ClusterCryptoConfig.ca_key` field: path to the CA private key file (main
    node only; empty on workers).
  - `CertificateAuthority::from_cert_pem()`: load CA cert without private key
    (used by worker nodes that only need to verify peer certs, not sign new ones).
  - Hostname resolution for cluster seeds: seeds can now be specified as
    `hostname:port` (e.g., `"node-a:16851"`) instead of requiring IP addresses —
    critical for docker-compose DNS names.
  - `auto_generate = false` path in `ClusterNode::run()`: loads certificates from
    files instead of always generating ephemeral in-memory certs.

### Changed

- `waf-common::config::ClusterCryptoConfig`: added `ca_key` field (empty default —
  fully backward-compatible with existing configs).
- `waf-cluster::crypto::ca::CertificateAuthority::as_rcgen_issuer()`: now returns
  an error if called on a cert-only instance (constructed via `from_cert_pem`).
- `waf-cluster::ClusterNode::run()`: restructured to support both in-memory cert
  generation (`auto_generate = true`) and file-based loading (`auto_generate = false`).
  NodeState is now created before cert setup to resolve `node_id` first.
- Cluster seed parsing: migrated from `str::parse::<SocketAddr>()` to
  `tokio::net::lookup_host()` for DNS/hostname support.

### Architecture Notes

- All cluster inter-node traffic runs over QUIC (UDP port 16851) with mutual TLS.
- Workers maintain an in-memory `RuleRegistry` populated via cluster sync.
  No SQLite required — workers operate database-free if needed.
- The entire cluster feature adds exactly **one new workspace dependency**: `lz4_flex`
  (all other deps — quinn, rustls, rcgen — were already in the workspace).
- WASM plugins are not synced to worker nodes in v1 (documented limitation).
- Standalone mode (no `[cluster]` section) continues to work with zero behavior change.

---

## [0.0.x] — Prior Releases

Phase 1–7 internal development milestones. Cluster P1–P4 completed 2026-03-16.
