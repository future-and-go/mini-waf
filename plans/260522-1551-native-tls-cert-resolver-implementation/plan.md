---
title: "Native TLS — wire SslManager + DB cert + ACME into Pingora runtime"
status: pending
created: 2026-05-22
owner: lotus
issue: https://github.com/future-and-go/mini-waf/issues/95
brainstorm: ./reports/brainstorm-summary.md
mode: hard
scope:
  hosts_per_node: 50
  cluster: false
  rust_edition: "2024"
  rustls_feature: "ring"
blockedBy: []
blocks: []
---

# Native TLS — wire SslManager + DB cert + ACME into Pingora runtime

## Goal

Kill nginx fronting. mini-waf binary tự terminate TLS, cert đọc từ Postgres `certificates` table qua rustls `ResolvesServerCert` resolver. ACME (instant-acme) tự issue + auto-renew. Wire `SslManager` (đã có sẵn ở `crates/gateway/src/ssl.rs`) vào Pingora runtime tại `crates/prx-waf/src/main.rs::run_server`. Đúng intent gốc của tác giả tại issue #95.

## Constraints

- 1 node, ≤50 hosts, **chưa** triển khai cluster
- Rust 2024, rustls 0.23 ring (KHÔNG switch boringssl/aws-lc-rs), Pingora 0.8 vendored fork
- LE production cuối, staging trong dev
- Backward-compat TOML `cert_file`/`key_file` 1 release (deprecate warning)
- HTTP-01 challenge — SG mở port 80 PERMANENT từ 0.0.0.0/0 (CFN update)

## Out of scope (defer)

Multi-cluster cert sync, DNS-01/wildcard, OCSP stapling, mTLS, PG column encryption cho cert PEM, cert sharding cross-node, upstream PR cloudflare/pingora.

## Phase status

| # | Phase | Status | LOC | Risk | File |
|---|---|---|---|---|---|
| 01 | Vendor pingora rustls patch | **completed 2026-05-22** | 59 net | Low | [phase-01-vendor-pingora-rustls-patch.md](./phase-01-vendor-pingora-rustls-patch.md) |
| 02 | DbCertResolver + cache + SslManager wire | pending | ~400 | **Med** | [phase-02-dbcertresolver-cache-sslmanager-wire.md](./phase-02-dbcertresolver-cache-sslmanager-wire.md) |
| 03 | ACME account persistence + HTTP-01 challenge filter | pending | ~500 | **Med** | [phase-03-acme-account-persist-http01-filter.md](./phase-03-acme-account-persist-http01-filter.md) |
| 04 | Background renewal + per-domain mutex + backoff | pending | ~250 | Low | [phase-04-background-renewal-and-hardening.md](./phase-04-background-renewal-and-hardening.md) |
| 05 | UI "Request via ACME" + CLI commands | pending | ~300 | Low | [phase-05-ui-cli-commands.md](./phase-05-ui-cli-commands.md) |
| 06 | Audit log + Prometheus metrics + key zeroize | pending | ~200 | Low | [phase-06-audit-metrics-zeroize.md](./phase-06-audit-metrics-zeroize.md) |

## Key dependencies

- Issue #95 architectural decision: chọn Path A (patch vendored pingora rustls + DB cert resolver)
- Brainstorm summary: [reports/brainstorm-summary.md](./reports/brainstorm-summary.md)
- Research bundle: [research/](./research/) — 3 reports (rustls API, instant-acme, vendor patch)
- Red-team findings reconciled vào phase 01-04 + 06 (hard mode requirement)
- Existing code: `crates/gateway/src/ssl.rs`, `vendor/pingora/pingora-core/src/listeners/tls/rustls/mod.rs`, `crates/gateway/src/proxy.rs:428` (filter mount point)
- Existing schema: migration `0003_certificates_and_rules.sql`; next available number `0012` (acme_accounts), `0013` (cert_audit_log), `0014` (acme_rate_limit_state)

## Red-team consistency sweep (mandatory before /ck:cook)

Trước khi implement, re-read mọi phase file để confirm:

- Phase 03 token regex `{22,128}` (NOT `{43}` cũ)
- Phase 03 filter mount AT TOP of `request_filter` (NOT vague "EARLY")
- Phase 03 XChaCha20-Poly1305 + per-row random nonce + BYTEA column (NOT ChaCha20 + TEXT)
- Phase 03 migration `0012_acme_accounts` (NOT `0011`)
- Phase 06 migration `0013_cert_audit_log` (NOT `0012`)
- Phase 04 migration `0014_acme_rate_limit_state` mới
- Phase 02 `tls_terminate` per-host gate preserve PR #93 fix
- Phase 02 hydrate fail-fast khi DB ≥1 row nhưng 0 cert load
- Phase 02 `AppState.ssl_manager: Option` → handler trả 503, không `.unwrap()`
- Phase 04 `consecutive_failure_count` cooldown column
- Phase 04 circuit breaker PERSIST DB, không in-memory only

## Verification gates

- Phase 01: vendor `cargo test -p pingora-core` xanh
- Phase 02: live cutover VM Singapore, smoke test §13 summary.md pass
- Phase 03: LE staging issue 1 cert end-to-end OK
- Phase 04: cert giả lập expiry +7d → background task tự renew
- Phase 05: UI manual smoke, CLI 6 commands work
- Phase 06: Prometheus scrape gauge exposed, audit row write

## Success metric overall

- nginx fully removed khỏi VM Singapore
- 50 hosts mỗi host cert riêng, SNI resolver hit ≥99.9%
- ACME auto-renew < 30d expiry, audit log capture
- Handshake p99 < 800ms từ US client
- Zero downtime trong cert rotation
