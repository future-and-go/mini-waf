---
title: "FR-039 Circuit Breaker — Backend Unresponsive"
description: "Set Pingora upstream timeouts (connect/read/write/total/idle) per HostConfig; map upstream timeout/refused errors to 503 in error_to_status(); render existing 503 error page. Stateless, surgical, KISS."
status: pending
priority: P0
branch: "feat/fr-039-circuit-breaker"
tags: ["resilience", "fr-039", "production-ready", "pingora"]
blockedBy: []
blocks: []
created: "2026-05-12T07:25:00Z"
createdBy: "ck:plan"
relatedReports:
  - plans/reports/researcher-260512-1425-fr-039-pingora-circuit-breaker.md
  - plans/reports/scout-260512-1425-fr-039-gateway-state.md
---

# FR-039 Circuit Breaker

**Spec:** `analysis/requirements.md` line 79 (FR-039, P0 mandatory)
**Mandate:** *"If backend unresponsive, WAF returns 503 instead of hanging"*
**Target module:** `crates/gateway/src/proxy.rs` + `crates/waf-common/src/types.rs`

## Overview

Production-ready circuit breaker leveraging Pingora 0.8's built-in `HttpPeer.options.*_timeout` primitives. Surgical change: (1) add `upstream_*_timeout_ms` fields to `HostConfig`, (2) apply timeouts in `upstream_peer()`, (3) map timeout/refused errors → 503 in `error_to_status()`, (4) override `fail_to_connect()` to disable retry on timeout. **NO state machine** — Pingora's per-peer timeout + Pingora-default no-retry-on-timeout = stateless fast-fail.

## Acceptance Criteria (from FR-039)

- [ ] AC-1: Backend `sleep(60s)` on accept → WAF returns 503 within `read_timeout + 200ms`
- [ ] AC-2: Backend `connection refused` (port closed) → WAF returns 503 within `connection_timeout + 200ms`
- [ ] AC-3: TLS handshake hang → WAF returns 503 within `total_connection_timeout + 200ms`
- [ ] AC-4: Normal upstream 5xx (e.g., 500) → still maps to 502, NOT 503 (distinguish transport vs app errors)
- [ ] AC-5: Healthy backend → request succeeds end-to-end (no false positive)
- [ ] AC-6: Streaming response (SSE-like, chunked every 100ms) → no false timeout
- [ ] AC-7: Coverage ≥ 90% line+branch on all FR-039 code (cargo-llvm-cov)
- [ ] AC-8: Hot-reload of HostConfig propagates new timeouts on next request
- [ ] AC-9: Retry-After header set on 503 responses (5s)
- [ ] AC-10: HTTP/2 and HTTP/3 paths also enforce timeouts

## Locked Decisions (do not redebate)

| # | Decision | Rationale |
|---|----------|-----------|
| Scope | Transport-level only (Pingora upstream timeouts). NOT detection-layer. | FR-039 spec is transport-only. Detection-layer fail-mode is FR-036/037/038 (already done). |
| State | **Stateless** — no per-upstream failure counter, no Open/Half-Open/Closed | YAGNI. Pingora timeouts + fast-fail meet spec. State machine adds 100+ LOC for zero spec value. |
| Reuse `degrade::resolve()`? | **NO** | Red-team finding: matrix `(Medium, Open, BackendOverload) → AllowAndWarn` contradicts FR-039 ("return 503"). Backend down ≠ detection-layer degrade. Always 503 on transport fail. |
| Config scope | Per-`HostConfig` (per virtual host), not per-tier | KISS for v1. Per-tier optionally in Phase 5 if needed. |
| Test strategy | `tokio::net::TcpListener` mocks (no Docker) for unit; Docker e2e per `rules.md` | Per `rules.md` line 7: local has no Rust; Docker for full e2e. Unit tests run in CI image (Rust container). |
| Timeout defaults | conn=5s, total_conn=10s, read=30s, write=10s, idle=60s | Industry defaults (research §1); SSE/WS safe. |
| Branch | `feat/fr-039-circuit-breaker` | Per `rules.md` line 2: branch matches feature. |

## Locked Defaults

```toml
# Default values, all optional in TOML; missing = use these
upstream_connect_timeout_ms = 5000
upstream_total_connection_timeout_ms = 10000
upstream_read_timeout_ms = 30000
upstream_write_timeout_ms = 10000
upstream_idle_timeout_ms = 60000
upstream_circuit_503_retry_after_s = 5
```

## Phases

| Phase | Name | Status | Effort |
|-------|------|--------|--------|
| 1 | [Config schema + defaults](./phase-01-config-schema.md) | Pending | 2h |
| 2 | [Apply timeouts + error mapping in proxy](./phase-02-proxy-wiring.md) | Pending | 3h |
| 3 | [Unit tests with tokio mock backends](./phase-03-unit-tests.md) | Pending | 4h |
| 4 | [Docker e2e + HTTP/2/3 verification](./phase-04-docker-e2e.md) | Pending | 3h |
| 5 | [Coverage gate + docs + journal](./phase-05-coverage-docs.md) | Pending | 2h |

**Total estimated effort:** 14h (under 2 days).

## Key Dependencies

- ✅ Pingora 0.8 (`HttpPeer.options.*_timeout` already in workspace)
- ✅ `ErrorPageFactory::render(503, ...)` already exists in `gateway/src/error_page/`
- ✅ `HostConfig` schema in `waf-common/src/types.rs` (extension point)
- ❌ No PostgreSQL/Redis dependency required

## Files (CREATE / MODIFY / DELETE)

**Create:**
- `crates/gateway/tests/circuit_breaker_timeouts.rs` — unit/integration tests (mock backends)
- `tests/e2e/circuit-breaker/` — Docker e2e script + fixtures

**Modify:**
- `crates/waf-common/src/types.rs` — add 6 timeout fields + serde defaults to `HostConfig`
- `crates/waf-common/src/config.rs` — add validator: connection ≤ total_connection
- `crates/gateway/src/proxy.rs` — `upstream_peer()` set HttpPeer options; `error_to_status()` map timeout → 503; add `fail_to_connect()` override
- `crates/gateway/src/error_page/error_page_factory.rs` — add `Retry-After: 5` for 503
- `configs/default.toml` — document new fields (commented defaults)
- `docs/codebase-summary.md` + `docs/project-roadmap.md` — note FR-039 completion (Phase 5)

**Delete:** none

## Risk Assessment

| Risk | Likelihood | Impact | Mitigation |
|------|-----------|--------|-----------|
| Pingora `HttpPeer.options` field names differ in 0.8 | Low | High (compile fail) | Phase-1 first task: `cargo doc -p pingora-core --open` and verify field names; fall back to `peer.options.connection_timeout = Some(d)` pattern from research |
| HTTP/3 path bypasses our changes (separate listener) | Med | Med | Phase-4: explicit H3 test; if `http3.rs` constructs its own HttpPeer, mirror changes |
| Test flakiness on slow CI | Med | Low | Use ≥ 500ms timeouts; `127.0.0.1:0` ephemeral; per research §6 |
| Customers rely on default-Pingora long timeouts | Low | Med | Documented defaults match industry; sensible upgrade path |
| Hot-reload races (config swap mid-request) | Low | Low | ArcSwap snapshot per request — no torn reads |

## Security Considerations

- **DoS surface:** Returning 503 fast actually *reduces* DoS exposure (no thread-blocking).
- **Information leak:** 503 error page is generic (existing `ErrorPageFactory`); no upstream details leaked.
- **Retry-After:** Set 5s to prevent thundering herd; documented & configurable.

## Success Criteria

- [ ] All 10 ACs pass
- [ ] Coverage ≥ 90% on modified files (cargo-llvm-cov)
- [ ] `cargo fmt --all -- --check` passes
- [ ] `cargo clippy --all-targets --all-features -- -D warnings` passes
- [ ] Docker e2e (`tests/e2e/circuit-breaker/`) green
- [ ] `cargo check` and `cargo test -p gateway` green
- [ ] PR merged to `main` with green CI
- [ ] `docs/project-roadmap.md` + `docs/codebase-summary.md` updated

## Next Steps

1. Switch branch: `git checkout -b feat/fr-039-circuit-breaker` (from `main`)
2. Execute Phase 1 → 2 → 3 → 4 → 5 sequentially
3. Write `context.md` (per `rules.md` line 3; do NOT commit)
4. Open PR with summary referencing FR-039 + this plan

## Unresolved Questions

1. **HTTP/3 path:** Does `crates/gateway/src/http3.rs` construct its own `HttpPeer`, or share `WafProxy::upstream_peer()`? → Resolve in Phase 4 (verify or extend).
2. **Per-tier timeouts:** Worth adding (Critical=3s, CatchAll=30s) or premature? → Default per-host now; ask user if per-tier needed.
3. **Metric counters:** Add `upstream_timeout_total` Prometheus counter, or rely on `tracing::warn!` only? → Recommend warn-only for v1, defer counter to observability sprint.
