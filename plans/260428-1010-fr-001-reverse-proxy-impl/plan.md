---
title: "FR-001 Full Reverse Proxy — Implementation"
description: "Close 12 AC gaps in crates/gateway/src/proxy.rs; introduce filter-pipeline + Strategy patterns; 95% coverage gate."
status: pending
priority: P1
effort: 5d
branch: main
tags: [waf, gateway, pingora, fr-001, reverse-proxy]
created: 2026-04-28
blockedBy: []
blocks: []
---

## Source
Design doc (verbatim source of all ACs): [`plans/reports/brainstorm-260424-1416-fr-001-reverse-proxy-design.md`](../reports/brainstorm-260424-1416-fr-001-reverse-proxy-design.md)

## Scope
Close all 25 ACs (AC-01..AC-25). Refactor `crates/gateway/src/proxy.rs` (currently 376 LoC, monolithic) into a filter-pipeline with Strategy-based header/body policies. Coverage gate ≥ 95% on new+modified gateway code.

## Phases

| # | File | Owner files | Status | ACs |
|---|------|-------------|--------|-----|
| 01 | [phase-01-foundation-refactor.md](phase-01-foundation-refactor.md) | proxy/* (split), pipeline/*, ctx-builder | completed | bug-fix is_tls, AC-22, AC-23 |
| 02 | [phase-02-request-transforms.md](phase-02-request-transforms.md) | filters/request-*, host-policy | completed | AC-12, 13, 14, 20, 25 |
| 03 | [phase-03-response-transforms.md](phase-03-response-transforms.md) | filters/response-*, error-page-factory | completed | AC-15, 16, 18, 19 |
| 04 | [phase-04-body-outbound-filter.md](phase-04-body-outbound-filter.md) | filters/body-mask | completed | AC-17 |
| 05 | [phase-05-protocol-matrix.md](phase-05-protocol-matrix.md) | protocol.rs, http3.rs, proxy.rs, main.rs | code-complete | AC-08, 09, 10, 11, 22 |
| 06 | [phase-06-test-harness-coverage.md](phase-06-test-harness-coverage.md) | tests/fr001_*.rs, synthetic-backend | pending | All (verification) |
| 07 | [phase-07-perf-leak-validation.md](phase-07-perf-leak-validation.md) | bench/, leak-sweep | pending | AC-21, 24, leak sweep |

Phase deps: 01 blocks 02..05. 06 blocks merge. 07 final gate.

## Design pattern justification

| Pattern | Where | Serves | Why beats simpler |
|---------|-------|--------|-------------------|
| **Pipeline (Chain of Responsibility)** | `RequestFilterChain` / `ResponseFilterChain` invoked from Pingora `upstream_request_filter` / `upstream_response_filter` | AC-12..18, future filters | New transforms (FR-033 outbound, header policies) drop into Vec<Box<dyn Filter>> — no edits to existing filter code. Alternative (one fat function) violates OCP and balloons proxy.rs past 200 LoC rule. |
| **Strategy** | `HostHeaderPolicy` (preserve/rewrite — AC-25), `ServerHeaderPolicy` (passthrough/strip — AC-16), `LocationRewritePolicy` (AC-18) | AC-16, 18, 25 (config-driven branches) | Config flag → trait object selected at router-resolve time. Alternative (if/else inside filter) couples policy to filter; can't unit-test policy in isolation. |
| **Builder** | `RequestCtxBuilder` (replaces `build_request_ctx`) | AC-22 (no-bypass invariant), is_tls fix | Single point of construction; impossible to forget `is_tls` or skip required fields; testable without Pingora session. |
| **Factory** | `ErrorPageFactory::render(status, accept_header)` | AC-19 | Negotiates HTML/JSON/plain per Accept; no Pingora-default fingerprint. Alternative (inline match in proxy) duplicates rendering across error sites. |
| **Registry** | Listener registry binding H1/H2/H3/WS to single `Arc<WafProxy>` | AC-08..11, AC-22 | Forces every listener to share one filter chain — structural guarantee against bypass. Alternative (per-protocol proxy impl) risks divergent filters. |

**Rejected patterns:** Visitor (overkill — one operation per filter), Observer (logging is already tracing), Decorator on `WafProxy` itself (Pingora trait sealed by macros), Command (no undo/queue need).

## Completion Status
**Phase 01:** completed 2026-04-28 — commits 5488cbf, efdf552 on main. Code review: 9.6/10. Unblocks phase 02–05.
**Phase 02:** completed 2026-04-28 — 5 filters + 1 strategy + chain wiring. 16 unit tests, all 373 workspace tests pass; clippy clean. Closes AC-12, 13, 14, 20, 25.
**Phase 03:** completed 2026-04-28 — 4 response filters + 2 strategies + ErrorPageFactory + `fail_to_proxy` override. 16 unit tests; 395/395 workspace pass; clippy clean. Closes AC-15, 16, 18, 19. `cargo-llvm-cov` coverage gate deferred to CI.
**Phase 04:** completed 2026-04-28 — streaming `response_body_mask_filter` (combined alternation `regex::bytes::Regex`, tail-buffered straddle), `BodyMaskState` on `GatewayCtx`, lazy per-host compiled cache on `WafProxy`. 8 unit tests; 403/403 workspace pass; clippy clean. Closes AC-17. KISS: skipped speculative `body-filter-chain.rs` until FR-033 needs a second body filter.
**Phase 05:** code-complete 2026-04-28 — new `protocol.rs` (`Protocol` enum + `ProtoCounters` struct + session detection), `proto_counters: Arc<ProtoCounters>` on `WafProxy`, tagged & incremented in `request_filter`, H3 path bumps the same struct, ALPN/protocol-surface log line at startup. 2 unit tests; clippy clean. Integration tests (H1/H2c/H3/WS handshake) deferred to phase-06 per plan. Documented scope: pipeline filter chains stay H1/H2-only by design; H3 still WAF-inspected via `engine.inspect()` so AC-22 no-bypass holds.

## Coverage strategy

- **Tool**: `cargo-llvm-cov` (LLVM source-based, workspace-aware, integrates with `nextest`).
- **Scope**: lines added or modified in `crates/gateway/src/{proxy,filters,policies,error_page,pipeline,ctx_builder}.rs`. Existing untouched modules (`cache.rs`, `lb.rs`, `tunnel.rs`, `ssl.rs`) excluded via `--ignore-filename-regex`.
- **Gate**: CI step `cargo llvm-cov --workspace --fail-under-lines 95 --ignore-filename-regex '(cache|lb|tunnel|ssl|http3)\.rs$'`.
- **Mock strategy**:
  - Strategies/factories tested as **plain unit tests** — no Pingora needed. Inputs: `&RequestHeader`, `&ResponseHeader`, `&HostConfig`. Outputs: header mutations or rendered bytes.
  - Filter chain unit-tested with a stub `Session` trait extracted from Pingora's surface used by filters (narrow trait, owned by us).
  - Integration tests use **axum synthetic backend** binding to `127.0.0.1:0`, started per-test, asserting `X-Forwarded-*`, body fidelity, etc.

## AC traceability matrix

| AC | Phase | Step | Test ID |
|----|-------|------|---------|
| AC-01 methods | 06 | 6.2 | fr001_methods_matrix |
| AC-02 req body | 06 | 6.3 | fr001_req_body_sizes |
| AC-03 resp body | 06 | 6.4 | fr001_resp_body_shapes |
| AC-04 header fidelity | 06 | 6.5 | fr001_header_diff |
| AC-05 status sweep | 06 | 6.6 | fr001_status_sweep |
| AC-06 url fuzz | 06 | 6.7 | fr001_url_fuzz |
| AC-07 keep-alive | 06 | 6.8 | fr001_keepalive |
| AC-08 H1 | 05 | 5.2 | fr001_proto_h1 |
| AC-09 H2 | 05 | 5.3 | fr001_proto_h2c, fr001_proto_h2_tls |
| AC-10 H3 | 05 | 5.4 | fr001_proto_h3 |
| AC-11 WS | 05 | 5.5 | fr001_ws_handshake_through_chain |
| AC-12 XFF inject | 02 | 2.3 | unit_xff_filter / fr001_xff_e2e |
| AC-13 XFProto/Host/Real-IP | 02 | 2.4 | unit_forwarded_headers |
| AC-14 XFF append | 02 | 2.3 | unit_xff_append_chain |
| AC-15 leak headers | 03 | 3.3 | unit_via_strip / fr001_leak_headers |
| AC-16 Server policy | 03 | 3.4 | unit_server_policy_{passthrough,strip} |
| AC-17 body internal-ref | 04 | 4.2 | unit_mask_filter / fr001_body_leak_scan |
| AC-18 Location rewrite | 03 | 3.5 | unit_location_rewriter |
| AC-19 error page | 03 | 3.6 | unit_error_factory_{html,json} / fr001_error_page |
| AC-20 hop-by-hop | 02 | 2.5 | unit_hop_by_hop |
| AC-21 p99 ≤5ms | 07 | 7.2 | bench_wrk_p99 |
| AC-22 no bypass | 01 | 1.4 | unit_fail_closed_on_no_ctx / fr001_counter_eq_requests |
| AC-23 TLS term | 06 | 6.9 | fr001_tls_termination |
| AC-24 abort | 07 | 7.3 | fr001_client_abort_loop |
| AC-25 Host policy | 02 | 2.6 | unit_host_policy_{preserve,rewrite} |

All 25 mapped. No orphans.

## Naming convention note
Phase files spell `.rs` paths in kebab-case for plan-readability and Grep/Glob friendliness (per project rule). At implementation time, translate to **snake_case** per Rust ecosystem convention (e.g. `request-xff-filter.rs` → `request_xff_filter.rs`). Module names follow snake_case. This translation is mechanical and non-negotiable for `rustc`.

## Unresolved questions
1. **WS frame-level inspection?** Design doc §9 Q1. Default: handshake-only, document clearly. Escalate to product if Attack Battle requires frame inspection.
2. **`preserve_host` default?** §9 Q2. Recommend **preserve** (transparent default); rewrite as opt-in per host config.
3. **AC-16 strip vs passthrough default?** §9 Q3. Recommend **passthrough** (preserves AC-04 byte-identical contract); strip is opt-in.
4. **HTTP/3 in Attack Battle scoring?** §9 Q4. Need product confirmation before sinking effort into AC-10 perf tuning.
5. **Error-page format default?** §9 Q5. Decision: content-negotiate by `Accept`; fallback `text/plain` minimal body. Implemented in phase-03.
6. **Coverage tool acceptance** — `cargo-llvm-cov` requires LLVM tools; confirm CI runner has them or fall back to `tarpaulin`.
