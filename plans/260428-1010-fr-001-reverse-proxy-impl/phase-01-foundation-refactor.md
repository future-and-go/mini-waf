# Phase 01 — Foundation Refactor

## Context Links
- Design doc §3 (gap), §4.5 (no-bypass), §4.6 (is_tls bug): `plans/reports/brainstorm-260424-1416-fr-001-reverse-proxy-design.md`
- Current code: `crates/gateway/src/proxy.rs` (376 LoC — exceeds 200 LoC rule, must split)
- ACs targeted: bug-fix `is_tls`, AC-22 no-bypass, AC-23 TLS term verification

## Overview
- **Priority:** P1 (blocks 02–05)
- **Status:** completed
- **Description:** Split monolithic `proxy.rs` into modules. Introduce `RequestFilterChain` / `ResponseFilterChain` traits. Introduce `RequestCtxBuilder`. Fix `is_tls` hardcoded false. Convert `Ok(false)` no-context fallthrough to fail-closed 5xx. Existing tests stay green; no new ACs satisfied here — this is the seam for phases 02–05.

## Key Insights
- Pingora `Session::digest().ssl_digest` is the source of truth for TLS termination at the listener.
- `request_filter` returning `Ok(false)` on missing ctx (line 213) is a silent bypass — must fail-closed.
- Splitting before adding new code prevents 600-line `proxy.rs`. Each new file <200 LoC per project rule.

## Requirements
**Functional**
- `is_tls` reflects listener TLS state.
- Missing `request_ctx` → 503 fail-closed, increments `blocked_counter`, never `Ok(false)`.
- `RequestFilterChain` and `ResponseFilterChain` exist as `Vec<Arc<dyn Filter>>` invoked in registration order.
- `RequestCtxBuilder` constructs `RequestCtx` from `(Session, HostConfig)` — no Pingora dependency in unit tests.

**Non-Functional**
- Each new file ≤ 200 LoC, kebab-case names.
- Zero new clippy warnings; `cargo clippy --workspace --all-targets -- -D warnings` clean.
- No `.unwrap()` / `.expect()` in non-test code.

## Architecture
```
crates/gateway/src/
├── proxy.rs                       # ProxyHttp impl only — wires chains; ~120 LoC
├── pipeline/
│   ├── mod.rs                     # Filter traits, FilterChain
│   ├── request-filter-chain.rs    # exec ordered request filters
│   └── response-filter-chain.rs   # exec ordered response filters
├── ctx-builder/
│   └── request-ctx-builder.rs     # Builder for RequestCtx (incl. is_tls fix)
├── filters/                       # populated in phases 02–04
└── policies/                      # populated in phases 02–03
```

**Pattern application**
- *Pipeline (CoR)*: `trait RequestFilter { fn apply(&self, req: &mut RequestHeader, ctx: &FilterCtx) -> Result<()> }`. Chain wraps `Vec<Arc<dyn RequestFilter + Send + Sync>>`. Justification: Phase 02–04 add filters without re-touching this code (OCP).
- *Builder*: `RequestCtxBuilder::new(session).with_host_config(hc).build() -> RequestCtx`. Single is_tls source.

**Data flow** (post-refactor):
```
listener → ProxyHttp::request_filter
              ├── RequestCtxBuilder.build()  (is_tls correct)
              ├── if ctx.is_none() → fail_closed_503 (AC-22)
              ├── WAF engine.inspect()
              └── (chains invoked in upstream_request_filter / upstream_response_filter — phases 02/03)
```

## Related Code Files
**Modify**
- `crates/gateway/src/proxy.rs` — slim to ProxyHttp impl + chain orchestration
- `crates/gateway/src/lib.rs` — export new modules

**Create**
- `crates/gateway/src/pipeline/mod.rs`
- `crates/gateway/src/pipeline/request-filter-chain.rs`
- `crates/gateway/src/pipeline/response-filter-chain.rs`
- `crates/gateway/src/ctx-builder/mod.rs`
- `crates/gateway/src/ctx-builder/request-ctx-builder.rs`

**Delete**: none.

## Implementation Steps
1. Create `pipeline/mod.rs` with traits:
   ```
   trait RequestFilter: Send + Sync {
       fn apply(&self, req: &mut RequestHeader, fctx: &FilterCtx) -> pingora_core::Result<()>;
       fn name(&self) -> &'static str;
   }
   trait ResponseFilter: Send + Sync {
       fn apply(&self, resp: &mut ResponseHeader, fctx: &FilterCtx) -> pingora_core::Result<()>;
       fn name(&self) -> &'static str;
   }
   ```
   `FilterCtx` borrows `&RequestCtx`, `&HostConfig`, peer IP, is_tls.
2. Create `request-filter-chain.rs` / `response-filter-chain.rs` — `apply_all` iterates filters; first error short-circuits with `tracing::warn!` (filter name + error).
3. Create `request-ctx-builder.rs`:
   - Replace inlined `build_request_ctx`.
   - `is_tls = session.digest().and_then(|d| d.ssl_digest.as_ref()).is_some()` — fixes line 125 bug.
   - Unit tests: feed minimal stub headers + `is_tls` flag; assert built ctx.
4. **Fail-closed patch in `proxy.rs::request_filter`** (replaces line 211–214):
   - If `ctx.request_ctx` still `None` after resolve attempt → return 503 with neutral body via `ErrorPageFactory` placeholder (factory itself lands in phase-03; phase-01 uses minimal "Service Unavailable" plain text), increment `blocked_counter`, `return Ok(true)`. **Never** `Ok(false)` here.
5. Wire empty chains into `WafProxy` struct: `request_chain: Arc<RequestFilterChain>`, `response_chain: Arc<ResponseFilterChain>`. Phase 02/03 register filters.
6. Add `upstream_request_filter` and `upstream_response_filter` ProxyHttp methods invoking the chains; pass through unchanged when chain empty.
7. Run `cargo clippy --workspace --all-targets --all-features -- -D warnings` and `cargo test -p gateway`.

## Todo List
- [x] Create `pipeline/` module with two traits + chains
- [x] Create `ctx-builder/` with `RequestCtxBuilder`
- [x] Fix `is_tls` to read `session.digest().ssl_digest`
- [x] Replace `Ok(false)` on missing ctx with fail-closed 503
- [x] Slim `proxy.rs` to ≤ 200 LoC
- [x] Wire empty chains into ProxyHttp filter callbacks
- [x] Unit tests for `RequestCtxBuilder` (TLS on/off, missing host header, IPv6 peer)
- [x] All existing tests green; clippy clean

## Success Criteria
- `RequestCtxBuilder` unit tests cover TLS-on, TLS-off, missing-host, IPv4, IPv6 (≥ 95% lines).
- `proxy.rs` ≤ 200 LoC.
- No-bypass test: induce `request_ctx == None` (mock router returns `None`) → response = 503, counter == 1, never reaches upstream. **Proves AC-22.**
- `is_tls` test: TLS session → ctx.is_tls == true.
- All existing gateway tests still pass.

## Risk Assessment
| Risk | Likelihood | Impact | Mitigation |
|------|-----------|--------|-----------|
| Pingora `Session::digest()` API differs in current pinned version | M | M | Verify against `Cargo.lock` Pingora version before coding step 3; fallback to `session.is_https()` if exposed |
| Refactor regresses an existing edge case | M | H | Run full `cargo test -p gateway` before & after; commit refactor as **separate** commit from logic changes |
| Filter trait object dispatch hot-path cost | L | L | Benchmark at phase 07; chains stay short (≤6 filters) |

## Security Considerations
- Fail-closed on missing ctx is a **security primitive** — must never regress to `Ok(false)`. Add a clippy `#[deny]` attribute or test guard.
- `RequestCtxBuilder` must not log header values (no secret leakage).

## Next Steps
- Phase 02 registers request filters into the chain.
- Phase 03 registers response filters and replaces stubbed error page with `ErrorPageFactory`.
