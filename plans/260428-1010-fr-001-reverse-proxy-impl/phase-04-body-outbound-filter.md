# Phase 04 — Body Outbound Filter (Internal-Ref Masking)

## Context Links
- Design doc §4.2 (response_body_filter), §6 risks (perf budget)
- Overlap: FR-033 outbound filter (this phase scope-limits to host-config-driven masking only)
- AC: AC-17

## Overview
- **Priority:** P2 (gate is FR-033 broader; this is the FR-001 slice)
- **Status:** completed (2026-04-28)
- **Description:** Implement `response_body_filter` ProxyHttp callback that streams chunks through a bounded regex masker driven by `host_config.internal_patterns: Vec<String>`. Out of scope: body decompression, full DOM rewriting — defer to FR-033.

## Key Insights
- Pingora `response_body_filter` sees raw bytes including possibly compressed (gzip/br). For FR-001 we **do not** decompress — only mask if `Content-Encoding: identity` (or absent). Compressed responses skipped with a `tracing::debug!`. Document explicitly.
- Streaming regex must handle pattern straddling chunk boundaries: keep a tail-buffer of `max_pattern_len - 1` bytes between chunks.
- Compile patterns once at `WafProxy::new` (or lazy per-host); never per-request.

## Requirements
**Functional**
- Replace each match of any configured pattern with a fixed mask token (default `[redacted]` or config-defined).
- Patterns config-driven per host: `internal_patterns: Vec<String>` (regex strings; `regex::RegexSet` for multi-pattern).
- Skip when `Content-Encoding` not in `{"", "identity"}`.
- Bounded: max body bytes processed per response = config (default 1 MiB); beyond → passthrough rest with `tracing::warn!`.

**Non-Functional**
- Allocation budget: at most one `Vec<u8>` rewrite per chunk; reuse buffers via `BytesMut`.
- p99 added latency at 5 KiB body ≤ 1 ms (verified phase 07).

## Architecture
**Pattern application**
- *Pipeline*: single body filter for now; trait `BodyFilter::apply(&self, chunk: &mut BytesMut, fctx: &FilterCtx, eos: bool)` — extension point for FR-033.
- *Strategy*: not needed yet (one masking algorithm); revisit in FR-033.

**Data flow**
```
response_body_filter(chunk, eos):
    if not maskable (encoding) → forward unchanged
    chunk = tail_buffer + chunk
    apply RegexSet → replacements
    keep last (max_pattern_len-1) bytes as new tail_buffer (unless eos)
    forward modified chunk
```

## Related Code Files
**Create**
- `crates/gateway/src/filters/body-mask-filter.rs`
- `crates/gateway/src/filters/body-filter-chain.rs` (mirror request/response chain)

**Modify**
- `crates/gateway/src/proxy.rs` — implement `response_body_filter` callback
- `crates/gateway/src/context.rs` — add `body_mask_state: BodyMaskState` (tail buffer, bytes-processed counter)
- `HostConfig` — add `internal_patterns: Vec<String>`, `mask_token: String` (default `[redacted]`), `body_mask_max_bytes: u64` (default 1 MiB)

## Implementation Steps
1. Add `HostConfig` fields with serde defaults.
2. Compile `regex::RegexSet` at host-config load (cache on `Arc<CompiledHostConfig>`); validate regex syntax — invalid → log error, host gets empty set (fail-open for body masking by design).
3. `BodyMaskState` lives in `GatewayCtx`: `tail: BytesMut`, `processed: u64`.
4. `BodyMaskFilter::apply`:
   - Skip if processed > max → forward.
   - Skip if no patterns → forward.
   - Concat tail + chunk → new buffer.
   - For each regex match → replace with mask token.
   - On `!eos`, retain last `max_pattern_len - 1` bytes in tail; rest = output chunk.
   - On `eos`, flush all.
5. Wire in `response_body_filter` ProxyHttp callback; check `Content-Encoding` from `ctx.upstream_response_headers` (cache during phase-03 response filter or read fresh).
6. Unit tests with crafted chunks straddling pattern boundary.

## Todo List
- [x] HostConfig fields + regex pre-compile (lazy, cached on `WafProxy.body_mask_cache` keyed by `Arc<HostConfig>` ptr)
- [x] `BodyMaskState` in `GatewayCtx`
- [x] `BodyMaskFilter` + tests (8 unit tests: single chunk, multi-chunk straddle, eos flush, disabled state, empty patterns, invalid pattern, ceiling, boundary regression)
- [x] Wire in `response_body_filter` (encoding detection + Content-Length strip in `response_filter`)
- [x] Document compressed-skip behavior in `crates/gateway/CLAUDE.md`

## Deviations from plan
- Skipped `body-filter-chain.rs` per YAGNI/KISS — only one body filter exists today; chain abstraction will be added when FR-033 introduces a second body filter. The single filter is invoked directly from `response_body_filter`.
- Used a single combined alternation `regex::bytes::Regex` instead of `RegexSet` because `RegexSet` only reports which patterns matched, not where — replacement requires positions.
- `Content-Length` is stripped whenever masking is *enabled*, not only when a replacement actually occurs (the header phase runs before any body chunks are seen, so we cannot know yet).

## Success Criteria
- AC-17: send response containing `backend.internal` and `10.0.0.5` → client receives `[redacted]` for both, identity-encoded only.
- Compressed (gzip) response: bypassed with debug log, no panic.
- Coverage ≥ 95% on new files.

## Risk Assessment
| Risk | Likelihood | Impact | Mitigation |
|------|-----------|--------|-----------|
| Regex catastrophic backtracking | M | H | Validate patterns at config load with `regex::Regex::new` (linear time engine — `regex` crate guarantees no backtracking; reject `regex_syntax` features that would degrade) |
| Tail buffer leaks across requests | M | M | Reset `BodyMaskState` on `new_ctx`; integration test long-running connection |
| Replacement changes Content-Length | H | H | Strip incoming `Content-Length` when mask token differs in length AND response was fixed-length; force chunked encoding. Test explicitly. |
| FR-033 scope creep | H | M | Hard scope: only `host_config.internal_patterns`. Body decoding/decompression is FR-033's problem. |

## Security Considerations
- Don't log matched/masked content (might be the secret itself).
- Patterns are operator-controlled config; no end-user input → regex DoS only via misconfig.

## Next Steps
- Phase 05: protocol matrix verifies the chain runs for h2/h3/ws too.
