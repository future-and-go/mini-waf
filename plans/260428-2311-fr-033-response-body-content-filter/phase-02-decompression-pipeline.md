# Phase 02 — Decompression Pipeline (gzip-only v1)

> **RED-TEAM PATCH (mandatory):**
> - **#3** v1 supports ONLY gzip via `flate2::read::MultiGzDecoder` over `bytes::Bytes`. **Drop deflate + brotli** (defer to FR-033b ticket). Removes brotli panic-isolation risk.
> - For non-identity non-gzip `Content-Encoding`, scanner is disabled for that response (mirror AC-17 — `tracing::debug!`).
> - Add **input cap** `MAX_INPUT_BYTES = 2 * MAX_DECOMPRESS_BYTES = 8 << 20` (separate from output cap) to defend against legitimate-ratio giant inputs (red-team Sec #1).
> - Use `flate2::read::*Decoder::take(MAX_DECOMPRESS_BYTES)` for pre-allocation gating, NOT post-hoc check (red-team Assumption #10).
> - Pin `flate2 = "1.0.x"` in `crates/gateway/Cargo.toml` with comment citing red-team #11.
> - Reference: [`reports/red-team-260428-2332-fr033-adjudication.md`](reports/red-team-260428-2332-fr033-adjudication.md).

## Context Links
- Research: `research/researcher-01-fr033-best-practices-and-attacks.md` §4 (compression specifics, RFC 9110 §8.4, bomb defense), §5 (memory budget)
- RFC: [RFC 9110 §8.4 Content-Encoding](https://www.rfc-editor.org/rfc/rfc9110#section-8.4) (decompress in reverse order)
- Crates: `flate2`, `brotli` (research §4 recommendation table)
- AC-17 limitation cited: `crates/gateway/CLAUDE.md` "Body decompression is FR-033's problem"

## Overview
- **Priority:** P0
- **Status:** completed 2026-04-28
- Build a streaming decoder factory + bomb-safe bounded reader for gzip / deflate / br. Returns `Option<Box<dyn Read>>`-style streaming decoder that the scanner (phase-03) feeds. No async; runs inside Pingora's body-filter callback (sync, called per chunk).

### Deviations
- gzip-only in v1 per red-team #3 (deflate/brotli deferred to FR-033b).
- `DecoderChain` renamed `GzipDecoder` for simplicity; no multi-layer chain built in v1.

## Key Insights
- Pingora's `response_body_filter` is sync — gives us a `&mut Option<Bytes>` per chunk. We do NOT use `async-compression`; instead we feed bytes into `flate2::write::*Decoder` / `brotli::DecompressorWriter` writer-style streams.
- Writer-style streaming is the correct shape: each chunk push → decoder writes decompressed bytes into an output `Vec<u8>` → scanner consumes. No need to own the full body.
- RFC 9110 §8.4 mandates decompression in **reverse encoding order** (`Content-Encoding: gzip, deflate` → deflate first, then gzip). Real traffic almost always has a single encoding; multi-encoding is an attacker shape (research §6.1) and we still handle it.
- Bomb defense is two-layered (research §4): output cap (`max_decompress_bytes`) AND ratio cap (`output_so_far / input_so_far > max_ratio`).
- Fail-open philosophy (research §5): bomb / decode error → forward original encoded chunk untouched + `tracing::warn!`. We do NOT 502 the host — keeps WAF off the critical path.
- Re-emission decision (research §4 Option A): always drop `Content-Encoding` + `Content-Length` when scanner enabled and decompressing. Downstream switches to identity + chunked. Trade-off: ~3-5x body size, but simpler and CRIME-safe.

## Requirements
**Functional**
- Support `gzip`, `deflate`, `br`. Treat `identity` / absent as no-op.
- Reject (forward unscanned, log) any encoding outside that set.
- Honor RFC 9110 §8.4 reverse-order decompression chain.
- Enforce `max_decompress_bytes` (hard output cap).
- Enforce `max_decompress_ratio` (output/input ratio).
- Return error → caller forwards original bytes (fail-open).

**Non-functional**
- No `.unwrap()` / `.expect()` outside tests.
- Per-decoder allocation bounded (`flate2` uses ~64 KB internal buffer; `brotli` lgwin configurable, default ~4 MB — set explicitly to 22 = 4 MB).
- All errors via `Result<_, anyhow::Error>` with `.context(...)`.

## Architecture
```
gateway::filters::response_body_decompressor (NEW)
   ├── enum Encoding { Gzip, Deflate, Brotli, Identity }
   ├── parse_content_encoding(&str) -> Vec<Encoding>   // reverse-order ready
   ├── struct DecoderChain {
   │       layers: Vec<DecoderLayer>,
   │       input_bytes: u64,
   │       output_bytes: u64,
   │       max_output: u64,
   │       max_ratio: u32,
   │       failed: bool,
   │   }
   │     impl push(&[u8]) -> Result<Vec<u8>>     // streaming decompress
   │     impl finish() -> Result<Vec<u8>>        // EOS flush
   └── enum DecoderLayer { Gzip(MultiGzDecoder<...>), Deflate(...), Brotli(...) }
```

`DecoderChain::push` semantics:
- Push input bytes through the layered writer-decoders; collect decompressed output.
- Increment `input_bytes` += chunk.len(), `output_bytes` += produced.len().
- If `output_bytes > max_output` → return `Err(anyhow!("decompress output cap"))`.
- If `input_bytes >= 1024 && output_bytes / input_bytes > max_ratio` → return `Err(anyhow!("decompress ratio bomb"))` (require min input to avoid early FP at 1:N first-chunk).
- If decoder returns `io::Error` → return `Err(...)`.

Caller (phase-03 scanner) on `Err`: set `state.failed = true`, forward original encoded chunk untouched, suppress further decompression for this response.

## Related Code Files
**Create**
- `/Users/admin/lab/mini-waf/crates/gateway/src/filters/response_body_decompressor.rs` (~180 lines)

**Modify**
- `/Users/admin/lab/mini-waf/crates/gateway/Cargo.toml` — add `flate2 = "1"`, `brotli = "7"` (or workspace inheritance)
- `/Users/admin/lab/mini-waf/crates/gateway/src/filters/mod.rs` — add `pub mod response_body_decompressor;`

## Implementation Steps
1. Add deps to `gateway/Cargo.toml`. Check workspace `Cargo.toml` first; if `flate2` / `brotli` already present at workspace level, use `flate2.workspace = true`.
2. Create `response_body_decompressor.rs`. Define:
   - `pub enum Encoding { Gzip, Deflate, Brotli, Identity, Unknown }`
   - `pub fn parse_encoding_chain(header: &str) -> Vec<Encoding>` — split on `,`, trim, lowercase, map. Rejects on `Unknown` (returns `vec![Unknown]` so caller can fail-open).
3. Implement `DecoderLayer` as enum wrapping:
   - `Gzip(flate2::write::MultiGzDecoder<Vec<u8>>)` — supports concatenated gzip streams (RFC 8478 hardening)
   - `Deflate(flate2::write::DeflateDecoder<Vec<u8>>)`
   - `Brotli(brotli::DecompressorWriter<Vec<u8>>)` — call `with_buffer_size(4096)` if available
4. Implement `DecoderChain::new(encodings: &[Encoding], max_output: u64, max_ratio: u32) -> Result<Self>`:
   - Reject if any layer is `Unknown` / `Identity`-only-with-others.
   - Build layers in **reverse** order (last encoding applied first → decoded first).
5. Implement `DecoderChain::push(&mut self, chunk: &[u8]) -> Result<Vec<u8>>`:
   - Iterate through layers, feeding each layer's output into the next.
   - On every push: bump counters, run cap checks (output cap & ratio cap with `input_bytes >= 1024` floor).
   - Return decompressed final-layer output as `Vec<u8>`.
6. Implement `DecoderChain::finish(&mut self) -> Result<Vec<u8>>`:
   - Call `try_finish()` on each layer in order, propagate output through subsequent layers.
   - Same cap checks.
7. Use `?` + `.context("decoder push")` for all errors. NO `.unwrap()`.
8. Inline tests (`#[cfg(test)] mod tests`):
   - gzip round-trip on `Hello, world!\n` × 1000
   - deflate round-trip
   - brotli round-trip
   - `Unknown` encoding rejected
   - Reverse-order chain: `gzip(deflate(payload))` decoded correctly
   - Output cap triggers on synthetic 100 KB output / 1 KB cap
   - Ratio cap triggers on `0x00` × 1024 gzipped (~ 30 bytes) → 1024 byte output, ratio 33; with `max_ratio=10` rejects
   - Identity passthrough returns input unchanged

## Todo List
- [x] Add `flate2` to `gateway/Cargo.toml` (brotli deferred)
- [x] Register module in `filters/mod.rs`
- [x] Implement `Encoding` enum + `parse_encoding_chain` (gzip-only for v1)
- [~] Implement `DecoderLayer` enum — gzip/deflate/brotli deferred; v1 uses `flate2::read::MultiGzDecoder` directly
- [x] Implement gzip decoder setup + dual-cap checks (output + ratio)
- [x] Implement streaming `push` + cap checks
- [x] Implement `finish()` EOS flush + cap recheck
- [x] 8 unit tests + integration tests cover decompression
- [x] `cargo clippy -p gateway --all-targets -- -D warnings`
- [x] `cargo test -p gateway response_body_decompressor` green

## Success Criteria
- All 8 unit tests green.
- `cargo clippy -D warnings` clean.
- No `.unwrap()` outside tests.
- Bomb fixture (10000:1 ratio) returns `Err`, does not allocate beyond cap.
- gzip-of-deflate chain decodes round-trip.

## Risk Assessment
- **brotli crate sync-only & memory** (Likelihood: Low, Impact: Medium): default lgwin 22 = 4 MB working window. Acceptable per research §5. Document in module rustdoc.
- **`flate2` MultiGzDecoder vs GzDecoder** (Likelihood: Low, Impact: Low): we pick `MultiGz` to handle concatenated streams (rare but observed in real CDN traffic).
- **Ratio false-positive on tiny inputs** (Likelihood: Medium, Impact: Low): mitigated by `input_bytes >= 1024` floor before ratio enforcement.

## Security Considerations
- Decompression bomb (research §4 OWASP zip-bomb) is the primary attack class. Two-layer defense (output cap + ratio cap) is industry standard.
- Per Iron Rule #6, all external inputs validated: `Content-Encoding` parse rejects unknown tokens; `Content-Encoding: ` from upstream is treated as untrusted.
- Per Iron Rule #5, validate via `cargo check`; never `cargo run` to "see if it works".
- No secret logging on decode failure — log encoding name + byte counts only, never raw bytes.

## Next Steps
- Phase 03: scanner consumes `DecoderChain::push` output. Scanner owns the `failed` fail-open semantics and decides whether to forward original bytes.
