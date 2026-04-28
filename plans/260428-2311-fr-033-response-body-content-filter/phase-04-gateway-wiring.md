# Phase 04 — Gateway Wiring (chain reorder + content-hash cache)

> **RED-TEAM PATCH (mandatory):**
> - **#4** Invocation order in `response_body_filter` is **FR-033 → PR-18 → AC-17** (NOT redact → scan → mask). PR 18 buffers entire body until EOS — placing FR-033 downstream collapses streaming. FR-033 owns decompression; PR-18/AC-17 see plaintext.
> - **#6** Cache key by content-hash, NOT `Arc::as_ptr`. Use `(host_name: String, xxhash64(serialized body_scan_* fields))` keyed `moka::sync::Cache<_, Arc<CompiledScanner>>` with `max_capacity(256)` + `time_to_live(Duration::from_secs(3600))`. Replace on hash mismatch for same host.
> - **#9** Drop `Content-Length` AND `Transfer-Encoding` UNCONDITIONALLY when `body_scan_enabled && !is_noop()`. Re-emit `Transfer-Encoding: chunked`. Drop `Content-Encoding` only when gzip-decoded successfully.
> - **#11** Add `static_assertions::assert_impl_all!(crate::context::BodyScanState: Send);` in test module (compile-time guarantee).
> - **(unresolved Q2)** Add Content-Type allowlist guard at `response_filter`: enable scanner ONLY for `text/*`, `application/json`, `application/xml`, `application/problem+json`, `application/javascript`. Skip `application/grpc*`, `text/event-stream`, `application/octet-stream`.
> - Reference: [`reports/red-team-260428-2332-fr033-adjudication.md`](reports/red-team-260428-2332-fr033-adjudication.md).

## Context Links
- AC-17 wiring reference: `crates/gateway/src/proxy.rs` lines 50–94 (cache field + `resolve_mask`), 325–390 (`response_filter` + `response_body_filter`)
- AC-17 cache pattern: `Arc<DashMap<usize, Arc<CompiledMask>>>` keyed by `Arc::as_ptr(hc)`
- Conflict map: see top-of-plan rules — DO NOT touch `prx-waf/main.rs`, `config.rs`, `project-roadmap.md`

## Overview
- **Priority:** P0
- **Status:** completed 2026-04-28
- Wire `CompiledScanner` into Pingora's response phase callbacks, mirroring AC-17 patterns. Insert FR-033 invocation between PR-18 redact and AC-17 mask in `response_body_filter`. Manage Content-Encoding/Content-Length header mutations correctly when scanner is decompressing.

### Deviations
- Cache key uses content-hash (xxhash64 of body_scan_* fields) instead of `Arc::as_ptr` per red-team #6.
- Uses `moka::sync::Cache` instead of `DashMap` for TTL-based eviction (1h default).
- Placeholder for PR-18 redact integration; order remains FR-033 → AC-17 in implementation.

## Key Insights
- AC-17 uses lazy-compile cache keyed by `Arc<HostConfig>` pointer identity (`Arc::as_ptr` cast `usize`). Survives until config reload (which produces a new `Arc`). FR-033 mirrors this exactly — separate cache field, same shape.
- Header mutation order in `response_filter`:
  1. existing `response_chain.apply_all` (via, server-policy, location, header-blocklist)
  2. PR-18 redact decision (drops `Content-Length` if active)
  3. **FR-033 scan decision** (drops `Content-Length` AND `Content-Encoding` if scanner active and will mutate body)
  4. AC-17 mask decision (drops `Content-Length` if active)
  
  Multiple drops of the same header are idempotent — order is safe.
- `response_body_filter` invocation order:
  1. `apply_redact_chunk` (PR-18 — JSON field name redact)
  2. `apply_body_scan_chunk` (FR-033 — built-in catalogs over plaintext)
  3. `apply_body_mask_chunk` (AC-17 — operator regex)
  
  Rationale: PR-18 most precise (named field), FR-033 broad-spectrum, AC-17 operator-specific. Each layer narrows leakage.
- Decision matrix for FR-033 enable in `response_filter`:

  | scan_enabled config | Content-Encoding | scanner.is_noop() | enable scan? | drop CE? | drop CL? |
  |---------------------|------------------|-------------------|--------------|----------|----------|
  | false               | any              | any               | no           | no       | no       |
  | true                | any              | true              | no           | no       | no       |
  | true                | identity / absent| false             | yes          | no       | yes      |
  | true                | gzip/deflate/br  | false             | yes          | yes      | yes      |
  | true                | unknown          | false             | no (fail-open)| no      | no       |

- Construct `DecoderChain` in `response_filter` (when scan enabled + decompressible encoding) and store in `BodyScanState::decoder`. This way decoder construction error → fail-open at decision time, not on first chunk.

## Requirements
**Functional**
- Add `body_scan_cache: Arc<DashMap<usize, Arc<CompiledScanner>>>` to `WafProxy`.
- Add `WafProxy::resolve_scanner(&self, hc: &Arc<HostConfig>) -> Arc<CompiledScanner>` mirroring `resolve_mask`.
- In `response_filter`: per decision matrix above, set `ctx.body_scan.enabled`, optionally construct `DecoderChain` into `ctx.body_scan.decoder`, drop CE/CL headers.
- In `response_body_filter`: invoke in chain order (PR-18 → FR-033 → AC-17). Each layer reads its own enable flag.

**Non-functional**
- Zero allocations on disabled path (early-return when `body_scan_enabled = false` AND no decompression needed).
- Header mutations via Pingora's typed API (`remove_header`).
- NO `.unwrap()` — pattern matching on `Option`s / `if let`.

## Architecture
```
proxy.rs:
   WafProxy {
       ...
       body_mask_cache: Arc<DashMap<usize, Arc<CompiledMask>>>,           // existing AC-17
       body_redact_cache: Arc<DashMap<usize, Arc<CompiledRedactor>>>,     // PR-18 (when merged)
       body_scan_cache:  Arc<DashMap<usize, Arc<CompiledScanner>>>,       // NEW
   }

   impl WafProxy {
       fn resolve_scanner(&self, hc: &Arc<HostConfig>) -> Arc<CompiledScanner> {
           // mirror resolve_mask line-for-line
       }
   }

   async fn response_filter(...) {
       self.response_chain.apply_all(...)?;

       // PR-18 (when merged)
       // ... redact decision, drop CL if active

       // FR-033
       if hc.body_scan_enabled {
           let scanner = self.resolve_scanner(hc);
           if !scanner.is_noop() {
               let ce = upstream_response.headers
                   .get("content-encoding")
                   .and_then(|v| v.to_str().ok())
                   .map(str::trim).unwrap_or("");
               let chain = parse_encoding_chain(ce);
               match build_decoder_or_identity(&chain, scanner.max_decompress_bytes, scanner.max_decompress_ratio) {
                   Ok(decoder_opt) => {
                       ctx.body_scan.enabled = true;
                       ctx.body_scan.decoder = decoder_opt;
                       let _ = upstream_response.remove_header("content-length");
                       if decoder_opt_used { let _ = upstream_response.remove_header("content-encoding"); }
                   }
                   Err(_) => { /* fail-open: leave disabled, debug-log */ }
               }
           }
       }

       // AC-17 (existing) — unchanged
   }

   fn response_body_filter(...) {
       // PR-18 (when merged)
       // apply_redact_chunk(&mut ctx.body_redact, &compiled_redact, body, eos);

       if ctx.body_scan.enabled && !ctx.body_scan.blocked {
           let scanner = self.resolve_scanner(hc);
           apply_body_scan_chunk(&mut ctx.body_scan, &scanner, body, eos);
       }

       if ctx.body_mask.enabled {
           let mask = self.resolve_mask(hc);
           apply_body_mask_chunk(&mut ctx.body_mask, &mask, body, eos);
       }
       Ok(None)
   }
```

## Related Code Files
**Modify**
- `/Users/admin/lab/mini-waf/crates/gateway/src/proxy.rs` —
  - Add `body_scan_cache` field on `WafProxy` (line ~58)
  - Initialize in `WafProxy::new` (line ~74)
  - Add `resolve_scanner` method (after `resolve_mask` line ~94)
  - In `response_filter` (line 325–366): insert decision block after PR-18 (or after existing AC-17 chain when PR 18 not yet merged), before AC-17 decision
  - In `response_body_filter` (line 368–387): insert FR-033 call between PR-18 and AC-17

**DO NOT MODIFY** (conflict avoidance)
- `crates/waf-common/src/config.rs` (PR-14 owns)
- `crates/prx-waf/src/main.rs` (auto-resolves via cache, no startup wiring needed)
- `docs/project-roadmap.md` (PR-18 strategy — avoid diamond conflict)

## Implementation Steps
1. Add `body_scan_cache` field on `WafProxy`. Initialize as `Arc::new(DashMap::new())` in `WafProxy::new`.
2. Implement `resolve_scanner(&self, hc: &Arc<HostConfig>) -> Arc<CompiledScanner>`:
   - Key = `Arc::as_ptr(hc) as usize`.
   - Cache hit → return clone.
   - Miss → `CompiledScanner::build(hc)` → wrap `Arc::new` → insert → return clone.
   - Use `parking_lot::Mutex` only if needed; `DashMap` is enough.
3. In `response_filter`:
   - After existing AC-17 decision block (line 343–363) or in PR-18 ordering position (between redact and mask), insert FR-033 block.
   - Build helper `build_decoder_or_identity(chain, max_out, max_ratio) -> Result<Option<DecoderChain>>`:
     - All-Identity → `Ok(None)`
     - Recognized chain → `Ok(Some(DecoderChain::new(...)?))`
     - Unknown encoding present → `Err(...)` → fail-open, log debug, scan disabled.
   - On success: set `ctx.body_scan.enabled = true`, set `ctx.body_scan.decoder = decoder_opt`, drop CL always, drop CE iff `decoder_opt.is_some()`.
4. In `response_body_filter`:
   - Insert FR-033 call between any future PR-18 redact call and existing AC-17 mask call.
   - Guard with `ctx.body_scan.enabled && !ctx.body_scan.blocked`.
   - On `state.blocked = true` flag set inside scanner, downstream chunks short-circuit (scanner already replaced `body`).
5. Verify no removal of existing AC-17 code paths — purely additive insertion.
6. `cargo check --workspace`, `cargo clippy --workspace --all-targets --all-features -- -D warnings`.

## Todo List
- [x] Add `body_scan_cache` field on `WafProxy` struct (`moka::sync::Cache`)
- [x] Initialize `body_scan_cache` in `WafProxy::new`
- [x] Implement `WafProxy::resolve_scanner` (mirror `resolve_mask`, content-hash key)
- [x] Add helper `build_decoder_or_identity` (gzip check, fail-open)
- [x] Insert FR-033 decision block in `response_filter` (after redact decision when merged)
- [x] Insert `apply_body_scan_chunk` call in `response_body_filter` (between redact/mask)
- [x] Verify AC-17 `body_mask_cache` and behavior unchanged
- [x] Verify ordering: scan (FR-033) → mask (AC-17) [PR-18 redact placeholder OK]
- [x] `cargo check --workspace` green
- [x] `cargo clippy --workspace -- -D warnings` green

## Success Criteria
- Scanner runs on identity bodies when enabled.
- Scanner runs on gzip/deflate/br bodies when enabled (decoder chain attached).
- Scanner skipped + warn-debug-log when unknown encoding (fail-open).
- AC-17 still works on identity bodies (regression-tested in phase-05).
- `cargo clippy -D warnings` clean.
- No new `.unwrap()`.

## Risk Assessment
- **PR-18 ordering placeholder** (Likelihood: High textual conflict, Impact: Low): the actual call to `apply_redact_chunk` lands when PR-18 merges. Until then, FR-033 sits at the same insertion point. Resolution map in phase-06 PR description.
- **`Arc::as_ptr` cast soundness** (Likelihood: Low, Impact: Low): same pattern as AC-17 line 82; reviewed and accepted; not Iron Rule violation (no unsafe, no panic).
- **Cache leak across config reloads** (Likelihood: Low, Impact: Low): when host config reloads, old `Arc` becomes orphan but cache entry survives until next eviction. AC-17 has same property; defer eviction policy to a future ticket consistent with AC-17.

## Security Considerations
- Iron Rule #1: no `.unwrap()` introduced; review every `?` site has `.context(...)`.
- Iron Rule #2: no dead code — feature gate the helper if PR-18 hasn't merged yet by using `pub(crate)` and a single call site.
- Iron Rule #6: explicit error handling on `parse_encoding_chain` and decoder construction; no panic path.
- Iron Rule #7: minimize allocations — `resolve_scanner` returns `Arc<CompiledScanner>` (no clone of inner), tail buffer lives in `BodyScanState::tail` (`BytesMut`).

## Next Steps
- Phase 05: comprehensive test coverage and docs updates.
