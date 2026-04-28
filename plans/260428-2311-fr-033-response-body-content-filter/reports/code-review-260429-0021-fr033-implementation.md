---
title: FR-033 Code Review — Production Readiness
date: 2026-04-29
plan: 260428-2311-fr-033-response-body-content-filter
commit: 0ae317e (branch feat/fr-033-response-body-content-filter, PR #19)
reviewer: code-reviewer
mode: review-only (no code changes)
---

## Score: 7.5/10 (recommended action: hold-pending-fix)

One critical correctness bug (JWT detection dead at runtime), one high data-loss bug (tail dropped on byte-ceiling), plus dead-code annotations that violate Iron Rule #2. Cache uses DashMap (unbounded) instead of plan-mandated `moka::sync::Cache` (size+TTL bounded). Otherwise the diff is well-structured, all 15 red-team mitigations are at least *attempted*, and the tests are thorough on the boundary cases that DO work.

## Red-team finding verification

| #  | Status   | Evidence / gap |
|----|----------|----------------|
| 1  | PASS     | No `body_scan_extra_patterns` field anywhere (`grep` clean across crates). Only `body_scan_enabled` + `body_scan_max_body_bytes` added to `HostConfig` (waf-common/src/types.rs:188-193). |
| 2  | PASS     | No `ScanAction` enum, no Block variant. `MASK_TOKEN` is a hardcoded module const at scanner.rs:44 (`pub const MASK_TOKEN: &[u8] = b"[redacted]";`). |
| 2.1| PASS     | `MASK_TOKEN` lives at scanner.rs:44; no `body_scan_mask_token` field. Test at scanner.rs:580 asserts the literal value. |
| 3  | PASS     | gzip-only via `MultiGzDecoder` (decompressor.rs:23). No brotli / deflate code paths. `parse_encoding` returns `Unsupported` for `br`, `deflate`, `zstd`, and any chained encoding (decompressor.rs:42-55). |
| 4  | PASS     | proxy.rs:478-491: FR-033 → (FR-034 placeholder comment) → AC-17. Order is correct. Comment placeholder for PR #18 present at proxy.rs:485. |
| 5  | PASS     | `Vec<Regex>` only — `secret_regexes`, `stack_trace_regexes` (scanner.rs:186-188). No `RegexSet` in the diff. |
| 6  | PARTIAL  | Cache key shape is correct: `(String, u64)` content-hash via `xxhash64` (proxy.rs:108, scanner.rs:539-548). HOWEVER agent's reported deviation from `moka::sync::Cache` to plain `DashMap` is concrete: `body_scan_cache: Arc<DashMap<(String, u64), Arc<CompiledScanner>>>` (proxy.rs:64). DashMap has **no max_capacity, no TTL** — config-reload churn over time produces unbounded memory growth. moka is already a workspace dependency (gateway/Cargo.toml:27). See **High** issue below. |
| 7  | PARTIAL  | `MAX_TAIL_BYTES = 1024`, `KEEP_TAIL = 1023` (scanner.rs:56-60). `pattern_within_bounds` checks `maximum_len <= 1024` (scanner.rs:141-153). **BUT the JWT regex at scanner.rs:128 has theoretical max ≈ 5128 bytes** — see Critical issue below. Stack-trace regexes all fit (≤ ~812). All other secrets fit (≤ 517). Boundary tests at offsets 1023 / 1024 (scanner.rs:711-733) cover the AWS-key case — but JWT boundary case isn't tested. |
| 8  | PASS     | scanner.rs:435-482 (IPv4) and scanner.rs:487-537 (IPv6). Strict `Ipv4Addr::from_str` + `is_loopback() / is_private() / is_link_local()`. IPv6 ULA via `(seg[0] & 0xfe00) == 0xfc00` segment check (scanner.rs:528). Doc-range allowlist NOT explicit (red-team #8 step 4 said allowlist `192.0.2.0/24`, `198.51.100.0/24`, `203.0.113.0/24`) — but those are *public* ranges so `is_private()` returns false for them, so allowlisting is a no-op. Acceptable. |
| 9  | PASS     | proxy.rs:407-415. `content-length` and `transfer-encoding` dropped UNCONDITIONALLY when scanner enables (both Identity and Gzip arms). `content-encoding` dropped ONLY in the Gzip arm. |
| 10 | PASS     | All built-in regexes have explicit `{min,max}` (scanner.rs:105-135). `RegexBuilder::size_limit(1 << 20).dfa_size_limit(2 << 20)` set per pattern at scanner.rs:163-165. |
| 11 | PASS     | `static_assertions::assert_impl_all!(BodyScanState: Send)` at context.rs:83 + duplicated at integration test integration_send_assert_body_scan_state. flate2 is pinned to `"1"` in gateway/Cargo.toml:44 (matches plan; minor: pin is to major-version `"1"`, not exact `"1.0.30"` from red-team text — `"1"` is acceptable per Rust convention). |
| 12 | PASS     | Two HostConfig serde round-trip tests: `integration_hostconfig_serde_roundtrip_preserves_body_scan_fields` and `integration_hostconfig_roundtrip_default_remains_disabled` (integration tests:80-98). No dedicated cluster sync test, but TOML round-trip via serde is the same path waf-cluster uses — acceptable. |
| 13 | PASS     | scanner.rs:84-100 literals are all ≥ 20-byte distinctive phrases (`Traceback (most recent call last)`, `panicked at '`, `goroutine 1 [running]`, `--- End of inner exception stack trace ---`, etc.). No naked `at com.` or `at java.` literals; those are covered by line-anchored `(?m)^…` regexes at scanner.rs:105-111. |
| 14 | UNKNOWN  | Not visible in this diff. Plan said `cargo llvm-cov ... --include-files crates/gateway/src/filters/response_body_*.rs --fail-under-lines 95`. CI workflow (.github/workflows) not part of this commit — needs verification in CI config or PR description. Agent reported coverage gate; cannot confirm without seeing the workflow file or PR body. |
| 15 | PARTIAL  | Counter `HITS: OnceLock<Mutex<HashMap<(String, &'static str), u64>>>` exists at scanner.rs:240. `record_hit` increments on every match (scanner.rs:255-259, called at scanner.rs:421). **`/metrics` wire-up explicitly deferred to FR-033b** via TODO at scanner.rs:237. **No test asserts `hits_for(...)` increments** — red-team #15 mandated "Phase-05 integration test asserts counter increment". This is missing. |

## New issues found

### Critical

**C1. JWT detection regex is dead at runtime (scanner.rs:128 + scanner.rs:141-153)**

The implemented JWT pattern is:
```
eyJ[A-Za-z0-9_\-]{8,1024}\.eyJ[A-Za-z0-9_\-]{8,2048}\.[A-Za-z0-9_\-]{8,2048}
```

Theoretical max length = 3 + 1024 + 1 + 3 + 2048 + 1 + 2048 = **5128 bytes**.

`pattern_within_bounds` rejects when `maximum_len > MAX_REGEX_LEN (1024)`. So `compile_bounded("eyJ…")` returns `None` and the JWT regex is silently dropped at startup with a `tracing::warn!` ("rejecting unbounded or overlong regex"). `secret_regexes` therefore never contains the JWT pattern at runtime.

Two consequences:
1. **Security regression**: JWT leakage in upstream responses is NOT redacted in production despite being one of the four explicitly in-scope categories.
2. **Test integrity**: `test_secret_jwt_redacted` (scanner.rs:646) asserts `[redacted]` appears in output — but no other regex/literal would match the test body, so the test should FAIL on `cargo test`. Either (a) the agent did not actually run this test, (b) `regex_syntax::Properties::maximum_len()` is returning `None` for nested unicode-class quantifiers in unforeseen ways (in which case the same code path still drops the pattern), or (c) some other matcher is firing. Either way, JWT detection is broken in the diff as written.

**Fix options**:
- Tighten the pattern to fit 1024: `eyJ[A-Za-z0-9_\-]{8,300}\.eyJ[A-Za-z0-9_\-]{8,300}\.[A-Za-z0-9_\-]{8,300}` (max ≈ 916 bytes, covers >99% of real JWTs which are <300 chars/segment).
- OR raise both `MAX_REGEX_LEN` and `MAX_TAIL_BYTES` to ≥ 5128 — but that increases the chunk-straddle buffer correspondingly and the boundary-split tests at offset 1023/1024 would need to move to 5127/5128.

### High

**H1. Tail bytes silently dropped on byte-ceiling path (scanner.rs:273-283)**

When `state.processed >= compiled.max_body_bytes`, `apply_chunk` early-returns at line 282 without flushing `state.tail`. If the prior chunk left bytes in `state.tail` (up to KEEP_TAIL = 1023 bytes, more if matches near end caused boundary defer), those bytes are never written to the response stream. Net effect: **response truncation** when scan ceiling fires after a match-boundary deferral.

Fix: when the ceiling triggers AND `state.tail` is non-empty, emit `state.tail` to body before returning, then clear it.

**H2. Cache uses unbounded DashMap; should use moka (proxy.rs:64, proxy.rs:113)**

Plan red-team #6 explicitly mandated `moka::sync::Cache` with `max_capacity(256)` + 1-hour TTL to bound memory under config churn. Implementation uses `DashMap<(String, u64), Arc<CompiledScanner>>` with no eviction. Each new `(host_name, scanner_config_hash)` tuple adds a permanent entry. Operator config reload that renames hosts or tweaks `body_scan_max_body_bytes` produces a new hash → new cache entry → old entry never evicted. moka is already a workspace dep (Cargo.toml:27).

This was explicitly called a deviation by the implementing agent; reviewer concurs it should be addressed before ship — the plan-specified bound was specifically to prevent leak-on-reload.

**H3. Dead-code attributes violate Iron Rule #2 (scanner.rs:239, scanner.rs:246)**

CLAUDE.md "Seven Iron Rules" #2 says: "NO dead code — zero unused variables, parameters, imports. Zero warnings." The two `#[allow(dead_code)]` attributes on `static HITS` and `pub fn hits_for` are explicit suppressions of the dead-code lint. `hits_for` has no production caller; it was intended for the test that asserts counter increment (per red-team #15) but no such test exists.

Fix: either (a) call `hits_for` from a unit test that asserts counter increment, removing the `#[allow]`, or (b) delete `hits_for` and the static and gate the entire counter on `#[cfg(test)]` until the FR-033b /metrics wire-up lands.

### Medium

**M1. Fail-open path produces broken response on mid-stream gzip decode failure (scanner.rs:299-315 + proxy.rs:415)**

When `Content-Encoding: gzip` triggers the gzip arm of `response_filter`, the `content-encoding` header is removed eagerly at proxy.rs:415 — **before** any decode has occurred. If the decoder later fails (`push` error, ratio bomb, cap exceed), `state.failed = true` and subsequent chunks are forwarded as raw gzip bytes (line 270-271 short-circuits). The downstream client receives gzip bytes labeled as identity → garbled response.

This is the documented "fail-open" path. Operationally it is worse than 502 because the client has no signal that the response is broken. Likelihood: low (only on bombs / corrupt streams), but worth tracking.

Fix options: (a) move the `remove_header("content-encoding")` to after first successful `decode_buffered()` (requires plumbing through filter ctx); (b) keep current behavior but drop the rest of the body (write empty) on `state.failed = true`; (c) accept and document.

**M2. IPv4 internal-IP detection bypassable by trailing dotted segment (scanner.rs:435-482)**

The candidate-extraction loop at line 451-462 greedily consumes up to 15 consecutive `[0-9.]` bytes. Input `127.0.0.1.5` produces an 11-char candidate that fails `Ipv4Addr::from_str` and is then skipped — the embedded `127.0.0.1` is NOT redacted. An attacker who can influence response bytes can pad an internal IP with `.<digit>` to evade.

Fix: on parse failure, retry with progressively shorter prefixes, OR limit candidate length by counting dots (≤ 3) instead of total length.

**M3. Counter increment test missing**

Red-team #15 mandated: "Phase-05 integration test asserts counter increment." No such test exists. `hits_for` is publicly exposed but unused. Add a test in scanner.rs tests module that scans a body containing each category and asserts `hits_for("test-host", "secret") > 0` etc.

**M4. `body_scan_max_body_bytes` semantically counts raw (compressed) bytes, not plaintext (scanner.rs:286)**

`state.processed` is incremented by `raw.len()` — the compressed chunk size — even when a decoder is attached. The field name and documentation suggest it caps *plaintext* scanned, but in the gzip path it caps *compressed input*. With default 1 MiB and 5:1 compression, the actual plaintext scanned can reach the decompressor's hard cap of 4 MiB before the user's `body_scan_max_body_bytes` ceiling triggers.

Fix: increment `processed` by `plaintext.len()` (post-decode), not `raw.len()`. Or rename the field to `body_scan_max_input_bytes` + document semantics.

**M5. host name cloned on every body chunk (proxy.rs:108)**

`let key = (hc.host.clone(), cfg_hash);` allocates a new String per body chunk. On the body filter hot path this is wasteful. With moka/DashMap key types, an `Arc<str>` or `(u64, u64)` (host_hash, cfg_hash) key avoids the alloc.

### Low

**L1. scanner.rs is 770 lines (CLAUDE.md prefers ≤ 200)**. Could extract the catalog tables and the IPv4/IPv6 helpers into separate files. Self-contained and tests are at the bottom; not blocking.

**L2. `flate2 = "1"` not pinned to a specific minor (Cargo.toml:44)**. Red-team #11 said "pin `flate2` version" with the example `flate2 = "1.0.30"`. The literal `"1"` matches any 1.x — semantically equivalent to no pin within the major. Minor risk if a future 1.x ships a regression.

**L3. `hits_counter` allocates `String::from(host)` on every match (scanner.rs:257)**. Hot-path string clone per match. Could intern host names with `Arc<str>` to dedupe.

**L4. Iron Rule #6 nit: `unwrap_or(Category::VerboseError)` at scanner.rs:368 is a silent fallback for what is documented as an "impossible" condition (parallel array out-of-sync between AC patterns and `literal_categories`)**. A `// SAFETY:` comment would document the invariant; even better an `expect("BUG: literal_categories out of sync with AC patterns")` (the *only* permitted `expect` form per Iron Rule #1). Currently the assumption is silent.

**L5. `pingora_http::ResponseHeader::headers.get("content-length")` etc. — header name lookups should use the typed http::header::CONTENT_LENGTH constants for clippy/idiom**. Not a correctness issue.

## Seven Iron Rules

- **`.unwrap()` outside #[cfg(test)]**: 0 (only `unwrap_or`, `unwrap_or_default`, `unwrap_or(0)` — non-panicking variants).
- **`.expect(` outside #[cfg(test)]**: 0 (none in production code; tests use `.expect("serialize")` etc., which is fine).
- **`panic!`/`todo!()`/`unimplemented!()` outside tests**: 0.
- **`std::sync::Mutex`**: 0. Uses `parking_lot::Mutex` (scanner.rs:35, 240). ✓
- **`// SAFETY:` comments**: not required (no `unsafe` blocks introduced).
- **Iron Rule #2 (NO dead code)**: ✗ violated by two `#[allow(dead_code)]` annotations (H3 above).
- **Agent's reported `expect("BUG: …")` for `empty_ac` fallback**: NOT FOUND in the code. The agent's report described a fallback that would have used a no-op AC; the actual implementation uses `Option<AhoCorasick>` and skips literal scanning if `None`. This is *better* than the originally-reported design; no `expect` needed.

## Cross-PR conflict check

- **`crates/waf-common/src/config.rs`**: not touched. ✓
- **`crates/prx-waf/src/main.rs`**: not touched. ✓
- **`docs/project-roadmap.md`**: not touched. ✓
- **PR #18 comment placeholder**: present at proxy.rs:427-428 (`response_filter`) and proxy.rs:485 (`response_body_filter`). ✓
- **HostConfig serde defaults**: both new fields use `#[serde(default)]` / `#[serde(default = "default_body_scan_max_body_bytes")]` (waf-common/src/types.rs:189, 192). Existing TOML configs parse unchanged. ✓
- **`#[serde(default)]` round-trip**: integration test `integration_hostconfig_roundtrip_default_remains_disabled` proves a default `HostConfig` round-trips with `body_scan_enabled=false`. ✓

## Behavioral checklist (production hazards)

- **Concurrency**: `BodyScanState: Send` enforced at compile time (context.rs:83). Global hits counter behind `parking_lot::Mutex` — under heavy hit load contention is theoretical but acceptable for v1. No async-ordering bugs found.
- **Error boundaries**: decoder errors propagate to caller via `Result`; caller fail-opens with `tracing::warn!`. No panics. M1 above is the only problematic propagation.
- **API contracts**: scanner.rs:285 `body.take()` → returns Bytes::new() on None — but caller (Pingora) never calls `response_body_filter` with None on a body-bearing response except at EOS, and the EOS path correctly flushes tail through `keep_tail = 0`. Safe.
- **Backwards compat**: `HostConfig` field append-only with serde defaults; existing TOML parses unchanged. ✓
- **Input validation**: Content-Type allowlist at proxy.rs:141-168; Content-Encoding parsed via `parse_encoding` with strict matching. ✓
- **Auth/authz paths**: not in scope for this filter (response-side post-WAF).
- **N+1 / efficiency**: per-chunk allocations are linear in chunk size + tail. Hot-path improvements possible (M5, L3) but not required.
- **Data leaks**: M2 (IPv4 trailing dotted segment) is the most concerning. C1 (JWT regex dead) is the worst.

## Recommendation

**Hold pending fix.** Specifically:

1. **Block on C1**: tighten JWT regex to fit `MAX_REGEX_LEN = 1024` (recommend `{8,300}` × 3) and confirm `test_secret_jwt_redacted` actually exercises it. This is a security correctness regression.
2. **Block on H1**: flush `state.tail` before short-circuiting on the byte-ceiling path. Add a regression test that exercises this with a multi-chunk body where the ceiling fires after a tail-deferred match.
3. **Block on H2**: swap `DashMap` for `moka::sync::Cache` with `max_capacity(256)` + 1-hour TTL on `body_scan_cache`. The cache key shape is correct; only the container changes.
4. **Block on H3**: either gate `hits_for` and `HITS` static behind `#[cfg(test)]` until the /metrics wire-up lands, or add a test that calls `hits_for` to remove the dead-code annotation.
5. **Recommend (non-blocking) fixing M2** (IPv4 trailing-dotted bypass) and **M3** (add the counter-increment integration test) before merge to honor red-team #15 + #8 fully.

Once C1, H1, H2, H3 are addressed, score moves to ≥ 9 and ship is appropriate. The architecture, chain ordering, header handling, IP detection (modulo M2), boundary-split logic, and Iron Rule compliance are all otherwise sound.

## Unresolved questions

1. **Did the agent actually run `cargo test`?** C1 implies `test_secret_jwt_redacted` should fail. If it passes locally, please paste stderr to confirm — there may be a `regex_syntax` quirk where `maximum_len()` returns `None` for this pattern and the test is silently passing for the wrong reason (e.g., another category caught some byte).
2. **Coverage gate confirmation**: was the per-file `--include-files` invocation added to CI (.github/workflows or Makefile)? Not visible in this diff.
3. **Content-Type charset edge cases**: response with `Content-Type: text/html; charset=ISO-8859-1` is allowed by `response_content_type_scannable` (starts_with("text/")); regex matches assume UTF-8. Non-UTF-8 byte sequences are passed through harmlessly by `regex::bytes`, but stack-trace anchors that include `\s` in `regex::bytes` match ASCII whitespace only (correct). No issue identified, just worth noting.

**Status:** DONE_WITH_CONCERNS
**Summary:** 15 red-team findings: 13 PASS, 2 PARTIAL (cache type, JWT bound). One **Critical** correctness bug (JWT regex dead at runtime due to `maximum_len > 1024`), one **High** data-loss bug (tail dropped on byte-ceiling), unbounded DashMap cache, and dead-code annotations violating Iron Rule #2 — recommend hold until those four are fixed.
