# Phase 03 — Streaming Scanner (single redact action)

> **RED-TEAM PATCH (mandatory):**
> - **#2** Drop `ScanAction` enum + `Block` mode + `state.blocked` + neutral-page integration. Single mode: replace match span with const `MASK_TOKEN = b"[redacted]"`. Whole-body block remains FR-005 territory.
> - **#5** Replace `RegexSet` with `Vec<Regex>` for span-aware replacement. `RegexSet::matches` returns indices only — no offsets. Iterate `.find_iter()` per `Regex`.
> - **#7** `keep_tail = MAX_TAIL_BYTES - 1 = 1023`. At catalog compile time, reject any pattern whose `regex_syntax::hir::Hir::properties().maximum_len()` exceeds 1024.
> - **#8** Internal-IP detection: byte-scan candidate substrings `\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b` → strict-parse via `std::net::Ipv4Addr::from_str` (rejects octal/leading-zero) → check `is_loopback() || is_private() || is_link_local()`. Add IPv6 ULA via `Ipv6Addr` parse + segment check `(addr.segments()[0] & 0xfe00) == 0xfc00`.
> - **#10** Every built-in regex MUST have explicit `{min,max}` (no naked `{N,}`). Compile via `RegexBuilder::new(p).size_limit(1 << 20).dfa_size_limit(2 << 20).build()`.
> - **#13** Stack-trace literals (Aho-Corasick): only distinctive ≥20-byte phrases (`Traceback (most recent call last)`, `panicked at '`, `goroutine 1 [running]`, `Fatal error: Uncaught`, `--- End of inner exception stack trace ---`). Line-anchored stack traces use `Vec<Regex>` with `(?m)^` anchors per language (see adjudication §13).
> - **#15** Counter `body_scan_hits_total{host,category}` increment inline; expose via existing `/metrics` (`waf-api`).
> - **(rejected #1 mostly)** Operator extras dropped — no `body_scan_extra_patterns` compile path. Catalog only.
> - Reference: [`reports/red-team-260428-2332-fr033-adjudication.md`](reports/red-team-260428-2332-fr033-adjudication.md).

## Context Links
- Research: `research/researcher-01-fr033-best-practices-and-attacks.md` §1 (ReDoS hardening), §2 (catalogs), §3 (incidents), §5 (perf budget), §6.4 (mask vs block)
- AC-17 mirror: `crates/gateway/src/filters/response_body_mask_filter.rs` (`apply_chunk`, `scan_and_replace`, tail-buffer logic)
- Error page: `crates/gateway/src/error_page/` (reuse `ErrorPageFactory::render` for Block action neutral 502)
- Decompressor: phase-02 `DecoderChain`

## Overview
- **Priority:** P0
- **Status:** completed 2026-04-28
- Build the chunk-aware scanner that runs detector catalogs over plaintext (post-decompression) bytes and applies operator-chosen action (`Mask` or `Block`). ReDoS-safe by construction: literals via Aho-Corasick, anchored regex via `Vec<Regex>`, IP detection via direct byte parse (no regex).

### Deviations
- Single action: redact only (no Block mode per red-team #2 scope cut).
- Uses `Vec<Regex>` instead of `RegexSet` for span-aware replacement (red-team #5).
- Catalog sources: hardcoded statics in scanner module; no separate `catalogs.rs` file.

## Key Insights
- Cloudflare 2019 (research §1, §6.2): ReDoS via combined alternation. We avoid by using `aho_corasick` for literal multipattern (stack-trace anchors, fixed prefixes) — linear time, no backtracking.
- For format-anchored secrets (`AKIA[A-Z0-9]{16}`, `ghp_[A-Za-z0-9_]{36,255}`): use `regex::bytes::RegexSet` (lazy DFA, linear bounds). Each pattern compiled and validated individually (mirror AC-17 line 44–53). Invalid → drop + warn.
- Internal IPs: `regex::bytes::Regex` for `\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b` plus a post-match RFC-1918/loopback/link-local CIDR check via byte parse — keeps regex tiny and avoids the giant alternation in research §2 IP table.
- Chunk-boundary straddle: AC-17's `keep_tail` algo is correct and reusable. Cap at `MAX_TAIL_BYTES = 1024` (mirror AC-17 line 22). Stack-trace anchors (`Traceback (most recent call last)` is 33 bytes, longest) all fit.
- Action `Block` semantics: on first hit, set `state.blocked = true`, replace remaining body with neutral 502 page once, drop subsequent chunks. We can NOT change response status code mid-body in Pingora (headers already sent in `response_filter`); instead we emit a body-only neutral page. Document this trade-off clearly.

  **Refinement:** because status is locked at `response_filter` time but we don't know hit-vs-miss until `response_body_filter` time, "block" in FR-033 means **body replacement**, not status change. The downstream sees `200 OK` (or whatever upstream sent) with body `[Content blocked by WAF]` neutral page. To get a true 502, operator must use FR-005 request-time block at request layer. Phase-05 docs section makes this explicit.

- Mask action: identical to AC-17's `scan_and_replace`, parameterized over a different matcher.

## Requirements
**Functional**
- Scanner consumes `&[u8]` (post-decompression bytes from phase-02), returns mutated `Vec<u8>` + boundary tail.
- Detect across 4 categories per `BodyScanCategories` (each opt-in).
- Action `Mask`: replace match span with `body_scan_mask_token`.
- Action `Block`: on first hit, replace whole remaining body with neutral page; subsequent chunks dropped.
- Per-request hit counter exposed for metrics (phase-05 logs counts; metrics integration deferred).
- Hard cap `body_scan_max_body_bytes` — beyond ceiling, forward unchanged + warn-once.

**Non-functional**
- NO `.unwrap()` outside `#[cfg(test)]`.
- NO panic on malformed UTF-8 (operate on bytes, not str).
- All catalogs compiled lazily via `OnceLock` — first request pays cost, subsequent free.
- ReDoS budget: every regex must be anchored OR limited via `Regex::new` size limit (default 10 MB DFA cap acceptable per research §1).

## Architecture
```
gateway::filters::response_body_content_scanner (NEW, ~400 lines, split if grows)
   ├── struct CompiledScanner {
   │       categories: BodyScanCategories,
   │       literal_ac: Option<AhoCorasick>,           // stack traces + verbose error literals
   │       anchored_regex_set: Option<RegexSet>,      // secret patterns
   │       ip_regex: Option<Regex>,                   // single dotted-quad shape
   │       extra_regex: Option<Regex>,                // operator extras (AC-17 style)
   │       mask: Bytes,
   │       action: ScanAction,
   │       max_body_bytes: u64,
   │       max_decompress_bytes: u64,
   │       max_decompress_ratio: u32,
   │       keep_tail: usize,
   │   }
   │     impl build(hc: &HostConfig) -> Self
   │     impl is_noop(&self) -> bool
   │
   ├── fn apply_body_scan_chunk(
   │       state: &mut BodyScanState,
   │       compiled: &Arc<CompiledScanner>,
   │       body: &mut Option<Bytes>,
   │       eos: bool,
   │   )
   │
   └── mod catalogs {
           pub static STACK_TRACE_LITERALS: &[&str] = &[ ... ];
           pub static VERBOSE_ERROR_LITERALS: &[&str] = &[ ... ];
           pub static SECRET_REGEXES: &[&str] = &[ ... ];   // anchored
           pub static IP_REGEX: &str = r"\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b";
       }

context.rs:
   └── + pub struct BodyScanState {
           pub enabled: bool,
           pub decoder: Option<DecoderChain>,
           pub processed: u64,
           pub hits: u32,
           pub blocked: bool,
           pub failed: bool,
           pub ceiling_logged: bool,
           pub tail: BytesMut,
       }
```

### Pseudocode for `apply_body_scan_chunk`
```
if !state.enabled || state.blocked { return; }
if state.processed >= compiled.max_body_bytes {
    log warn-once; return; (forward unchanged)
}

let raw = body.take().unwrap_or_default();
state.processed += raw.len() as u64;

let plaintext: Vec<u8> = match &mut state.decoder {
    Some(chain) => match chain.push(&raw) {
        Ok(v) => v,
        Err(e) => { warn!; state.failed = true; *body = Some(raw); return; }
    },
    None => raw.to_vec(), // identity path
};

if eos {
    if let Some(chain) = state.decoder.as_mut() {
        match chain.finish() { ... }
    }
}

// Concat tail + plaintext; scan_and_replace; emit out + new tail
let (out, new_tail, hits) = scan_and_replace_multi(compiled, &state.tail, &plaintext, eos);
state.hits += hits;
state.tail = new_tail;

if hits > 0 && compiled.action == ScanAction::Block {
    state.blocked = true;
    *body = Some(neutral_block_page_bytes());
    return;
}

*body = if out.is_empty() { None } else { Some(Bytes::from(out)) };
```

### Catalog seeds (subset — full list in implementation)
**Stack-trace literals** (research §2 stack table — pull anchors only, NOT regexes):
- `Traceback (most recent call last)`, `panicked at`, `goroutine `, `Fatal error:`, `Call Stack:`, `at System.`, `at org.springframework`, `at java.`, `at com.`, `\nthread '` (only literals → AhoCorasick handles them)

**Verbose-error literals:**
- `You have an error in your SQL syntax`, `ORA-`, `PG::SyntaxError`, `Hibernate:`, `SQLAlchemy`, `Doctrine`, `undefined method`, `at System.Web.`, `Express ` (with version probe deferred)

**Secret anchored regex (RegexSet):**
- `(?:A3T|AKIA|ASIA|ABIA|ACCA)[A-Z0-9]{16}`
- `xox[bpe]-[0-9A-Za-z-]{20,}`
- `gh[pousr]_[A-Za-z0-9_]{36,255}`
- `sk_(?:live|test)_[0-9a-zA-Z]{24,}`
- `eyJ[A-Za-z0-9_-]{8,}\.eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}` (JWT — note research §2 medium FP risk; gated behind `secrets` category)
- `-----BEGIN (?:RSA|DSA|EC|OPENSSH|ENCRYPTED|PRIVATE) (?:PRIVATE )?KEY-----`
- `aws_secret_access_key\s*[=:]\s*[A-Za-z0-9/+=]{40}`

**IP regex + post-match check:**
- Match dotted quad; parse 4 octets via `str::parse::<u8>()`; classify against RFC-1918 / 169.254.x / 127.x. Skip exact `127.0.0.1` (research §6.7 default allowlist).

## Related Code Files
**Create**
- `/Users/admin/lab/mini-waf/crates/gateway/src/filters/response_body_content_scanner.rs` (~400 lines — split into `scanner.rs` + `catalogs.rs` if exceeds 200 per development-rules.md "modularization")

**Modify**
- `/Users/admin/lab/mini-waf/crates/gateway/src/context.rs` — append `BodyScanState` struct after `BodyMaskState` (and after PR 18's `BodyRedactState` once merged); append `body_scan: BodyScanState` field to `GatewayCtx`
- `/Users/admin/lab/mini-waf/crates/gateway/src/filters/mod.rs` — `pub mod response_body_content_scanner;` + re-export `CompiledScanner`, `apply_chunk as apply_body_scan_chunk`
- `/Users/admin/lab/mini-waf/crates/gateway/Cargo.toml` — add `aho-corasick = "1"` (likely already in workspace via pingora deps)

## Implementation Steps
1. Add `BodyScanState` to `context.rs` and embed in `GatewayCtx`. Preserve AC-17 `body_mask` field.
2. Create `catalogs.rs` (or inline if file < 200 lines) with `OnceLock<AhoCorasick>` / `OnceLock<RegexSet>` initializers. Each pattern validated individually (`Regex::new` per item) before being added to the set.
3. Implement `CompiledScanner::build(hc: &HostConfig) -> Self`:
   - Read `hc.body_scan_categories` and assemble enabled-only literal slice / regex slice.
   - Compile `AhoCorasick::new(literals)` (configure `MatchKind::LeftmostFirst`).
   - Compile `RegexSet::new(secret_regexes)` once; on individual failure, drop + warn.
   - Compile single dotted-quad `Regex` if `internal_ips` enabled.
   - Compile `body_scan_extra_patterns` into a single combined `Regex` (mirror AC-17 line 60).
   - Compute `keep_tail = max(longest_literal, longest_anchored_regex_min_len) - 1`, clamped at `MAX_TAIL_BYTES = 1024`.
4. Implement `apply_body_scan_chunk` per pseudocode above. Mirror AC-17's `apply_chunk` for tail-buffer mechanics.
5. Implement `scan_and_replace_multi`:
   - Walk `AhoCorasick::find_iter` and `RegexSet::matches` then individual regex `find_iter` for span info; sort matches by start offset; resolve overlaps by leftmost-first.
   - For Mask action: copy non-match bytes; emit `mask` for each match span.
   - Track straddle boundary identical to AC-17.
   - Return `(out, new_tail, hit_count)`.
6. Implement `ip_post_match` helper — parses 4 u8s, returns `bool` for "should-mask". Excludes `127.0.0.1`.
7. Implement neutral block page helper — call `ErrorPageFactory::render(502, ...)` from `error_page/` and return `Bytes`. Document explicitly: status code stays as upstream sent (already on the wire); we replace body only.
8. NO `.unwrap()`. Use `if let Some(...)` / `?` / `unwrap_or_default()` everywhere.
9. Inline tests deferred to phase-05 (kept tight here for review focus).

## Todo List
- [x] Append `BodyScanState` to `context.rs`; embed `body_scan` in `GatewayCtx`
- [x] Add `aho-corasick` to `gateway/Cargo.toml`
- [x] Create scanner module (`response_body_content_scanner.rs`); inline catalogs
- [x] Implement `catalogs` (literals + regex strings + IP regex)
- [x] Implement `CompiledScanner::build` (per-category opt-in compile, fail-open on bad regex)
- [x] Implement `apply_body_scan_chunk` (decompress → scan → redact, fail-open on decoder error)
- [x] Implement `scan_and_replace_multi` (multi-matcher merge, leftmost-first, straddle-safe)
- [x] Implement `ip_post_match` byte parser (no regex CIDR alternation)
- [~] Implement neutral block page — deferred per red-team #2 (single redact action only)
- [x] Re-export from `filters/mod.rs`
- [x] `cargo clippy -p gateway -- -D warnings` green

## Success Criteria
- File compiles, no warnings, no `.unwrap()` outside `#[cfg(test)]`.
- `is_noop()` returns true when scan disabled OR all categories off.
- `apply_body_scan_chunk` short-circuits cleanly when `state.enabled = false` (zero-cost passthrough).
- `state.blocked = true` after first hit on Block action; subsequent chunks emit empty `body` (already replaced + drained).

## Risk Assessment
- **Block action body-only replacement vs status code semantics** (Likelihood: High doc-only, Impact: Medium UX): operators may expect a 502. Mitigation: doc explicit; PR description calls this out as a known limitation; future ticket can hold body until first chunk to lock status (significant refactor — defer).
- **Multi-matcher overlap resolution** (Likelihood: Medium, Impact: Low): leftmost-first semantics tested in phase-05.
- **AC + RegexSet hit-count double-counting** (Likelihood: Low, Impact: Low): merge-sort-by-start dedups overlapping spans.

## Security Considerations
- ReDoS: every regex anchored or short; `RegexSet` non-backtracking. Cite Cloudflare 2019.
- Pattern provenance documented in module rustdoc: TruffleHog / Gitleaks / OWASP CRS — see research §2 sources.
- Iron Rule #6: external (upstream) bytes treated as untrusted; never log raw matched content (log category + offset only).
- Iron Rule #1: zero `.unwrap()`; bad regex → drop + warn.
- Iron Rule #4: business logic verified via `cargo check`; integration test fixtures in phase-05.

## Next Steps
- Phase 04: wire scanner into Pingora `response_filter` / `response_body_filter` callbacks; lazy-compile cache.
