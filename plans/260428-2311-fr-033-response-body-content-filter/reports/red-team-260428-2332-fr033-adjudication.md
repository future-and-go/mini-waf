---
title: FR-033 Red Team Adjudication
date: 2026-04-28
plan: 260428-2311-fr-033-response-body-content-filter
reviewers: [security-adversary, failure-mode-analyst, assumption-destroyer, scope-complexity-critic]
total_findings: 40
deduped: 15
accepted: 15
rejected: 0
---

# FR-033 Red Team Review — Adjudication

## Severity tally
- Critical: 6  | High: 6  | Medium: 3
- All 15 accepted (some merged + cross-cutting; rejected zero — every finding had a defensible action item).

## Findings table

| # | Title | Severity | Reviewers | Disposition | Phase touched |
|---|-------|----------|-----------|-------------|---------------|
| 1 | Drop `body_scan_extra_patterns` — duplicates AC-17 `internal_patterns` | Critical | Scope, Sec, Failure, Assumption | Accept | 01, 03 |
| 2 | Drop dual Mask/Block; ship single mask-redact mode | Critical | Scope, Sec, Failure, Assumption | Accept | 01, 03, 04, 05 |
| 3 | MVP cut: gzip-only decompression in v1; defer deflate + brotli | Critical | Scope, Failure | Accept | 02, 03, 05 |
| 4 | Reorder chain: scan (FR-033) BEFORE redact (PR-18) | Critical | Assumption | Accept | 04 |
| 5 | Replace `RegexSet` with `Vec<Regex>` for span-aware replacement | Critical | Assumption | Accept | 03 |
| 6 | Cache key by content-hash, not `Arc::as_ptr` (cross-host bleed risk) | Critical | Sec, Failure, Assumption | Accept | 04 |
| 7 | Fix `keep_tail` to use longest-possible match length, hard-cap pattern max-len at MAX_TAIL_BYTES=1024 | High | Sec, Failure | Accept | 03, 05 |
| 8 | Internal IP detection via `std::net::Ipv4Addr::is_loopback/is_private` after strict octet parse | High | Sec | Accept | 03 |
| 9 | Always drop `Content-Length` when scanner enabled, regardless of decompression | High | Sec, Failure | Accept | 04 |
| 10 | Cap upper bounds on every built-in `{N,}` regex; explicit `dfa_size_limit(2 << 20)` | High | Sec | Accept | 03 |
| 11 | `static_assertions::assert_impl_all!(BodyScanState: Send)`; pin gzip crate version | High | Failure | Accept | 04, 05 |
| 12 | HostConfig serde round-trip + cluster sync compatibility test | High | Failure | Accept | 05 |
| 13 | Replace literal `at com.` / `at java.` with anchored multiline regex `(?m)^\s+at\s+[A-Za-z_][\w$.]*\(` | Medium | Assumption | Accept | 03, 05 |
| 14 | Coverage gate explicit per-file via `--include-files` | Medium | Assumption | Accept | 05, 06 |
| 15 | Ship one counter `body_scan_hits{host,category}` for SRE observability | Medium | Failure | Accept | 03, 04, 05 |

## Detailed findings + mitigations

### 1 — Drop `body_scan_extra_patterns` (Critical, multi-reviewer)
**Flaw:** AC-17 already exposes `HostConfig::internal_patterns: Vec<String>` for operator regex on response bodies. FR-033 mirroring it via `body_scan_extra_patterns` violates DRY and creates two ReDoS surfaces on the same byte stream.

**Action:** Remove `body_scan_extra_patterns` field from `HostConfig`. FR-033 ships only the built-in catalog. Operator extras stay AC-17's concern. Eliminates findings about combined-alternation ReDoS and operator self-pwn.

### 2 — Drop dual Mask/Block; single mode (Critical)
**Flaw:** `Block` cannot truly block mid-body in Pingora (`response_filter` locks status code before body bytes seen). Every reviewer flagged this. Block also (a) lets pre-match chunks through unmodified (partial leak), (b) does not handle HTTP/2 trailers, (c) doubles test surface for theatre.

**Action:** Drop `ScanAction` enum. FR-033 ships ONE mode: replace match span with mask token `[redacted]` (hardcoded — see #2.1). Whole-body block remains FR-005's job (request-time). Rename: not "scan" with action — call it `body_scan_redact`. Update phase-01/03/04/05 to remove Block code paths, neutral-page rendering, `state.blocked` field.

**2.1 Mask token hardcoded constant** — drop `body_scan_mask_token` from `HostConfig`. `const MASK_TOKEN: &[u8] = b"[redacted]";` in module. Avoids operator-supplied mask-token corruption / cross-pollution with AC-17 (Sec F6 + Assumption F3).

### 3 — gzip-only decompression in v1 (Critical)
**Flaw:** Brotli + deflate triple the dependency surface, double the test matrix, and brotli has historical panic risk on adversarial input. Real upstreams overwhelmingly use gzip.

**Action:** Phase-02 supports ONLY gzip via `flate2::read::MultiGzDecoder<bytes::Bytes>`. Drop brotli + deflate. For non-gzip non-identity `Content-Encoding`, scanner is disabled for that response (mirror AC-17's existing behavior — log `tracing::debug!`). Removes brotli panic isolation finding (Failure F10). Defer deflate + brotli to follow-up `FR-033b`.

### 4 — Reorder chain: FR-033 BEFORE PR-18 (Critical)
**Flaw:** PR 18 (FR-034) buffers entire body until EOS or 256 KiB cap, then emits one chunk. FR-033 in the slot AFTER PR-18 sees `None` for every chunk, then a single huge buffer at EOS — every per-chunk streaming claim (decoder push, ratio guard, tail straddle) collapses to single-shot at EOS.

**Action:** Update phase-04 invocation order to: **FR-033 (scan + decompress) → PR-18 (redact JSON fields) → AC-17 (operator mask)**.

Rationale: FR-033 owns decompression; downstream layers operate on plaintext. FR-033 sees real Pingora chunks. PR-18 receives FR-033's redacted-and-decompressed plaintext (JSON parse works correctly only on plaintext). AC-17 sees the final plaintext for operator extras.

Phase-04 must rewrite the architecture diagram, decision matrix, and update CLAUDE.md AC-17 deferred-line rewording.

### 5 — Replace `RegexSet` with `Vec<Regex>` (Critical)
**Flaw:** `regex::bytes::RegexSet::matches` returns only the *indices* of patterns that matched, not match offsets. Span-aware replacement is impossible from `RegexSet` alone.

**Action:** In phase-03, replace `anchored_regex_set: Option<RegexSet>` with `anchored_regexes: Vec<Regex>`. Build phase compiles each pattern individually. Scanner iterates `regexes.iter().for_each(|r| r.find_iter(buf))` collecting `Match` ranges. Sort + dedupe overlapping ranges before replacement. Update `keep_tail` math to use the actual longest pattern's max-length (statically bounded — see #7).

Alternative (rejected): single combined alternation à la AC-17. AC-17 line 60 is the very pattern Cloudflare 2019 broke. Keep separate `Vec<Regex>` to avoid combined-alternation ReDoS surface.

### 6 — Cache key by content-hash (Critical)
**Flaw:** `Arc::as_ptr(hc) as usize` cache key is fragile: when `Arc` is dropped during config reload, allocator can reuse the address for a *different* `HostConfig`, producing a stale cache hit on the wrong host. Memory also leaks across reloads (no eviction).

**Action:** Phase-04 uses `(host_name: String, config_hash: u64)` as cache key. `config_hash` = `xxhash` of the `body_scan_*` fields only (not full `HostConfig`). Eviction: replace on hash mismatch for same host_name. Use `moka::sync::Cache` with `max_capacity(256)` and 1-hour TTL.

Document: AC-17's `body_mask_cache` and PR-18's `body_redact_cache` have the same bug — backport fix to those caches in a follow-up ticket. Do not block FR-033 landing; cite the issue in PR description.

### 7 — Fix `keep_tail` math (High)
**Flaw:** Plan formula `keep_tail = max(longest_literal, longest_anchored_regex_min_len) - 1` uses regex *minimum* match length. Real ReDoS-safe regex have variable max-length (e.g., GitHub PAT `gh[pousr]_[A-Za-z0-9_]{36,255}` has max length 263). Match straddling chunk boundary at offset > keep_tail leaks unmasked bytes.

**Action:** Phase-03:
- Compute `keep_tail = MAX_TAIL_BYTES - 1` where `MAX_TAIL_BYTES = 1024` is hardcoded const.
- Reject any built-in regex whose theoretical max length > 1024 at compile-time (use `regex_syntax::hir::Hir::properties().maximum_len()` to compute statically; cap upper bounds in catalog patterns to fit).
- `gh[pousr]_[A-Za-z0-9_]{36,255}` → already fits (max 263 < 1024); confirm same for AWS/Slack/JWT.
- Add boundary-split tests at offsets `[1, keep_tail-1, keep_tail, keep_tail+1]` for each built-in pattern's full match string in phase-05.

### 8 — Internal IP detection via std::net (High)
**Flaw:** Hardcoded skip on exact string `127.0.0.1` is bypassed by `127.0.0.2`, `127.000.000.001`, `2130706433`, `0x7f000001`. `127/8` is the full RFC-1122 loopback CIDR.

**Action:** Phase-03 internal-IP detection:
1. Find candidate substrings via byte-scan for `\b\d+\.\d+\.\d+\.\d+\b` shape.
2. Strict parse each candidate via `std::net::Ipv4Addr::from_str` — rejects octal / leading-zero / hex / decimal-encoded forms by construction (Rust strict).
3. Apply `addr.is_loopback() || addr.is_private() || addr.is_link_local()` to decide internal.
4. Allowlist: `0.0.0.0`, `255.255.255.255`, well-known doc ranges (`192.0.2.0/24`, `198.51.100.0/24`, `203.0.113.0/24`).
5. IPv6 ULA: separate scan via `Ipv6Addr::from_str`; check `addr.segments()[0] & 0xfe00 == 0xfc00`.

### 9 — Always drop Content-Length (High)
**Flaw:** Decision matrix in phase-04 conditionally drops CL based on whether decompression is involved. If scanner enabled but never matches, we strip CL anyway (forcing chunked) — operationally fine. But the matrix's branching invites the bug where CL survives on a code path where bytes get mutated → request smuggling vector.

**Action:** Phase-04: drop `Content-Length` AND `Transfer-Encoding` headers UNCONDITIONALLY when `body_scan_enabled = true && !is_noop()`. Re-emit `Transfer-Encoding: chunked`. Drop `Content-Encoding` only when decompression actually occurred (decoder ran successfully). Add invariant test "CL absent on every code path post-scanner-enable decision".

### 10 — Cap upper bounds on regex; explicit DFA limits (High)
**Flaw:** Built-in patterns ship with unbounded `{N,}` quantifiers (JWT, Slack, Stripe). Combined with rare DFA cache thrash on adversarial input, gives a CPU-amplification vector.

**Action:** Phase-03:
- Every built-in regex MUST have explicit `{min,max}` (no `{N,}`).
  - JWT: `eyJ[A-Za-z0-9_-]{8,1024}\.eyJ[A-Za-z0-9_-]{8,2048}\.[A-Za-z0-9_-]{8,2048}` (capped at 5KB total).
  - Slack: `xox[baprs]-[0-9A-Za-z-]{20,512}`.
  - Stripe: `sk_(?:live|test)_[0-9a-zA-Z]{24,256}`.
  - All others similar.
- Build via `RegexBuilder::new(pat).size_limit(1 << 20).dfa_size_limit(2 << 20).build()`.
- Phase-05 adds adversarial-input test: 50 KB poisoned `eyJ...` body, assert scan time < 50 ms.

### 11 — Send-Sync assertion + crate pin (High)
**Flaw:** `BodyScanState` embedded in `GatewayCtx` — Pingora `ProxyHttp::CTX: Send + Sync`. `flate2` decoders are Send only because backed by `Vec<u8>`; brotli historically not (mooted by #3). Need compile-time guarantee.

**Action:** Phase-04 adds `static_assertions::assert_impl_all!(crate::context::BodyScanState: Send);` in test module. Phase-05 pins `flate2 = "1.0.30"` (or current stable) in `Cargo.toml` of `crates/gateway` with comment.

### 12 — HostConfig cluster sync round-trip (High)
**Flaw:** New `body_scan_*` fields flow via cluster config sync (`waf-cluster/src/protocol.rs:142` — full TOML payload with version stamp). If protocol schema-validates, unknown fields drop silently → workers diverge.

**Action:** Phase-05 adds:
- Test: `HostConfig::with_body_scan_enabled(true).to_toml()` → parse back → fields preserved.
- Test: send TOML through `waf-cluster::config_sync_serialize/deserialize` round-trip → fields preserved.
- Document: cluster `config_version` schema number unchanged (additive fields with `#[serde(default)]`).

### 13 — Anchored multiline stack-trace regex (Medium)
**Flaw:** Literal AC patterns `at com.`, `at java.`, `at System.` produce high FP on legitimate prose / API references and high FN on traces using other prefixes (e.g., `at javax.servlet.`).

**Action:** Phase-03 catalog:
- Stack-trace literals (Aho-Corasick): only **distinctive multi-word phrases** ≥ 20 bytes: `Traceback (most recent call last)`, `panicked at '`, `goroutine 1 [running]`, `Fatal error: Uncaught`, `System.NullReferenceException`, `--- End of inner exception stack trace ---`.
- Stack-trace regex (Vec<Regex>) for line-anchored patterns:
  - Java/Kotlin/Scala: `(?m)^\s+at\s+[A-Za-z_][\w$.]+\([^)]*\)`
  - Python: `(?m)^  File "[^"]+", line \d+, in `
  - Rust: `(?m)^thread '[^']+' panicked at`
  - Node: `(?m)^\s+at\s+[\w$<>.]+\s+\(.+:\d+:\d+\)$`
- Update phase-05 FP/FN tests with corpus from research §2 citations.

### 14 — Per-file coverage gate (Medium)
**Flaw:** Plan says "≥ 95% line coverage on new files" but `gateway/CLAUDE.md` documents a global gate via `--ignore-filename-regex`. Ambiguity blocks merge.

**Action:** Phase-05 + phase-06 coverage command becomes:
```bash
cargo llvm-cov -p gateway \
  --include-files 'crates/gateway/src/filters/response_body_content_scanner.rs' \
  --include-files 'crates/gateway/src/filters/response_body_decompressor.rs' \
  --fail-under-lines 95
```
Phase-06 PR checklist updates accordingly.

### 15 — Single observability counter (Medium)
**Flaw:** `state.hits` incremented but never exported. SRE has no signal that scanner is alive after pattern-compile failures or config reload.

**Action:** Phase-03 emits Prometheus counter `body_scan_hits_total{host,category}` on every match. Increment under `parking_lot::Mutex<HashMap<(String, &'static str), u64>>` exposed via existing `/metrics` endpoint (already wired by `waf-api`). Phase-05 integration test asserts counter increment.

## Scope reductions applied (from Scope Critic)
- 6 phases → 5 phases (merge phase-05 tests-and-docs + phase-06 ship-and-pr → phase-05 tests-docs-ship)
- HostConfig fields: keep ONLY `body_scan_enabled: bool`, `body_scan_max_body_bytes: u64` (default 1 MiB). Drop: `body_scan_action`, `body_scan_categories`, `body_scan_extra_patterns`, `body_scan_mask_token`, `body_scan_max_decompress_bytes`, `body_scan_max_decompress_ratio`.
- Hardcode constants in module: `MASK_TOKEN`, `MAX_DECOMPRESS_BYTES = 4 << 20`, `MAX_DECOMPRESS_RATIO = 100`, `MAX_TAIL_BYTES = 1024`, `MAX_PII_SCAN_LEN = 8 << 10`.
- Master toggle replaces per-category — categories are baked. Operator turns scanner on/off only.
- Test count: target 18 unit + 4 integration tests (down from 35 + 7).
- Conflict probe: replace 6-line `git merge-tree` block with `gh pr view 14 --json mergeable && gh pr view 18 --json mergeable`.

## Items NOT applied (rationale)
None. Every finding had a defensible accept; the remaining design tension (e.g., keep_tail vs operator-set max body bytes) is resolved by hardcoding caps as constants.

## Unresolved questions
1. **AC-17 + PR-18 cache pointer-key bug** — Should FR-033 block on backporting the fix to AC-17/PR-18 caches, or land FR-033 with the same bug and address all three in one follow-up? Recommendation: land FR-033 with new content-hash key; file follow-up issue for AC-17/PR-18 retrofit. PR description explicitly cites the inconsistency.
2. **gRPC / HTTP/2 trailers handling** — Phase-04 should add `Content-Type` allowlist guard (`text/*`, `application/json`, `application/xml`, `application/problem+json`) and skip on `application/grpc*`, `text/event-stream`. Add to phase-04 implementation steps.
3. **Cluster `config_version` bump?** — Defaults via `#[serde(default)]` make this additive; no bump expected. Confirm at phase-05 round-trip test time.
