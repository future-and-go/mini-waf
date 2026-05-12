---
slug: fr-033-response-body-content-filter
title: "FR-033 — Response Body Content Filtering"
description: "Mask/block stack traces, secrets, internal IPs, verbose errors in upstream response bodies; supersedes AC-17 by adding built-in catalog + decompression."
status: completed
completed: 2026-04-28
pr: 19
priority: P0
effort: 3d
branch: feat/fr-033-response-body-content-filter
tags: [feature, backend, security, outbound]
created: 2026-04-28
owner: lotus
blockedBy: []
blocks: []
related_prs: [14, 18]
---

# FR-033 — Response Body Content Filtering

## Goal
Redact sensitive content leaking from upstream HTTP response **bodies**: stack traces, verbose error messages, API keys/tokens, internal IPs. Operates on identity AND gzip-decompressed bodies. Single redact action — replaces match span with hardcoded mask token `[redacted]`. ReDoS-bounded by construction.

## Why now
`analysis/requirements.md` line 73 mandates FR-033. Existing AC-17 (`response_body_mask_filter.rs`) covers operator-supplied regex over **identity** bodies only — research report (`research/researcher-01-fr033-best-practices-and-attacks.md` §1, §6) identifies this as the OWASP CRS bypass vector: attackers gzip leaks to evade. Real incidents (Equifax 2017, Capital One 2019, Spring4Shell 2022) show response-body sanitization is load-bearing for breach prevention.

## Scope (post-red-team)
**In scope:**
- Built-in detector catalog (4 categories: stack traces, verbose errors, secrets, internal IPs) — no operator regex
- gzip body decompression (deflate + brotli deferred to FR-033b)
- Single action: replace match span with hardcoded token `[redacted]` (no `Block` mode — see red-team finding #2)
- Decompression bomb defense: bounded reader + ratio guard (hardcoded 4 MiB / 100:1)
- Streaming, chunk-aware. ReDoS-bounded by per-pattern DFA size limit + max upper-bound on every quantifier
- Coexists with AC-17 (operator regex) and PR 18 (FR-034 JSON field redact)
- Chain order: **scan (FR-033) → redact (PR-18) → mask (AC-17)** — FR-033 owns decompression; downstream layers see plaintext

**Out of scope (deferred):**
- Whole-body block (FR-005 owns request-time block)
- deflate / brotli / zstd / lz4 decompression
- Operator-supplied extras (AC-17 owns `internal_patterns`)
- Per-route policy DSL
- HTML-aware sanitization
- Multi-language stack-trace ML classifier
- gRPC / event-stream / WebSocket-upgrade Content-Types (skipped at `response_filter`)
- Header-level scanning (covered by FR-035 / PR 14)

## Architecture summary

```
upstream_response
   │
   ├── response_filter (proxy.rs)
   │     ├── existing chain (via, server-policy, location, header-blocklist)
   │     ├── FR-033 decide scan_enabled    (drop CL + TE; drop CE iff gzip)
   │     ├── PR-18  decide redact_enabled  (no CL touch — FR-033 already dropped it)
   │     └── AC-17  decide mask_enabled    (no CL touch — FR-033 already dropped it)
   │
   └── response_body_filter (proxy.rs)
         ├── FR-033 apply_body_scan_chunk  (gzip decompress → scan → redact)
         ├── PR-18  apply_redact_chunk     (JSON field name on plaintext)
         └── AC-17  apply_body_mask_chunk  (operator regex on plaintext)
```

Order rationale (revised post-red-team #4): FR-033 owns decompression. Plaintext flows out of FR-033 to PR-18 (which can JSON-parse correctly) and finally AC-17. Putting FR-033 first preserves real per-chunk streaming because PR-18 buffers the entire body until EOS, which would collapse FR-033's streaming guarantees if it sat downstream.

## Phase index (post-red-team — phase-06 collapsed into phase-05)
| # | Phase | File | Effort |
|---|-------|------|--------|
| 1 | Host config + detector catalog | [phase-01-host-config-and-detector-catalog.md](phase-01-host-config-and-detector-catalog.md) | 3h |
| 2 | Decompression pipeline (gzip-only) | [phase-02-decompression-pipeline.md](phase-02-decompression-pipeline.md) | 3h |
| 3 | Streaming scanner (single redact action) | [phase-03-streaming-scanner-and-actions.md](phase-03-streaming-scanner-and-actions.md) | 5h |
| 4 | Gateway wiring (chain reorder + content-hash cache) | [phase-04-gateway-wiring.md](phase-04-gateway-wiring.md) | 3h |
| 5 | Tests + docs + ship | [phase-05-tests-and-docs.md](phase-05-tests-and-docs.md) | 4h |

phase-06 absorbed into phase-05; ship checklist becomes a sub-section in phase-05. See red-team-260428-2332-fr033-adjudication.md scope reductions.

## Risk register (post-red-team)
| Risk | Likelihood | Impact | Status | Mitigation |
|------|-----------|--------|--------|------------|
| Cache pointer-key bleed across hosts on reload | Medium | High | ✓ mitigated | Content-hash key `(host_name, xxhash(body_scan_*))` via `moka::sync::Cache`. AC-17/PR-18 inherit same fix in follow-up. (Red-team #6) |
| Chunk-boundary secret leak via small `keep_tail` | High | High | ✓ mitigated | `keep_tail = MAX_TAIL_BYTES - 1 = 1023`; reject built-in patterns whose `regex_syntax::hir::Hir::properties().maximum_len()` exceeds 1024. (Red-team #7) |
| Decompression bomb DoS | Medium | High | ✓ mitigated | Hardcoded 4 MiB output cap + 100:1 ratio guard + 1 MiB input cap. Fail-open on excess; pin `flate2` version. (Red-team #3) |
| ReDoS via per-regex DFA cache | Low | High | ✓ mitigated | Every built-in regex has explicit `{min,max}` quantifiers. `RegexBuilder::dfa_size_limit(2 << 20)`. No combined alternation. (Red-team #10) |
| FP rate on legit pages | Medium | Medium | ✓ mitigated | Stack traces use anchored multiline regex (not naked literals); test fixtures from real Stripe/AWS/GitHub responses; per-pattern FP corpus in phase-05. (Red-team #13) |
| HTTP/2 trailers / gRPC body-format break | Medium | Medium | ✓ mitigated | `Content-Type` allowlist guard at `response_filter`: skip `application/grpc*`, `text/event-stream`. (Red-team unresolved Q2) |
| PR 14 / PR 18 merge conflicts | High | Low | ✓ resolved | Append-only HostConfig fields; no edits to `config.rs` / `prx-waf/main.rs` / `project-roadmap.md`. Conflict map in phase-05 ship section. |

## Success criteria (post-red-team)
- All 4 categories detected on positive fixtures (stack-traces use anchored multiline regex, not naked literals)
- gzip positive path passes; non-gzip non-identity Content-Encoding skipped with `tracing::debug!`
- Bomb fixture (10000:1 ratio) rejected without OOM; 4 MiB output cap enforced pre-allocation
- Redact emits hardcoded `[redacted]` token; `Content-Length` + `Transfer-Encoding` dropped unconditionally; `Content-Encoding` dropped iff gzip-decoded
- gRPC / event-stream Content-Type skipped at `response_filter` time
- Cache key by content-hash; cross-host bleed on config reload prevented (assertion test)
- `static_assertions::assert_impl_all!(BodyScanState: Send)` compiles
- HostConfig serde round-trip preserves new fields through cluster sync (TOML round-trip test)
- Counter `body_scan_hits_total{host,category}` increments; surfaced via existing `/metrics` endpoint
- p99 latency ≤ +25 ms on 50 KB JSON (research §5)
- ≥ 95% line coverage via `cargo llvm-cov --include-files` per-file gate on new modules
- `cargo fmt --check && cargo clippy -D warnings && cargo test --workspace` green

## Red Team Review

### Session — 2026-04-28 (4 hostile reviewers, 40 raw findings → 15 deduped, all accepted)

**Severity:** 6 Critical · 6 High · 3 Medium · 0 rejected
**Adjudication:** [`reports/red-team-260428-2332-fr033-adjudication.md`](reports/red-team-260428-2332-fr033-adjudication.md)

| # | Finding | Sev | Applied to |
|---|---------|-----|------------|
| 1 | Drop `body_scan_extra_patterns` (DRY w/ AC-17) | Critical | phase-01, phase-03 |
| 2 | Drop dual Mask/Block; single redact mode + hardcoded mask token | Critical | phase-01, phase-03, phase-04, phase-05 |
| 3 | gzip-only v1; defer deflate + brotli | Critical | phase-02, phase-03, phase-05 |
| 4 | Reorder chain: scan (FR-033) BEFORE redact (PR-18) | Critical | phase-04 |
| 5 | Replace `RegexSet` with `Vec<Regex>` for span-aware replace | Critical | phase-03 |
| 6 | Cache key by content-hash, not `Arc::as_ptr` | Critical | phase-04 |
| 7 | Fix `keep_tail` math; cap built-in regex max-length ≤ 1024 | High | phase-03, phase-05 |
| 8 | Internal IP via `std::net::Ipv4Addr::is_loopback/is_private` | High | phase-03 |
| 9 | Always drop `Content-Length` + `Transfer-Encoding` when scanner enabled | High | phase-04 |
| 10 | Cap upper bounds on every regex; explicit `dfa_size_limit` | High | phase-03 |
| 11 | `assert_impl_all!(BodyScanState: Send)`; pin `flate2` version | High | phase-04, phase-05 |
| 12 | HostConfig serde round-trip + cluster sync test | High | phase-05 |
| 13 | Anchored multiline regex for stack traces | Medium | phase-03, phase-05 |
| 14 | Per-file coverage gate via `--include-files` | Medium | phase-05 |
| 15 | Counter `body_scan_hits_total` for SRE observability | Medium | phase-03, phase-04, phase-05 |

**Scope reductions (Scope Critic):**
- 6 phases → 5 phases (phase-06 absorbed)
- HostConfig: 8 fields → 2 fields (`body_scan_enabled`, `body_scan_max_body_bytes`)
- Constants hardcoded in module: `MASK_TOKEN`, `MAX_DECOMPRESS_BYTES`, `MAX_DECOMPRESS_RATIO`, `MAX_TAIL_BYTES`, `MAX_PII_SCAN_LEN`
- Tests: target 18 unit + 4 integration (down from 35 + 7)
- Conflict probe: replace `git merge-tree` block with `gh pr view 14/18 --json mergeable`

## Implementation Outcome
**Status:** Completed 2026-04-28 in PR #19 (commit `2034c6e`).

| Phase | Status | Notes |
|-------|--------|-------|
| 1 | ✓ done | HostConfig + 2 fields, hardcoded constants, 4-category catalog with `pattern_within_bounds` enforcement |
| 2 | ✓ done | gzip-only via `flate2::read::MultiGzDecoder`; 4 MiB output / 8 MiB input / 100:1 ratio caps |
| 3 | ✓ done | Single redact mode; `Vec<Regex>` (no RegexSet); `(?m)^` anchored stack-trace regex; std::net IP detection |
| 4 | ✓ done | Chain order FR-033 → FR-034 placeholder → AC-17; `moka::sync::Cache` content-hash key |
| 5 | ✓ done | 113+6+14 tests green in Docker; docs appended; PR #19 with single commit + force-push amends |

**Red-team mitigation status:** 15/15 applied. Code-review post-fix: C1 + H1 + H2 + H3 resolved. M1-M5 / L1-L5 deferred to follow-up tickets per YAGNI.

**Drive-by fixes (pre-existing on main, also fixed by PR 14 / PR 18):**
- `crates/gateway/src/ctx_builder/request_ctx_builder.rs:175` — `inefficient_to_string`
- `crates/prx-waf/src/main.rs:1475` — `assigning_clones` → `clone_from`

## Out-of-scope explicit
Whole-body block (FR-005), deflate/brotli/zstd/lz4 decompression, operator-supplied extras (AC-17), per-route DSL, HTML sanitization, ML classifier, encrypted-body decryption, header scanning, gRPC/event-stream Content-Types — all deferred.

## Unresolved questions
1. AC-17 + PR-18 inherit same `Arc::as_ptr` cache bug — backport jointly or follow-up ticket? (Recommendation: follow-up; FR-033 lands with new content-hash key, cite inconsistency in PR description.)
2. Cluster `config_version` schema bump — defaults via `#[serde(default)]` make this additive; confirm at phase-05 round-trip test.
3. p99 SLA target — 25 ms budget cited from research §5; confirm with k6 benchmark in phase-05.
