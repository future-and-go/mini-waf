# Phase 05 — Tests + Docs + Ship (phase-06 absorbed)

> **RED-TEAM PATCH (mandatory):**
> - **scope-#1** phase-06 absorbed into phase-05; ship checklist becomes a sub-section.
> - **scope-#8** Test count target: ~18 unit + 4 integration (down from 35 + 7). Drop redundant per-pattern tests; one positive per category + boundary-split + gzip + bomb + integration.
> - **scope-#9** Conflict probe: replace 6-line `git merge-tree` block with `gh pr view 14 --json mergeable && gh pr view 18 --json mergeable`.
> - **#7** Add boundary-split tests at chunk offsets `[1, MAX_TAIL_BYTES-1, MAX_TAIL_BYTES, MAX_TAIL_BYTES+1]` for each built-in pattern's full match string.
> - **#11** Add `static_assertions::assert_impl_all!(BodyScanState: Send)` in test module.
> - **#12** Add cluster-sync round-trip test: `HostConfig{body_scan_enabled: true, body_scan_max_body_bytes: 2<<20}.to_toml()` → parse back → fields preserved. Also test through `waf-cluster::config_sync_serialize/deserialize`.
> - **#13** FP/FN corpus: real Stripe webhook signature header, real GitHub PAT documentation snippet, real Java prose `at javax.servlet`. Each must NOT trigger; matching catalog patterns MUST trigger on synthetic positive fixtures.
> - **#14** Coverage gate is per-file: `cargo llvm-cov -p gateway --include-files crates/gateway/src/filters/response_body_content_scanner.rs --include-files crates/gateway/src/filters/response_body_decompressor.rs --fail-under-lines 95`.
> - **#15** Integration test asserts `body_scan_hits_total` counter increments after a positive match.
> - **PR description constraints:** No AI references, no prompt-derived language, no AI tool / agent mentions. Cite `analysis/requirements.md` line 73, cross-reference PR 14 + PR 18 with conflict-resolution notes, list test coverage, declare out-of-scope. Single commit policy.
> - Reference: [`reports/red-team-260428-2332-fr033-adjudication.md`](reports/red-team-260428-2332-fr033-adjudication.md).

## Context Links
- Coverage policy: `crates/gateway/CLAUDE.md` "Testing & coverage" — 95% line gate via `cargo-llvm-cov`
- AC-17 test pattern reference: `crates/gateway/src/filters/response_body_mask_filter.rs` lines 168–282 (8 tests)
- Research §3 (real attack cases) — drives positive fixtures
- Research §6 (anti-patterns) — drives negative/FP fixtures

## Overview
- **Priority:** P0
- **Status:** completed 2026-04-28
- 25+ unit tests inline in scanner module, 5+ integration tests, docs updates. Target: ≥ 95% line coverage on new files. No mocks, no fake data — real fixtures (real gzip-of-real-stack-trace, real Stripe webhook signature shape, real AWS pre-signed URL form) per development-rules.md "DO NOT use mocks/cheats just to pass build".

### Deviations
- Counter test: added `test_hits_counter_increments_on_redact` per red-team #15.
- H1 regression test: added `test_byte_ceiling_flushes_pending_tail` for chunk-boundary tail flush.
- HostConfig serde + cluster sync round-trip test: placed in scanner module tests (not waf-cluster; cluster integration deferred to FR-033b).
- 6 integration tests vs 7 planned (placeholder for PR-18 full-chain test deferred until merge).

## Key Insights
- AC-17 has 8 inline tests covering: single-chunk replace, straddle, EOS flush, disabled, empty patterns, invalid pattern, ceiling, boundary regression. FR-033 needs ≥ 3× that scope (4 categories × 3 dimensions = decompression x action x boundary).
- Block action testing must verify body replacement (status code stays — see phase-03 trade-off note); assert resulting bytes contain neutral page marker, not match.
- FP suppression tests are mandatory per research §6.7 (allowlist) — skipping them lets us ship a high-FP filter.
- Integration tests reuse FR-001 phase-06b deferral context: live-Pingora E2E remains deferred. We instead add **Pingora-free integration tests** that exercise the full response-body filter chain at the function level (compose `apply_redact → apply_body_scan → apply_body_mask` in test).

## Requirements
**Functional**
- ≥ 25 unit tests in `response_body_content_scanner::tests` and `response_body_decompressor::tests`.
- ≥ 5 integration tests in `crates/gateway/tests/response_body_content_scanner_integration.rs`.
- All categories' positive paths covered.
- All categories' explicit negative (no-match) paths covered.
- gzip / deflate / br positive paths.
- Decompression bomb rejected (ratio > limit).
- Mask action emits token; Block action emits neutral page; Block action drops subsequent chunks.
- Custom `body_scan_extra_patterns` regex applied alongside built-ins.
- FP fixtures from real Stripe webhook signature header (not body) — assert NOT matched in body.
- FP fixtures from real AWS pre-signed URL — assert NOT matched (pre-signed URLs contain key-id but operator wants pass-through; document via test name).
- Boundary straddle with each matcher type (literal AC + regex set).

**Non-functional**
- Tests use real bytes (gzip via `flate2::write::GzEncoder` in fixture builder, brotli via `brotli::CompressorWriter`).
- No `unwrap()` outside test code (test code may use `.unwrap()` per CLAUDE.md `#[cfg(test)]` exception).
- `cargo-llvm-cov` ≥ 95% on new files.

## Architecture
```
crates/gateway/src/filters/response_body_content_scanner.rs
   #[cfg(test)] mod tests { ... 18+ inline tests ... }

crates/gateway/src/filters/response_body_decompressor.rs
   #[cfg(test)] mod tests { ... 8+ inline tests ... }

crates/gateway/tests/response_body_content_scanner_integration.rs   (NEW, ~250 lines)
   - test_full_chain_redact_scan_mask_order
   - test_gzip_stack_trace_block_action_neutral_page
   - test_brotli_secret_mask_action
   - test_deflate_internal_ip_with_allowlist
   - test_decompression_bomb_fail_open
   - test_chunk_boundary_split_secret
   - test_unknown_encoding_fail_open

docs/system-architecture.md   (APPEND new section)
docs/codebase-summary.md       (UPDATE crate tree)
crates/gateway/CLAUDE.md       (REPLACE AC-17 line + ADD FR-033 subsection)
```

## Related Code Files
**Modify**
- `/Users/admin/lab/mini-waf/crates/gateway/src/filters/response_body_content_scanner.rs` — append `#[cfg(test)] mod tests`
- `/Users/admin/lab/mini-waf/crates/gateway/src/filters/response_body_decompressor.rs` — append `#[cfg(test)] mod tests`
- `/Users/admin/lab/mini-waf/docs/system-architecture.md` — append "Response Body Content Scanning (FR-033)" section AFTER PR-14 / PR-18 sections (textual append → minimal merge conflict)
- `/Users/admin/lab/mini-waf/docs/codebase-summary.md` — update tree under `crates/gateway/src/filters/`
- `/Users/admin/lab/mini-waf/crates/gateway/CLAUDE.md` — replace line `Body decompression is FR-033's problem` with `Body decompression delivered in FR-033 (see "Body content scanner (FR-033)" subsection below)`; append new "Body content scanner (FR-033)" subsection (~30 lines)

**Create**
- `/Users/admin/lab/mini-waf/crates/gateway/tests/response_body_content_scanner_integration.rs` — 7 integration tests

**DO NOT MODIFY**
- `docs/project-roadmap.md` (conflict avoidance)

## Implementation Steps

### Test list (≥ 25 unit + 7 integration)

**Decompressor (`response_body_decompressor.rs::tests`):**
1. `gzip_roundtrip_short`
2. `gzip_roundtrip_1mb`
3. `deflate_roundtrip`
4. `brotli_roundtrip`
5. `unknown_encoding_returns_err`
6. `reverse_chain_gzip_of_deflate`
7. `output_cap_triggers`
8. `ratio_cap_triggers_on_zero_payload_gzip`
9. `identity_passthrough_no_decoder`

**Scanner core (`response_body_content_scanner.rs::tests`):**
10. `is_noop_when_all_categories_off`
11. `is_noop_when_disabled_globally`
12. `stack_trace_python_traceback_masked`
13. `stack_trace_rust_panic_masked`
14. `stack_trace_java_at_com_masked`
15. `verbose_error_sql_masked`
16. `verbose_error_file_path_unix_masked`
17. `secret_aws_access_key_masked`
18. `secret_github_pat_masked`
19. `secret_jwt_masked`
20. `secret_private_key_block_masked`
21. `internal_ip_rfc1918_masked`
22. `internal_ip_loopback_127_0_0_1_skipped` (allowlist FP suppression)
23. `internal_ip_link_local_masked`
24. `extra_pattern_combined_with_builtins`
25. `mask_action_emits_token_in_place`
26. `block_action_emits_neutral_page_first_hit`
27. `block_action_drops_subsequent_chunks`
28. `chunk_boundary_straddle_secret_split`
29. `chunk_boundary_straddle_stack_anchor_split`
30. `byte_ceiling_forwards_remainder_unchanged`
31. `disabled_state_zero_cost_passthrough`
32. `invalid_extra_pattern_dropped_others_kept`
33. `fp_stripe_webhook_signature_in_body_not_masked`
34. `fp_aws_pre_signed_url_query_not_masked` (signed URL key id is benign in URL form — assert pass)
35. `category_secrets_only_skips_stack_traces`

**Integration (`tests/response_body_content_scanner_integration.rs`):**
36. `full_chain_redact_then_scan_then_mask` — exercise all three layers in PR-18 / FR-033 / AC-17 ordering on a JSON body containing a card_number, an AWS key, and an operator regex match
37. `gzip_stack_trace_block_action` — gzipped Python traceback → after scanner, body == neutral page bytes
38. `brotli_secret_mask_action` — brotli'd body with `ghp_xxxx...` PAT → masked
39. `deflate_internal_ip_with_allowlist` — deflate'd body with `127.0.0.1` and `10.0.0.5` → only `10.0.0.5` masked
40. `decompression_bomb_fail_open` — synthetic 100:1 ratio gzip → `state.failed = true`, body forwarded unchanged
41. `chunk_boundary_split_secret_via_two_pushes` — feed `ghp_` + remainder; assert masked when reassembled
42. `unknown_encoding_fail_open` — `Content-Encoding: zstd` → scanner disabled, body forwarded unchanged

### Docs steps
1. **`docs/system-architecture.md`** — append after PR-14 / PR-18 sections:
   ```markdown
   ## Response Body Content Scanning (FR-033)

   The gateway's response_body_filter runs three independent sanitization layers in sequence:
   PR-18 JSON field redact → FR-033 catalog scan → AC-17 operator regex.

   FR-033 detects four leak categories (stack traces, verbose errors, secrets, internal IPs)
   in identity, gzip, deflate, and brotli-encoded response bodies. Per-host operator chooses
   `Mask` (replace match with token) or `Block` (replace remaining body with neutral 502 page).

   ReDoS-safe by construction: literal multipattern via aho_corasick, anchored format patterns
   via regex::RegexSet, internal-IP detection via direct byte parse + RFC-1918/loopback CIDR
   classification (no regex CIDR alternation).

   Decompression bomb defense: bounded reader (4 MiB output cap default) + ratio guard
   (100:1 default). Fail-open on decode error: forward original bytes, log warn, suppress
   further inspection for that response.

   Configuration on HostConfig:
   - body_scan_enabled, body_scan_action (Mask|Block), body_scan_categories
   - body_scan_extra_patterns, body_scan_mask_token
   - body_scan_max_body_bytes, body_scan_max_decompress_bytes, body_scan_max_decompress_ratio
   ```
2. **`docs/codebase-summary.md`** — update gateway tree to list `response_body_content_scanner.rs` and `response_body_decompressor.rs` under `filters/`.
3. **`crates/gateway/CLAUDE.md`** — replace AC-17 line "Body decompression is FR-033's problem" with done-link, append "Body content scanner (FR-033)" subsection mirroring AC-17 subsection structure.

## Todo List
- [x] Write 9+ decompressor unit tests (positive, negative, caps, chains) — all green in Docker
- [x] Write 26+ scanner unit tests (4 categories × dimensions, FP suppression, action variants, straddle, ceiling, counter) — all green
- [x] Write 6 integration tests in `tests/response_body_content_scanner_integration.rs` (7th deferred until PR-18 merge)
- [x] Run `cargo test -p gateway` — all green in Docker
- [x] Run scoped `cargo llvm-cov` — ≥ 95% on new files confirmed
- [x] Append "Response Body Content Scanning (FR-033)" section to `docs/system-architecture.md`
- [x] Update `docs/codebase-summary.md` filter tree
- [x] Update `crates/gateway/CLAUDE.md` — replace AC-17 stub line + add FR-033 subsection
- [x] `cargo fmt --all -- --check` green
- [x] `cargo clippy --workspace --all-targets --all-features -- -D warnings` green

## Success Criteria
- All 42 tests pass on `cargo test --workspace`.
- Scoped llvm-cov shows ≥ 95% on new files (consistent with FR-001 phase-06 gate).
- `cargo fmt --check`, `cargo clippy -D warnings` clean.
- No fake data, no mocks, no skipped/ignored tests (development-rules.md "DO NOT use fake data, mocks, cheats").
- All four real-incident scenarios from research §3 (Equifax stack-trace, Capital One IP, Spring4Shell trace, GitHub-PAT-in-traceback) reproduced as test fixtures and pass.

## Risk Assessment
- **Pattern FP rate post-merge** (Likelihood: Medium, Impact: Medium): real-traffic FP often only surfaces in staging. Mitigation: ship default-off (categories all-false); operators must opt-in; test FP fixtures cover top 2 known cases (Stripe sig, AWS pre-signed). Future: collect FP corpus in follow-up ticket.
- **Coverage gap on `unsafe`-adjacent paths** (Likelihood: Low, Impact: Low): no unsafe in new code, so no `// SAFETY:` review needed.
- **Test runtime** (Likelihood: Low, Impact: Low): 42 tests + decompression in-process; expect < 5 seconds total.

## Security Considerations
- Iron Rule #6: integration tests assert fail-open on every adversarial path (bomb, unknown enc, malformed body).
- No real secrets in test fixtures: use deliberately-invalid-checksum AWS-key-format strings (`AKIAFAKEFAKEFAKEFAKE`), example JWTs from RFC 7519. Document in test module rustdoc.
- No log of raw matched content in tests — assertions on byte-position / hit-count / category only.

## Next Steps
- Phase 06: branch, CI green, conflict probe, single PR.
