# Phase 01 — waf-common (config, types, panel) → 90%

## Context Links
- Baseline: `plans/260509-1039-coverage-90/plan.md`
- Crate: `crates/waf-common/`
- Existing tests: `crates/waf-common/src/lib.rs` (23 inline unit tests), `crates/waf-common/tests/tier.rs` (6 integration tests)

## Overview
- **Priority:** P2
- **Status:** pending
- **Target:** 90% line (baseline 59.42%)
- File ownership glob: `crates/waf-common/**`

## Key Insights
- `config.rs` (464 regions, **34.27%**) is the single biggest gap — TOML loader, env-var override, defaults, validation.
- `types.rs` (216 regions, 71.30%) — `RequestCtx` builders, header parsing, decision construction.
- `crypto.rs` (106 regions, 84.91%) — AES-GCM helpers; missing edge cases (bad nonce, short ciphertext).
- `panel_config.rs` (206 regions, 83.50%) — already well covered; minor edge cases.
- `url_validator.rs` (248 regions, 85.48%) — SSRF guard; missing IPv6 mixed-case + percent-encoded host paths.
- Pure types crate, no I/O — 90% trivially achievable.

## Requirements
- Functional: every public function in `config.rs` exercised at least once with valid + at least one invalid input.
- Non-functional: tests deterministic, ≤ 50ms each, no global state mutation (use `serial_test` only if env-var tests collide).

## Architecture (module map)
```
waf-common/src/
├── config.rs        ← BIG GAP (305 missed lines)
├── types.rs         ← MEDIUM (62 missed)
├── url_validator.rs ← LOW (36 missed)
├── crypto.rs        ← LOW (16 missed)
├── panel_config.rs  ← LOW (34 missed)
├── tier.rs          ← 100% (skip)
└── tier_match.rs    ← 100% (skip)
```

## Related Code Files
**Modify (add inline `#[cfg(test)]` modules):**
- `crates/waf-common/src/config.rs`
- `crates/waf-common/src/types.rs`
- `crates/waf-common/src/crypto.rs`
- `crates/waf-common/src/url_validator.rs`

**Create:**
- `crates/waf-common/tests/config_loader.rs` — TOML parsing, defaults, env-var override matrix
- `crates/waf-common/tests/types_request_ctx.rs` — `RequestCtx` happy + edge cases (Unicode headers, oversized cookies)

## Implementation Steps
1. Read current `config.rs`; enumerate every `pub fn`, `impl Default`, `impl<'de> Deserialize`. List branches missed.
2. Add inline tests for each `Config` substruct: `[proxy]`, `[api]`, `[storage]`, `[cache]`, `[rules]`, `[cluster]`, `[tier]`. For each: (a) minimal-valid TOML, (b) one missing-field default, (c) one invalid value rejected.
3. Add `tests/config_loader.rs` integration test that loads `configs/default.toml` from disk.
4. For `types.rs`: cover `RequestCtx::new`, header iteration (multi-value), cookie parser malformed inputs, `WafDecision` constructors.
5. `crypto.rs`: cover encrypt-decrypt roundtrip (already), bad-nonce-length, short-ciphertext, key-mismatch.
6. `url_validator.rs`: add IPv6 zone-id (`fe80::1%eth0`), percent-encoded host (`http://%31%32%37.0.0.1`), uppercase scheme (`HTTPS://`).
7. Run `cargo llvm-cov -p waf-common --summary-only` after each step; target 90%.

## Todo List
- [ ] `config.rs` inline tests for each section struct (≥10 new tests)
- [ ] `config.rs` env-var override tests (extend existing 4 → cover all 12 keys)
- [ ] `tests/config_loader.rs` integration with `configs/default.toml`
- [ ] `types.rs` inline tests: header multi-value, cookie malformed, `RequestCtx` builder
- [ ] `crypto.rs` edge cases: nonce-len, short-ct, key-mismatch
- [ ] `url_validator.rs` IPv6/percent-encoded/case cases
- [ ] Verify `cargo llvm-cov -p waf-common --summary-only` ≥ 90%
- [ ] `cargo check --tests -p waf-common` clean
- [ ] `cargo fmt --all -- --check` clean

## Success Criteria
- `cargo llvm-cov -p waf-common --summary-only --ignore-filename-regex 'vendor/|target/'` reports ≥ 90.0% line coverage.
- Zero warnings on `cargo check --tests -p waf-common`.
- `cargo test -p waf-common` < 5 s.

## Risk Assessment
- **Low**: Pure data crate. Likelihood of regressions = low.
- Env-var override tests may collide if run in parallel — use `serial_test` crate or unique env-var prefixes per test.

## Security Considerations
- Crypto tests must NOT commit real keys — generate ephemeral keys per test.
- `url_validator` is the SSRF gate — every new branch added must come with a denial test, not just an allow.

## Next Steps
- Phase 04 (waf-api) consumes `config.rs` types — coordinate test fixture sharing.
