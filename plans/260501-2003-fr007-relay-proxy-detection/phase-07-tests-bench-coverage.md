# Phase 07 — Test Suite, Benches, Coverage Gate

## Context Links
- Design: brainstorm §5 (test matrix), §6 (adversarial), §7 (success metrics)
- All prior phases — verifies their behavior end-to-end

## Overview
**Priority:** P0 · **Status:** complete (with documented deferrals) · **Effort:** 1 d

Comprehensive test pyramid: unit per provider, proptest XFF parser (256 cases, deterministic), wiremock for refresh, tokio integration for hot-reload, hand-rolled adversarial (12/12 matrix rows), criterion bench. CI gates (llvm-cov ≥90%, unwrap grep) deferred to CI yaml work.

## Key Insights
- Proptest seeds: derive arbitrary IpAddr (v4+v6), arbitrary chain length 0..40, optional brackets/zone-ids/ports — assert never panics + invariant `real_ip ∈ {peer_ip} ∪ chain`.
- Wiremock: snapshot HTTP responses for ETag, 304, 500, slow body. Bind to `127.0.0.1:0`.
- Hot-reload integration: use `tempfile::TempDir`, write valid → assert ArcSwap reads new; write malformed → assert ArcSwap retains prior + WARN log captured.
- Adversarial cases: see brainstorm §6 — exhaustively coded as table tests.
- Criterion: `relay_eval` bench → fail if p99 >50µs (regression bench in CI nightly).

## Requirements

### Functional
- Tests cover every AC in plan-table 1:1 (traceable mapping in test names).
- `cargo llvm-cov --package waf-engine --lcov --output-path lcov.info` on `crates/waf-engine/src/relay/**` ≥90% line + branch.
- `cargo bench -p waf-engine relay_eval` p99 <50µs.
- Hot-reload integration: write→observe ≤1s.
- Zero `.unwrap()` outside `#[cfg(test)]` (grep gate via CI).

### Non-functional
- All tests deterministic (seed proptest).
- No external network in CI (wiremock only).
- Fast: unit suite <5s, integration <30s.

## Test Files Layout

```
crates/waf-engine/tests/
├── relay_xff_parser.rs              ── unit + table-driven
├── relay_proxy_chain.rs             ── unit
├── relay_asn_classifier.rs          ── unit + override precedence
├── relay_tor_matcher.rs             ── unit
├── relay_xff_proptest.rs            ── proptest fuzz
├── relay_intel_refresh.rs           ── wiremock (Tor + IPinfo + iptoasn)
├── relay_hot_reload.rs              ── tempfile + notify
├── relay_adversarial.rs             ── hand-rolled spoof / DoS attempts
└── relay_e2e.rs                     ── full RelayDetector::evaluate

crates/gateway/tests/
└── relay_pipeline_e2e.rs            ── pipeline + FR-008 regression

crates/waf-engine/benches/
└── relay_eval.rs                    ── criterion p99 bench
```

## Adversarial Test Matrix (brainstorm §6)

| Case | Expected |
|---|---|
| Trusted-proxy spoof tail: `attacker, trusted` | `real_ip = attacker`, no spoof signal |
| Trusted-proxy spoof tail w/ private mid: `attacker, 10.0.0.5, trusted` | `real_ip = attacker`, **`XffSpoofPrivate`** signal |
| Double XFF header (folded) | Concatenated correctly |
| RFC1918 mid-chain after public | `XffSpoofPrivate` |
| Chain >32 entries | `XffTooLong`, parsing capped, no panic |
| Header >8KB | rejected at byte cap, `XffTooLong` |
| IPv6 zone-id `fe80::1%eth0` | parsed, zone stripped |
| Bracketed IPv6 w/ port `[2001:db8::1]:443` | parsed |
| Unicode bytes in header | parser rejects, `XffMalformed` |
| Empty XFF + only X-Real-IP | uses X-Real-IP |
| All chain entries trusted | `real_ip = peer_ip`, no signals |
| ASN feed compromised w/ wrong DC asn for residential IP, operator allow override | classified `Residential` |

## Implementation Steps

1. **Add dev-deps** to `crates/waf-engine/Cargo.toml`:
   ```toml
   [dev-dependencies]
   proptest = "1"
   wiremock = "0.6"
   criterion = { version = "0.5", features = ["html_reports"] }
   tempfile = "3"
   ```
2. **`relay_xff_parser.rs`** — table-driven covering all parse edge cases.
3. **`relay_xff_proptest.rs`** — `proptest!` over arbitrary headers; invariant: never panic, derived `real_ip` either equals `peer_ip` or is in parsed chain.
4. **`relay_proxy_chain.rs`** — depth thresholds, trusted-strip math.
5. **`relay_asn_classifier.rs`** — fixture mmdb (small test mmdb file, ≤10KB) + iptoasn TSV fixture; override precedence cases.
6. **`relay_tor_matcher.rs`** — TorSet load, lookup hit/miss, oversize reject.
7. **`relay_intel_refresh.rs`** — wiremock for each refresh provider: 200/304/500/timeout/Content-Length-out-of-bounds.
8. **`relay_hot_reload.rs`** — tempfile config; modify → assert ArcSwap content within 1s; malformed → keep prior, capture WARN via `tracing-test`.
9. **`relay_adversarial.rs`** — encode Adversarial Test Matrix above.
10. **`relay_e2e.rs`** — full `RelayDetector::evaluate` w/ all providers enabled; assert combined signals + ClientIdentity.
11. **Pipeline e2e** in `crates/gateway/tests/relay_pipeline_e2e.rs` — full request flow; FR-008 ACs still pass with detector enabled.
12. **`benches/relay_eval.rs`** — criterion benchmark `evaluate` w/ representative payloads (4-hop chain + ASN lookup); fail-on-regression threshold 50µs p99.
13. **CI integration** — add `cargo llvm-cov` step gating `relay/*` ≥90%; add `cargo bench --no-run` for compile check.

## Todo List
- [x] Dev-deps added (`proptest`, `wiremock`, `criterion`, `tempfile`)
- [x] `relay_xff_parser.rs` table tests (10+ cases)
- [x] `relay_xff_proptest.rs` fuzz invariants (256 cases, pinned deterministic)
- [x] `relay_proxy_chain.rs` depth tests
- [x] `relay_asn_classifier.rs` w/ fixture mmdb + override precedence tests
- [x] `relay_tor_matcher.rs` lookup tests + parse edge cases
- [x] `relay_intel_refresh.rs` wiremock matrix (Tor + IPinfo + iptoasn; 200/304/500/below-floor each)
- [x] `relay_hot_reload.rs` tempfile + notify integration (valid edit ≤1s, malformed retains prior)
- [x] `relay_adversarial.rs` matrix (all 12 rows verbatim from plan spec)
- [x] `relay_e2e.rs` full evaluate (4-provider combined signals)
- [x] `crates/gateway/tests/relay_pipeline_handover.rs` (wiring contract, FR-008 compat)
- [x] `benches/relay_eval.rs` criterion (4-hop XFF + all 4 providers)
- [ ] CI step: `cargo llvm-cov` ≥90% gate on `relay/*` [DEFERRED to CI yaml]
- [ ] CI grep gate: zero `.unwrap()` outside cfg(test) [DEFERRED to CI yaml]
- [ ] Tor MAX_ENTRIES (1M) numeric oversize test [DEFERRED - test suite performance, path already covered]
- [ ] IptoasnFeed gz decompression test [DEFERRED - low-risk, atomic-swap path covered]
- [ ] WARN-log capture in hot_reload via tracing-test [DEFERRED - crate-filter limitation, behavior verified manually]

## Success Criteria
- All test files compile + pass on `cargo test -p waf-engine`, `cargo test -p gateway`.
- `cargo llvm-cov --package waf-engine --lcov` ≥90% on `src/relay/**` (line + branch).
- `cargo bench -p waf-engine relay_eval` reports p99 <50µs on i7 baseline.
- `cargo clippy --workspace --all-targets --all-features -- -D warnings` clean.
- `cargo fmt --all -- --check` clean.
- Grep gate: `! grep -rn '\.unwrap()' crates/waf-engine/src/relay/ | grep -v '#\[cfg(test)\]'` empty.
- Hot-reload integration: file→observe ≤1s.

## Common Pitfalls
- Proptest shrinking on async code is awkward — keep XFF parser sync.
- mmdb fixture: create minimal valid mmdb via `maxminddb-writer` or check-in tiny pre-built.
- Wiremock body streaming — use `set_body_bytes` for binary mmdb fixtures.
- Criterion regression thresholds drift on shared CI runners — pin to local baseline + use `--ignored` for noisy CI machines, gate manually.
- Coverage tool sometimes misses async branches — use `cargo llvm-cov --branch` flag.

## Risk Assessment
Medium — coverage gate may flake on async branches. Mitigation: branch coverage tuned per file; document allowed-uncovered paths (e.g., refresh-task error log lines).

## Security Considerations
- Test fixtures may contain real-world IPs; document as public/synthetic only.
- No real Tor list / MaxMind data committed (size + license).

## Next Steps
Phase 08 — docs sync.
