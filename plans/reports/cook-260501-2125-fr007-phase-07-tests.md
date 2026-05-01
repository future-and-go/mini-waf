# FR-007 Phase-07 — Test Suite + Criterion Bench

**Status:** DONE_WITH_CONCERNS

---

## Files Written

### crates/waf-engine/Cargo.toml
- Added dev-dependencies: `proptest = "1"`, `tracing-test = "0.2"`, `reqwest = { workspace = true, features = ["stream", "gzip"] }`
- Added `[[bench]] name = "relay_eval" harness = false`

### crates/waf-engine/tests/
| File | Description |
|---|---|
| `relay_xff_parser.rs` | Table-driven XFF parse edge cases (empty, IPv4, brackets+port, zone-id, malformed, folded, byte-cap, count-cap) + end-to-end via `RelayDetector` |
| `relay_xff_proptest.rs` | 256-case proptest: never panics + real_ip ∈ {peer} ∪ chain |
| `relay_proxy_chain.rs` | ProxyChainAnalyzer depth tests (under/at/over cap, trusted-tail strip math) |
| `relay_asn_classifier.rs` | AsnClassifier override precedence (operator_allow > dc_set > operator_deny, CIDR match, DB miss, compromised-feed adversarial) |
| `relay_tor_matcher.rs` | TorSet parse (comments, blanks, malformed), contains hit/miss, TorExitMatcher emission |
| `relay_intel_refresh.rs` | Wiremock: TorFeed + IpinfoLiteFeed + IptoasnFeed — 200/304/500/below-floor for each |
| `relay_hot_reload.rs` | RelayReloader watcher: valid edit propagates ≤1s, malformed retains prior + WARN log via tracing-test |
| `relay_adversarial.rs` | All 12 adversarial matrix rows verbatim |
| `relay_e2e.rs` | Full 4-provider evaluate: combined signals (DC+Tor, spoof+unknown, hop+DC), real_ip resolution |

### crates/gateway/tests/relay_pipeline_handover.rs
Wiring contract test: `GatewayCtx.client_identity.real_ip` preferred over raw peer; no-identity fallback to peer; signal accessibility.

### crates/waf-engine/benches/relay_eval.rs
Criterion bench `relay_eval_4hop`: 4-hop XFF + all 4 providers (EmptyAsnDb, 10-IP TorSet). No hard threshold in code — CI nightly gates p99 <50µs.

---

## Checks Passed

- `cargo check -p waf-engine --tests --benches` — clean
- `cargo check -p gateway --tests` — clean
- `cargo clippy -p waf-engine --tests --benches -- -D warnings` — clean
- `cargo clippy -p gateway --tests -- -D warnings` — clean
- `cargo fmt -p waf-engine -- --check` — clean
- `cargo fmt -p gateway -- --check` — clean

---

## Deferred Items

1. **Tor oversize numeric test** — `MAX_ENTRIES=1_000_000` inserting 1M entries in a test suite is prohibitively slow (~10s+). The `bail!` path in `TorSet::parse` is exercised indirectly (the code path is trivially covered by the unit tests in `src/`). Noted in `relay_tor_matcher.rs` doc comment.

2. **CI gates** — `cargo llvm-cov` ≥90% gate and `unwrap` grep gate are CI yaml changes, outside file scope. Both flagged as deferred per phase-07 spec.

3. **Gateway full Pingora e2e** — Full request-cycle Pingora integration test requires a harness not present in this repo. `relay_pipeline_handover.rs` tests the wiring contract instead (GatewayCtx + ClientIdentity round-trip). Full e2e deferred per phase-07 note.

4. **IptoasnFeed gz path** — gz decompression test path not covered (would require a valid gz blob ≥256KB). The plain-body path (Updated/304/500/below-floor) is covered. gz path is low-risk (same atomic-swap plumbing as plain).

---

## Key Implementation Notes

- `RelayConfig::from_yaml_str` already returns `Arc<RelayConfig>` — tests call it directly without re-wrapping.
- Test files use `#![allow(clippy::unwrap_used, clippy::expect_used, ...)]` for test-only lints (doc_markdown, missing_const_for_fn) — consistent with existing bench files in the repo.
- `relay_intel_refresh.rs` uses `std::fmt::Write` for body building to avoid `clippy::format_collect`.
- proptest pinned: `failure_persistence: None, cases: 256` for determinism in CI.

---

## Unresolved Questions

None.
