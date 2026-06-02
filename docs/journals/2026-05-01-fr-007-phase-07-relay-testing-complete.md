# FR-007 Phase-07: Relay/Proxy Detection Test Suite & Benchmarks

**Date**: 2026-05-01 13:45
**Severity**: Low
**Component**: waf-engine relay detection (test suite, benchmarks, gateway integration)
**Status**: Resolved

## What Happened

Phase-07 shipped 11 green tests covering relay/proxy detection: 9 waf-engine integration tests + 1 gateway wiring test + 1 Criterion bench. Adversarial test matrix (12/12 rows) validates XFF parsing under untrusted vs. trusted proxy chains. Proptest fuzz (256 cases) exercises parser invariants. Wiremock matrix covers 3 threat intel feeds (IpinfoLite, Iptoasn, Tor) with synthetic responses (200/304/500/below-floor). Hot-reload integration test verifies file→ArcSwap propagation ≤1s. Code review yielded 8.5/10 with two nits addressed.

## The Brutal Truth

We almost shipped with a silent failure in the trusted-proxy logic. Test row "trusted-proxy spoof tail w/ private mid" passed its assertions initially, which should've been a red flag—the test itself was broken, not the code. Over-broad CIDR trust (`10.0.0.0/8`) stripped the intermediate private IP before the spoofing check could trigger, masking the signal. Spent 45 minutes digging into why a deliberately-spoof payload didn't fail. The fix was one character: tighten the trusted CIDR to the single LB IP `/32`. **The real lesson:** trusted CIDRs in tests must be scoped tighter than the chain entries you want to flag—over-broad trust isn't just loose, it's **silent**.

The Iptoasn feed bounds test nearly shipped with a decimal/binary unit confusion. `IPTOASN_BOUNDS` floor is 1 MiB binary (`1024 * 1024`), not 1 MB decimal. Burned 20 minutes arguing with the test because the feed body (`1_000_001` bytes) was below the constant and triggered `Failed`, as intended—but I'd assumed decimal. Read the constant, don't assume.

## Technical Details

**Test Files:**
- `crates/waf-engine/tests/relay_adversarial_matrix.rs`: 12-row matrix (trusted proxy IP, XFF chain shape, injected spoofs). Each row validates correct classification (Trusted / TrustedButTainted / Untrusted / Injected).
- `crates/waf-engine/tests/relay_xff_parser_proptest.rs`: 256-case fuzz on XFF header parsing. Invariants: (1) valid chains parse without panic, (2) empty headers → empty chain, (3) IP addresses are valid.
- `crates/waf-engine/tests/relay_feed_wiremock_*.rs`: Separate test per feed (ipifo, iptoasn, tor). 4 scenarios per feed (200 OK, 304 Not Modified, 500 Error, below-floor data). Feed constructor + cache entry validation.
- `crates/waf-engine/tests/relay_hot_reload_integration.rs`: Simulates file change (touch → poll). Assert ArcSwap swap completes ≤1s. Verify old handle still valid during transition.
- `crates/gateway/tests/relay_pipeline_handover.rs`: Gateway unit test. Mocks waf-engine, validates pipeline translates `RelayDecision` → context flags (is_spoofed, is_tainted, proxy_tier).

**Benchmark (`benches/relay_eval.rs`):**
- Measures XFF parser latency + IP→ASN lookup under synthetic load
- Three payload sizes: minimal (1 hop), medium (5 hops), large (15 hops)
- Pre-parses ASN database (was: `EmptyAsnDb` mock; now: `StaticDb` with 10k entries)
- Gate: 50 µs/op max (XFF parse + lookup in warm cache)
- Result: 18–31 µs depending on chain depth (under gate)

**Cargo.toml Additions:**
- Dev-deps: `proptest` (fuzz), `reqwest` (HTTP client for wiremock), `wiremock` (HTTP mock server)
- Bench entry: `relay_eval` with criterion feature enabled

## What We Tried

1. **Trusted CIDR Overscope:** Initial test passed `10.0.0.0/8` as trusted. Mid-chain IP `10.0.0.5` was also in that range, so it got stripped before spoofing check ran. Test passed when it should've failed. Fixed by tightening to `/32` LB IP only.

2. **Iptoasn Feed Bytes Confusion:** Feed body size `1_000_001` bytes vs. `IPTOASN_BOUNDS` floor `1024 * 1024` (1 MiB). Assumed decimal MB during test write; realized the constant is binary. Took a second pass to confirm the test was correct and the assumption was wrong.

3. **Tor Feed MAX_ENTRIES Numeric Oversize:** Considered adding a test for >1M entries (Tor feed MAX_ENTRIES). Concluded impractical; bail path is covered in src code. Deferred as nice-to-have.

4. **Iptoasn Gzip Path:** Considered separate test for `.gz` file path. Plumbing reused from plain-file path; coverage redundant. Deferred.

5. **Gateway E2E Pingora Harness:** No test seam in Pingora host; substituted with gateway wiring contract test (mocks engine, validates pipeline flag translation). Adequate coverage.

6. **WARN-Log Capture in Hot-Reload:** Attempted to assert WARN log on old-file deletion via tracing-test env_filter. Filter defaults to test crate; events from `waf_engine` silenced. Retained prior assertion (ArcSwap propagation ≤1s) as load-bearing invariant.

## Root Cause Analysis

No critical failures. Two test-quality issues (over-broad CIDR, unit confusion) were caught during review and fixed. No code bugs; test suite itself needed scoping refinement.

## Lessons Learned

**Trusted CIDR scoping in tests must be tighter than threat-plane IPs.** When building adversarial tests, the test author is responsible for ensuring trust zones don't accidentally bleach the signal. Broad CIDR trust that covers your injected spoof payloads will silently pass the test. Always ask: "Does my trusted zone include any of the IPs I'm trying to flag?"

**Constants require reading.** `IPTOASN_BOUNDS` is a binary unit (bytes), not decimal. The constant name doesn't hint at the unit. Policy: When a test references a magic constant, read its docstring and/or definition before building test data around it.

**Defer impractical coverage, document it.** Tor MAX_ENTRIES oversize test and `.gz` path test are not worth the effort; the bailout logic and file-read plumbing are already covered elsewhere. Deferral list is part of the deliverable.

**Gateway wiring tests replace E2E in the absence of test harnesses.** We don't have a Pingora test seam; the gateway unit test validates pipeline contract (RelayDecision → context flags). Adequate for this phase.

## Next Steps

All acceptance criteria green. Phase-07 test suite is production-ready. Deferrals documented above (Tor oversize, `.gz` path, WARN-log capture, gateway E2E) are tracked for future phase-07b if scope permits.

CI integration: `cargo test --test relay_*` and `cargo bench --bench relay_eval` are part of standard test suite. No new CI gates needed (existing code quality + coverage gates apply).

Minor future improvement: Iptoasn feed timestamp validation test (mocked 304 Not Modified state). Low priority; defer to phase-07b if requested.

**Code review: 8.5/10.** Nits addressed: (1) `failure_persistence: None` on proptest with docstring for `PROPTEST_RNG_SEED` override, (2) bench replaced `EmptyAsnDb` with `StaticDb` to measure real work.
