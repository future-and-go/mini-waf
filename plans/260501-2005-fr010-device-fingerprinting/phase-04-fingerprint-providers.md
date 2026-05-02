# Phase 04 — Fingerprint Providers: JA3, JA4, H2 Akamai

**Status:** completed (core impl); deferred — FoxIO golden vectors, proptests, benches | **Priority:** P0 | **Effort:** M | **Blocked by:** phase-03

## Context

Convert `RawCapture` into stable fingerprint strings. Three algorithms, all impl `FingerprintProvider`. Versioned (`ja4_v1`, etc.) so future algorithm updates don't silently change downstream behavior.

## Requirements

### Functional
- `Ja3Hasher`: classic JA3 = MD5(`SSLVersion,Cipher,Extension,EllipticCurve,EllipticCurvePointFormat`)
- `Ja4Hasher`: JA4_a + JA4_b + JA4_c per FoxIO spec; strip GREASE; sort/normalize per spec
- `H2AkamaiHasher`: `S[settings]|W[window]|P[priorities]|H[pseudo_order]` then truncated SHA256
- All three return `Option<FingerprintValue { algorithm, version, value }>`

### Non-functional
- Deterministic: same `RawCapture` → same hash, always
- GREASE-resistant: GREASE values stripped before hashing (proptest)
- Versioned: bump `version` field if algorithm changes

## Files

**Created:**
- `crates/waf-engine/src/device_fp/fingerprint/ja3.rs`
- `crates/waf-engine/src/device_fp/fingerprint/ja4.rs`
- `crates/waf-engine/src/device_fp/fingerprint/h2_akamai.rs`
- `tests/golden/ja4_vectors.json` — FoxIO reference vectors

## Steps

1. Implement `Ja3Hasher` per Salesforce spec (md5)
2. Implement `Ja4Hasher` per FoxIO spec — variants `a/b/c` for v1; document JA4S/H/X as future
3. Implement `H2AkamaiHasher` per Akamai 2017 paper format
4. Register all three w/ `FingerprintProvider` registry
5. Property tests: GREASE permutation invariance; cipher order invariance for JA4 (sorted per spec); SETTINGS order matters for h2
6. Golden tests against FoxIO JA4 reference vectors + Akamai sample bot fingerprints
7. Bench

## Todos

- [x] JA3 implementation + tests
- [x] JA4 implementation + tests
- [ ] FoxIO JA4 golden vectors — deferred (needs fixture import in phase-09)
- [x] H2 Akamai implementation + tests
- [x] Provider registration (`FingerprintRegistry::assemble`)
- [ ] Property tests (GREASE, ordering) — deferred to phase-09 coverage gate
- [ ] Golden vector tests (Chrome/Firefox/Safari/curl/curl-impersonate) — deferred to phase-09
- [ ] Bench `ja3_hash`, `ja4_hash`, `h2_akamai_hash` — deferred to phase-09
- [x] Document algorithm versions (`JA3_VERSION`, `JA4_VERSION`, `H2_AKAMAI_VERSION` consts)

## Success Criteria

- FoxIO JA4 reference vectors all pass
- 7 client fixtures produce stable fingerprints across runs
- GREASE permutation property test 1000 cases pass
- Bench: each hasher <50µs

## Risks

- JA4 spec evolves — pin to spec date in version field; v1 = `2024-01`
- MD5 in JA3 — security warnings ok (it's a fingerprint, not crypto); add `#[allow(...)]` w/ comment

## Next

Phase 06 — signal providers consume FingerprintValue + IdentityStore observations.
