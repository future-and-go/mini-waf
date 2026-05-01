# Phase 02 — XFF Validator + Proxy Chain Analyzer

## Context Links
- Design: brainstorm §4.4 (signals), §4.8 (perf), §6 (DoS risk)
- Phase 01 types: `relay/signal.rs`, `relay/config.rs`

## Overview
**Priority:** P0 · **Status:** completed · **Effort:** 1 d

Two `SignalProvider` impls: `XffValidator` (parse + spoof detect) and `ProxyChainAnalyzer` (effective hop depth after trusted strip). These produce `real_ip` consumed by phases 03/04.

## Key Insights
- `real_ip` derivation: walk XFF chain right→left, strip trusted CIDRs, first non-trusted IP is `real_ip` (fall back to `peer_ip` if all trusted or empty/malformed).
- IPv6 traps: brackets `[fe80::1]:443`, zone IDs `fe80::1%eth0`, scope literals — RFC 4291 canonicalize before compare.
- DoS hardening: hard cap header size 8KB, entry count 32 — enforced BEFORE parse.
- Multiple `X-Forwarded-For` headers (folded) → concatenate with comma per RFC 7230 §3.2.2.
- Private/loopback IP mid-chain (i.e. not at the trusted-prefix tail) → `XffSpoofPrivate` signal.

## Requirements

### Functional
- `XffValidator::evaluate` parses configured headers (default `X-Forwarded-For`, `X-Real-IP`), emits:
  - `XffMalformed` on parse failure of any entry
  - `XffTooLong` if entry count > 32 or header bytes > 8192
  - `XffSpoofPrivate` if private/loopback found beyond trusted-strip prefix
- `ProxyChainAnalyzer::evaluate` computes effective hop depth (chain length after trusted strip), emits `ExcessiveHopDepth(n)` when `n > max_chain_depth`.
- Both providers compute and stash `real_ip` into `RelayCtx::derived` (shared scratch struct) so downstream providers reuse without re-parsing.

### Non-functional
- p99 < 10µs per provider on 8-entry chain (criterion bench in phase-07).
- Zero allocations on hot path where avoidable (use `&str` slices).
- File ≤200 LOC each.

## Architecture

```
RelayCtx {
   peer_ip,
   headers,
   derived: Cell<Derived>,    // mutated by first provider that parses XFF
}
struct Derived {
   parsed_chain: SmallVec<[IpAddr; 8]>,
   real_ip: IpAddr,            // peer_ip default
   trusted_stripped_count: u8,
}
```

Single-pass parse: first call to either provider populates `Derived`; second reads cache. Use `OnceCell` or `RefCell`-wrapped `Option`.

## Related Code Files

### Create
- `crates/waf-engine/src/relay/providers/xff_validator.rs`
- `crates/waf-engine/src/relay/providers/proxy_chain.rs`
- `crates/waf-engine/src/relay/providers/parse.rs` — shared XFF parse helpers

### Modify
- `crates/waf-engine/src/relay/signal.rs` — extend `RelayCtx` with `Derived` cache field
- `crates/waf-engine/src/relay/providers/mod.rs` — declare submodules

## Implementation Steps

1. **Hard caps** — define `MAX_HEADER_BYTES: usize = 8192`, `MAX_CHAIN_ENTRIES: usize = 32` in `parse.rs`. Reject before split.
2. **`parse.rs::parse_xff_chain(&HeaderMap, &[HeaderName]) -> Result<Chain, ParseErr>`**:
   - Concatenate folded headers w/ `,`.
   - Byte-cap check.
   - Split on `,`, trim whitespace.
   - Entry-cap check.
   - For each entry: strip optional `"`/`[`/`]`, strip port suffix (last `:` IFF preceded by `]` or no `:` earlier — IPv4 only), strip zone ID after `%`.
   - Parse via `IpAddr::from_str`; collect `MalformedAt(i)` errors.
3. **`parse.rs::derive_real_ip(chain, &[IpNet] trusted, peer_ip) -> (IpAddr, u8 stripped_count, bool spoof_private_mid_chain)`**:
   - Walk right→left, strip while in trusted set, count.
   - First non-trusted entry → `real_ip`; if none, fall back to `peer_ip`.
   - Spoof check: any entry LEFT of the first non-trusted that is RFC1918/loopback/link-local → `spoof_private_mid_chain = true`.
4. **`XffValidator`** — `impl SignalProvider`:
   - Lazy-populate `ctx.derived` on first call.
   - Emit `XffTooLong` / `XffMalformed` / `XffSpoofPrivate` per derive output.
5. **`ProxyChainAnalyzer`** — `impl SignalProvider`:
   - Use cached chain length minus stripped trusted count = effective depth.
   - `if depth > cfg.max_chain_depth { emit ExcessiveHopDepth(depth) }`.
6. **Wire registry** — `ProviderRegistry::from_config(&RelayConfig)` instantiates these two when `signals.enabled` contains their names (`"xff_validator"`, `"proxy_chain"`).
7. **Test** — table-driven unit tests (see Success Criteria).

## Todo List
- [x] `parse.rs` — caps + `parse_xff_chain` + `derive_real_ip`
- [x] `XffValidator` provider
- [x] `ProxyChainAnalyzer` provider
- [x] Extend `RelayCtx::derived` cache
- [x] `ProviderRegistry::from_config` wiring for these two
- [x] Unit tests: malformed, oversize, IPv6 zone-id, IPv4 port suffix, private mid-chain, all-trusted fallback to peer_ip, multi-header folding
- [x] `cargo check` + clippy clean

## Success Criteria
- Unit tests cover: empty header, single IP, 32+ entries (capped), 8KB+ bytes (capped), `[2001:db8::1]:443`, `fe80::1%eth0`, `1.2.3.4, 10.0.0.1, 5.6.7.8` w/ trusted `10.0.0.0/8` → spoof signal, all-trusted chain → `real_ip = peer_ip`.
- Property test stub (real proptest in phase-07) — at least one randomized input that does not panic.
- p99 latency rough check via `#[ignore]` micro-bench (real bench in phase-07).
- File LOC ≤200 each.

## Common Pitfalls
- `IpAddr::from_str("[::1]")` fails — must strip brackets first.
- IPv4 port detection: presence of `:` in IPv4-only token = port; in IPv6 = part of address. Disambiguate by counting `:` (>1 → IPv6, ≤1 → IPv4 maybe-with-port).
- Header folding: `HeaderMap::get_all` returns multi-value iter; do NOT just take first.
- Trusted-CIDR strip is the CRITICAL correctness path (per brainstorm §6 risk #1) — exhaustive cases mandatory.

## Risk Assessment
**CRITICAL** — trusted-strip bug → wrong `real_ip` → bypass downstream gates. Mitigated by exhaustive table tests here + proptest in phase-07.

## Security Considerations
- DoS cap enforced before any allocation-heavy parse.
- Never log raw header (may contain PII) — log entry count + outcome only.
- Zone IDs (`%eth0`) ignored for matching — never trusted as routable.

## Next Steps
Phase 03 — `AsnClassifier` + ASN intel feeds.
