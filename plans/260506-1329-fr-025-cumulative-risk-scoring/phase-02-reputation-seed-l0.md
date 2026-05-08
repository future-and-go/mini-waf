---
phase: 2
title: "Reputation Seed L0"
status: complete
priority: P1
effort: "2d"
dependencies: [1]
---

# Phase 2: Reputation Seed L0 — Tor / ASN / Whitelist

## Overview

Add the L0 reputation seed: before any other layer runs, classify the peer IP via (a) whitelist short-circuit (returns 0, bypasses all subsequent layers), (b) Tor exit list, (c) ASN classification (datacenter/badlist/normal). Each lookup ≤100µs p99; lists hot-reloadable.

## Why L0 First (After Skeleton)

Most attacks come from cheap infrastructure (datacenter ASNs, Tor exits). L0 is the highest-leverage layer for the lowest cost — a single lookup against pre-built data structures. Also lets us validate the layered-pipeline budget pattern (§3.1 of brainstorm) before adding more expensive layers.

## Requirements

**Functional:**
- Whitelist match → seed score = 0, **short-circuits remaining layers** (Iron rule §10 brainstorm).
- Tor exit IP match → seed delta = +30 contributor with kind `Seed(TorExit)`.
- ASN classification:
  - Datacenter (AWS/GCP/Azure/DO/OVH/Hetzner/Linode/etc.) → +15
  - Known-bad ASN (operator-curated list) → +25
  - Residential → 0
- Lists loaded from disk on startup; hot-reload via `notify`.
- ASN lookup uses radix trie (CIDR ranges) — no linear scan.

**Non-functional:**
- p99 ≤ 100µs per lookup (criterion gate).
- Hot-reload swap with zero request-path lock contention (`ArcSwap<SeedTables>`).
- Memory: 5M ASN ranges ≤ 200MB resident.

## Architecture

```
risk/seed/
├── mod.rs           # SeedLayer struct, public Layer impl
├── tor.rs           # Tor exit list loader + HashSet<IpAddr> lookup
├── asn.rs           # IP→ASN trie (cidr-utils or ip_network_table)
├── whitelist.rs     # whitelist short-circuit logic
└── tables.rs        # SeedTables struct held inside ArcSwap
```

### Data Sources

| Source | Format | Default Path | Refresh |
|--------|--------|--------------|---------|
| Tor exits | newline IPs | `/etc/prx-waf/tor-exits.txt` | `notify` on file change |
| ASN classification | CSV `cidr,asn,classification` | `/etc/prx-waf/asn-classes.csv` | `notify` |
| Whitelist | newline CIDRs | `/etc/prx-waf/risk-whitelist.txt` | `notify` |

> Operators bring their own data. Plan does NOT bundle Tor/ASN data — document expected refresh cadence in `docs/deployment-guide.md`.

### Trie Choice

Use `ip_network_table` if FR-008 dyn blacklist already uses it (grep first), else `cidr-utils`. **Do NOT** use `iptrie` (GPL).

## Related Code Files

**Create:**
- `crates/waf-engine/src/risk/seed/mod.rs`
- `crates/waf-engine/src/risk/seed/tor.rs`
- `crates/waf-engine/src/risk/seed/asn.rs`
- `crates/waf-engine/src/risk/seed/whitelist.rs`
- `crates/waf-engine/src/risk/seed/tables.rs`
- `crates/waf-engine/src/risk/tests/seed_layer.rs`
- `crates/waf-engine/benches/risk_seed.rs`
- `configs/seed/tor-exits.example.txt`
- `configs/seed/asn-classes.example.csv`
- `configs/seed/risk-whitelist.example.txt`

**Modify:**
- `crates/waf-engine/src/risk/mod.rs` — `pub mod seed;`
- `crates/waf-engine/src/risk/scorer.rs` — call `seed.evaluate(ip)` BEFORE any other layer; whitelist match → return `Action::Allow` with score=0 immediately.
- `crates/waf-engine/src/risk/config.rs` — `seed:` section.
- `crates/waf-engine/src/risk/reload.rs` — watch seed data files.
- `docs/deployment-guide.md` — document data file format + refresh expectation.

## Implementation Steps

1. **Pick CIDR trie crate.** Grep workspace for existing CIDR usage. Reuse if present.
2. **Loader functions.** `tor::load(path)`, `asn::load(path)`, `whitelist::load(path)`. Each returns `anyhow::Result<T>`; malformed line → log warn + skip, never panic.
3. **`SeedTables` struct.** Bundle three structures behind one `Arc`. Single `ArcSwap<SeedTables>` swapped atomically on reload.
4. **`SeedLayer`.** `pub fn evaluate(&self, ip: IpAddr) -> SeedVerdict`. Variants: `Whitelisted`, `Score { delta: u8, contributor: ContributorKind }`, `None`.
5. **Whitelist short-circuit.** Scorer special-cases `Whitelisted` → return `Allow` immediately, set header to 0, skip ALL subsequent layers including async ingest accumulator.
6. **Hot-reload.** Add seed paths to `reload.rs` watcher. On change → reload affected file → swap full `SeedTables`.
7. **Tests.** Tor IP → +30, AWS CIDR → +15, whitelist CIDR → short-circuit, unknown IP → 0, malformed line → warn, no crash. IPv6 covered.
8. **Bench.** `evaluate` p99 ≤ 100µs across 5M-entry trie + 10k Tor set + 1k whitelist CIDRs.
9. **Compile gates.** Standard set.

## Common Pitfalls

- **Whitelist applied AFTER expensive layers** (§6 pitfall #6). Always FIRST.
- **Loading Tor list every request** — load once, swap via ArcSwap.
- **CIDR overlap ambiguity** — bad ASN list overlaps datacenter list → longest-prefix; tie → badlist wins (more conservative).
- **IPv6 missed** — ASN trie MUST handle both v4 and v6 prefixes.

## Success Criteria

- [x] `evaluate` p99 ≤ 100µs (bench gate).
- [x] Whitelist short-circuit verified by integration test (Allow even when other detectors WOULD have triggered).
- [x] Hot-reload test: append IP to tor-exits.txt → within 2s next request scored +30.
- [x] Malformed CSV line → loader logs warn, skips, no crash.
- [x] IPv6 lookup tested.
- [x] All Iron Rules respected (no `.unwrap()`, ≤200 LoC per file).

## Risk Assessment

| Risk | Severity | Mitigation |
|------|----------|------------|
| ASN list 200MB resident under load | Medium | Compact radix trie; memory residency bench |
| Operator runs without seed data → all 0 | Low | Empty file valid; log warn at startup |
| GeoIP/ASN data privacy concern | Low | Operator-supplied; document in deployment-guide |
| CIDR parse overflows on malformed input | Medium | `IpNetwork::from_str` returns Result; never panic |
| Hot-reload races partial file write | Medium | `notify` debounce 500ms + atomic-rename pattern |

## Verify

```bash
cargo test -p waf-engine risk::seed
cargo bench -p waf-engine --bench risk_seed
echo "1.2.3.4" >> /etc/prx-waf/tor-exits.txt
sleep 3
curl -sI -H "X-Forwarded-For: 1.2.3.4" http://localhost:16880/ | grep -i x-waf-risk-score
```
