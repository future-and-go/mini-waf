# Phase 03 — ASN Classifier + Datacenter Override Merge

## Context Links
- Design: brainstorm §4.5 (ASN data sources), §4.9 (failure modes), §10 Q1/Q2/Q4
- Reuse: `crates/waf-engine/src/geoip.rs` (mmdb mmap pattern)

## Overview
**Priority:** P0 · **Status:** completed · **Effort:** 1 d

Implement `AsnClassifier` provider with pluggable ASN data backends: IPinfo Lite mmdb (primary), iptoasn TSV (fallback), MaxMind GeoLite2-ASN (alt). Merge datacenter override sources at load.

## Key Insights
- `AsnDb` is a trait-erased Arc behind `ArcSwap` — swap atomically on refresh (phase-04).
- DC classification = `asn ∈ datacenter_asn_set` (built at load by merging hyperscaler ranges + X4BNet + operator overrides). Operator override list ALWAYS WINS (allow + deny).
- Fail-close policy (Q2): per-tier configurable. Default: refuse-start ONLY when any CRITICAL-tier route enabled AND mmdb unreadable. Post-startup refresh failure → keep last good DB + warn.
- MaxMind license-key (Q4): env var `MAXMIND_LICENSE_KEY` with file-path fallback `license_key_file:`; never logged.
- Initial seed (Q1): bundle hyperscaler-only seed in `rules/threat-intel/hyperscaler-asn-seed.yaml`; X4BNet via optional refresh feed.

## Requirements

### Functional
- `AsnDb` trait: `lookup(IpAddr) -> Option<AsnRecord { asn: u32, org: String }>`.
- Three impls: `IpinfoLiteMmdb`, `IptoasnTsv`, `MaxmindGeoliteAsn`. YAML `asn.provider` selects.
- `DatacenterSet` built from: `datacenter_lists` paths (txt ASN list, YAML CIDR list, operator override YAML w/ allow+deny). Merge order documented; operator override file wins.
- `AsnClassifier::evaluate`: lookup `real_ip` (from cached `Derived`); classify → emit `AsnDatacenter{asn,org}` | `AsnResidential` | `AsnUnknown` (always exactly one of these).
- Startup fail-close: if `cfg.tor.fail_close_on_critical = true` AND any tier marked CRITICAL AND mmdb unreadable → return `Err` from builder.

### Non-functional
- Lookup O(1) (mmdb mmap) or O(log n) (iptoasn sorted ranges).
- Per-lookup p99 < 5µs (criterion bench in phase-07).
- File ≤200 LOC each (`asn_classifier.rs`, `asn_feed.rs`, `asn_feed_iptoasn.rs` separate).

## Architecture

```
trait AsnDb: Send + Sync {
    fn lookup(&self, ip: IpAddr) -> Option<AsnRecord>;
    fn name(&self) -> &'static str;
}

struct AsnClassifier {
    db: Arc<ArcSwap<dyn AsnDb>>,
    dc_set: Arc<ArcSwap<DatacenterSet>>,   // ASN-id set + CIDR table
}

struct DatacenterSet {
    asn_ids: HashSet<u32>,
    cidrs: IpRangeTable,                    // for vendor lists w/o ASN
    operator_allow: HashSet<u32>,           // wins over deny
    operator_deny:  HashSet<u32>,
}
```

## Related Code Files

### Create
- `crates/waf-engine/src/relay/providers/asn_classifier.rs`
- `crates/waf-engine/src/relay/intel/asn_feed.rs` — IPinfo Lite mmdb loader
- `crates/waf-engine/src/relay/intel/asn_feed_iptoasn.rs` — TSV parser + sorted-range table
- `crates/waf-engine/src/relay/intel/asn_feed_maxmind.rs` — MaxMind GeoLite2-ASN (gated by feature `maxmind`)
- `crates/waf-engine/src/relay/intel/datacenter_set.rs` — merge loader
- `rules/threat-intel/hyperscaler-asn-seed.yaml` — bundled minimal seed (AWS/GCP/Azure/OCI/DO/OVH/Hetzner top ASNs)

### Modify
- `crates/waf-engine/Cargo.toml` — verify `maxminddb` (likely present via `geoip.rs`); add only if missing
- `crates/waf-engine/src/relay/mod.rs` — wire `AsnClassifier` into `ProviderRegistry::from_config`

## Implementation Steps

1. **Verify `maxminddb`** — grep workspace + waf-engine Cargo.toml. Reuse if present.
2. **`AsnDb` trait** in `intel/mod.rs` (extend phase-01 file).
3. **`asn_feed.rs::IpinfoLiteMmdb`** — open mmdb via `maxminddb::Reader::open_mmap`; `lookup` returns `(asn, org)` from record.
4. **`asn_feed_iptoasn.rs::IptoasnTsv`** — parse `start_ip\tend_ip\tasn\tcountry\torg` lines; build `Vec<(IpAddr, IpAddr, u32, String)>` sorted by start; binary search on lookup.
5. **`asn_feed_maxmind.rs`** — feature-gated `#[cfg(feature = "maxmind")]`; license key from `env::var("MAXMIND_LICENSE_KEY").or_else(|_| read(cfg.license_key_file))`. Never log.
6. **`datacenter_set.rs::DatacenterSet::load(paths: &[PathBuf]) -> Result<Self>`**:
   - Detect format by extension (`.txt` ASN-per-line, `.yaml` CIDR list / operator override).
   - Operator override file recognized by top-level keys `allow:` / `deny:`.
   - Merge: union all sources for `asn_ids` + `cidrs`; operator allow/deny tracked separately.
7. **`AsnClassifier::evaluate`**:
   - Read `real_ip` from `ctx.derived` (populated phase-02; if missing, default to `peer_ip`).
   - `db.lookup(real_ip)` → `Option<AsnRecord>`.
   - Classify:
     - `None` → `AsnUnknown`
     - `dc_set.operator_allow.contains(asn)` → `AsnResidential` (operator override allow)
     - `dc_set.operator_deny.contains(asn)` OR `dc_set.asn_ids.contains(asn)` OR `dc_set.cidrs.contains(real_ip)` → `AsnDatacenter{asn,org}`
     - else → `AsnResidential`
8. **Startup fail-close** — `RelayDetector::new(cfg, tier_registry)` checks: if `cfg.asn.fail_close_on_critical && tier_registry.has_critical()` and DB load errors → propagate `Err`.
9. **Bundle seed** — minimal hyperscaler ASN list (~30 entries) in `rules/threat-intel/hyperscaler-asn-seed.yaml`.
10. **Unit tests** — see Success Criteria.

## Todo List
- [x] `AsnDb` trait declared (`relay/intel/mod.rs`)
- [x] `IpinfoLiteMmdb` impl (`relay/intel/asn_feed.rs`, generic mmdb reader)
- [x] `IptoasnTsv` impl + sorted-range binary search (split v4/v6)
- [ ] `MaxmindGeoliteAsn` feature-gated impl — **DEFERRED** (YAGNI; mmdb reader covers the file format, schema variant tracked for phase-04 if needed)
- [x] `DatacenterSet::load` merge logic + format detection (`.txt` ASN, `.yaml` asns/cidrs, `.yaml` allow/deny)
- [x] `AsnClassifier::evaluate` w/ override precedence (allow > deny > asn_ids > cidrs)
- [x] Startup fail-close via `asn.fail_close` flag (no tier_registry plumbing — that lives in FR-008/phase-06)
- [x] Bundle `rules/threat-intel/hyperscaler-asn-seed.yaml`
- [x] Unit tests: 50 relay tests pass — DC ASN, residential, unknown, operator allow/deny override, CIDR match, mmdb-missing fail-close path
- [x] `cargo check` + clippy clean (all targets, all features)

## Notes / Deviations
- **`iprange` → `ip_network_table`**: workspace already had `ip_network_table = "0.2"` + `ip_network = "0.4"`; reused those instead of adding `iprange`. `IpNetworkTable<()>::longest_match` provides the same per-CIDR membership test.
- **`maxminddb` added** to `crates/waf-engine/Cargo.toml` (`= "0.24"`); `geoip.rs` uses `ip2region` not mmdb so no shared dep.
- **`ArcSwap<dyn AsnDb>`**: `ArcSwap<T>` requires `T: Sized`. Stored as `ArcSwap<Box<dyn AsnDb>>` instead — same atomic-swap semantics, one extra fat-pointer indirection.
- **MaxMind GeoLite2-ASN deferred**: spec listed three impls; we ship two (mmdb + TSV). The mmdb reader is generic — adding MaxMind schema is a 30-line follow-up if/when an operator needs it.
- **Tier-registry fail-close**: spec referenced a tier registry from FR-008 for "CRITICAL tier" fail-close; we implemented a simpler `asn.fail_close: bool` flag. Tier-aware policy can layer on at phase-06 (gateway integration) without touching this code.

## Success Criteria
- Unit: 8.8.8.8 → ASN 15169 (Google) → `AsnDatacenter`.
- Unit: 1.1.1.1 → Cloudflare → `AsnDatacenter` (in seed).
- Unit: residential ISP IP → `AsnResidential`.
- Unit: bogon/private IP not in DB → `AsnUnknown` (or short-circuit before lookup if RFC1918 — document choice).
- Unit: operator allow `[15169]` → 8.8.8.8 → `AsnResidential` (override wins).
- Unit: mmdb missing + CRITICAL tier enabled → `RelayDetector::new` returns `Err`.
- Unit: mmdb missing + no CRITICAL tier → builds OK, classifier emits `AsnUnknown` for all.
- File LOC ≤200 each.

## Common Pitfalls
- `maxminddb` returns IP-range record; ASN field is `Option<u32>` — treat None as `AsnUnknown`.
- IPv6 in iptoasn TSV: ranges interleave with IPv4; segregate into two sorted vecs by family.
- License key in error messages: scrub before log.
- `IpRangeTable` uses `iprange` crate — verify API for mixed v4/v6 (may need separate `IpRange<Ipv4Net>` / `IpRange<Ipv6Net>`).

## Risk Assessment
**High** — wrong classification on legit cloud-hosted clients (false positives). Mitigated by operator override allow + risk-delta-not-block design.

## Security Considerations
- License keys never logged.
- mmdb file reads on startup only — no untrusted-path traversal (paths from operator-supplied YAML).
- Refresh integrity: ETag pinned + content-length sanity (phase-04).

## Next Steps
Phase 04 — Tor exit matcher + intel refresh tasks (HTTP fetch, atomic swap).
