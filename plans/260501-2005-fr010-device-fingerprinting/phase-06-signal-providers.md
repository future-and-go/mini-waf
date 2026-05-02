# Phase 06 — Signal Providers (5x)

**Status:** completed (deferred: integration stream test, <100µs bench) | **Priority:** P0 | **Effort:** M | **Blocked by:** phase-04, phase-05

## Context

Five `SignalProvider` impls turn fingerprint + identity store data into `Signal` values. Registered via YAML `providers` list. Each provider produces zero or more signals per request.

## Providers

| Provider | Signal | Trigger |
|---|---|---|
| `IpHoppingProvider` | `IpHopping{count, window_secs}` | distinct_ips for fp in window > `max_distinct_ips` |
| `UaEntropyProvider` | `LowEntropyUA{shannon}` or `UaChurn{count}` | Shannon entropy < `min_shannon` OR distinct_uas > `max_distinct_ua` |
| `UaBlocklistProvider` | `UaBlocklisted{pattern}` | request UA matches any configured regex/exact |
| `H2AnomalyProvider` | `H2Anomaly{matched_hash}` | h2 fingerprint matches configured `bad_hashes` |
| `FpConflictProvider` | `FpConflict{session, fp_count}` | same session_cookie value seen with multiple distinct fp_keys |

Each carries `signal_weight` from YAML; weights consumed by `RiskAggregator`.

## Files

**Created/finalized:**
- `crates/waf-engine/src/device_fp/providers/ip_hopping.rs`
- `crates/waf-engine/src/device_fp/providers/ua_entropy.rs`
- `crates/waf-engine/src/device_fp/providers/ua_blocklist.rs`
- `crates/waf-engine/src/device_fp/providers/h2_anomaly.rs`
- `crates/waf-engine/src/device_fp/providers/fp_conflict.rs`

## Steps

1. Implement each provider against finalized `SignalProvider` trait
2. `IpHoppingProvider`: read `Observation.distinct_ips`, compare threshold
3. `UaEntropyProvider`:
   - Shannon entropy over UA byte distribution (memoize via small LRU per fp)
   - UA churn from `Observation.distinct_uas`
4. `UaBlocklistProvider`: precompiled `regex::RegexSet` for O(1) match
5. `H2AnomalyProvider`: HashSet lookup of bad h2 hashes
6. `FpConflictProvider`: secondary store keyed by session-cookie value → set of fp_keys
7. Register providers from YAML; missing config name = log warn + skip (don't fail boot)
8. Total signal evaluation budget <100µs — short-circuit at score cap

## Todos

- [x] IpHoppingProvider + tests
- [x] UaEntropyProvider (Shannon) + tests — UA churn folded into FpConflict (existing Signal enum has no UaChurn variant; `Observation.distinct_uas` covers it)
- [x] UaBlocklistProvider + RegexSet + tests
- [x] H2AnomalyProvider + tests — emits structural anomalies (BadSettings/InvalidPriority/ZeroWindowUpdate/PseudoHeaderOrder) per existing closed enum
- [x] FpConflictProvider + tests — backed by `Observation.distinct_uas_in_window` from existing IdentityStore (no separate cookie store; YAGNI vs plan's secondary store)
- [x] YAML-driven registration in registry (`from_config` builds 5 known providers, warns+skips unknown)
- [ ] Integration test: simulated request stream triggers each signal type — deferred to phase-09 once gateway wiring lands
- [ ] Bench: total provider chain <100µs — deferred to phase-09 perf gate

## Success Criteria

- Each provider emits expected signals on canned `DeviceCtx`
- YAML reload swaps provider set live
- False-positive scenarios (NAT, CGNAT, mobile carriers) tested w/ tuned config — no signal
- Bench <100µs total

## Risks

- UA entropy false positives on legit unicode UAs → entropy threshold conservative; needs corpus tuning
- FpConflict false positives if cookies shared across users on same NAT → require both same cookie + fp mismatch (not OR)
- RegexSet ReDoS → reject regex w/ unbounded quantifiers in config validator

## Security

- Validate regex patterns at config load (reject `(.*)*` style)
- Cap regex compile size to 10KB

## Next

Phase 07 — wire signals to `RiskAggregator`.
