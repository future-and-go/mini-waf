# waf-engine Coverage Push — Phase 8 Report
<!-- 2026-05-09 -->

## Goal
Lift `waf-engine` owned modules (`logging/`, `plugins/`, `community/`, `crowdsec/`, `relay/`, `geoip*`) to ≥88% combined line coverage.

## Results

| Module | Before | After |
|---|---|---|
| `community/enroll.rs` | 75% | 100% |
| `crowdsec/client.rs` | 61% | 97.06% |
| `crowdsec/pusher.rs` | 65% | 93.60% |
| `relay/intel/asn_feed_iptoasn.rs` | 67% | 92.20% |
| `community/reporter.rs` | 56% | 90.43% |
| `relay/intel/atomic_swap.rs` | 74% | 89.58% |
| `crowdsec/sync.rs` | 66% | 68.97% |
| `geoip_updater.rs` | 77% | 79.76% |
| **TOTAL project** | 90.07% | **91.69%** |

**Blockers (cannot reach 88% combined):**
- `community/mod.rs`: 14.6% — `init_community` requires real machine enrollment + full TLS stack; untestable in unit/integration scope.
- `crowdsec/mod.rs`: 19.1% — `init_crowdsec` wires AppSec component + LAPI connection; same constraint.
- `relay/mod.rs`: 56.5% — `init_relay` async initialization depends on live feed URLs.

These three files account for ~200 missed lines that pull combined coverage to ~83-84%.

## Files Added / Modified

**New test binaries (14 files in `crates/waf-engine/tests/`):**
- `logging_batch_lifecycle.rs`, `logging_audit_sender.rs`, `logging_vlogs_layer.rs`
- `community_blocklist_http.rs`, `community_enroll_http.rs`, `community_reporter_http.rs`, `community_reporter_throttle.rs`
- `crowdsec_lapi_client_http.rs`, `crowdsec_pusher_sync_http.rs`, `crowdsec_appsec_client.rs`, `crowdsec_bouncer_cache.rs`
- `relay_intel_http_feeds.rs`, `relay_intel_refresh_errors.rs`
- `geoip_updater_schedule.rs`, `geoip_lookup.rs`, `plugins_wasm_lifecycle.rs`

**Modified source:**
- `crates/waf-engine/src/relay/intel/atomic_swap.rs` — 4 inline `#[cfg(test)]` tests added
- `crates/waf-engine/Cargo.toml` — added `wiremock`, `wat`, `tempfile`, `ed25519-dalek`, `zstd` dev-deps

All changes committed (8 commits). `cargo fmt --all -- --check` clean. 0 test failures.

## Unresolved

`init_community`, `init_crowdsec`, and `init_relay` are integration-time wiring functions requiring live network/enrollment infrastructure. Coverage can only improve with contract-test harnesses or dependency-injection refactors, both out of scope for this phase.

---

**Status:** DONE_WITH_CONCERNS
**Summary:** Total project coverage rose from 90.07% → 91.69%; owned-module combined coverage is ~83-84% (not ≥88%) due to three untestable `init_*` async functions in `community/mod.rs`, `crowdsec/mod.rs`, and `relay/mod.rs`.
