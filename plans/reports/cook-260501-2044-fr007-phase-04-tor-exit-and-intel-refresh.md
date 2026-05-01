# Cook Report — FR-007 Phase-04 (Tor Exit + Intel Refresh)

**Date:** 2026-05-01 20:44 (Asia/Saigon)
**Mode:** `--auto`
**Plan:** [phase-04-tor-exit-and-intel-refresh.md](../260501-2003-fr007-relay-proxy-detection/phase-04-tor-exit-and-intel-refresh.md)

## Summary
Implemented Tor exit matcher, intel refresh tasks (HTTP w/ ETag → atomic file swap), and gateway-friendly spawn primitive on `RelayDetector`. Air-gap mode auto-detects when `refresh.url` is absent.

## Files Created
| Path | LOC | Purpose |
|---|---:|---|
| `crates/waf-engine/src/relay/intel/http.rs` | 39 | shared `reqwest::Client` builder (UA, 5s/60s timeouts) |
| `crates/waf-engine/src/relay/intel/atomic_swap.rs` | 109 | size-bounded streaming write → fsync → rename |
| `crates/waf-engine/src/relay/intel/feed_helpers.rs` | 78 | shared HTTP+ETag+swap routine |
| `crates/waf-engine/src/relay/intel/tor_feed.rs` | 134 | TorFeed: IntelProvider + ArcSwap publish on update |
| `crates/waf-engine/src/relay/providers/tor_exit.rs` | 167 | TorSet loader + TorExitMatcher SignalProvider |

## Files Modified
- `crates/waf-engine/Cargo.toml` — added `reqwest` features `stream,gzip`; `flate2`, `futures-util`; dev-dep `wiremock`.
- `crates/waf-engine/src/relay/intel/mod.rs` — register new submodules; re-export feed types.
- `crates/waf-engine/src/relay/intel/asn_feed.rs` — `IpinfoLiteFeed: IntelProvider` (refresh task wrapping path/URL).
- `crates/waf-engine/src/relay/intel/asn_feed_iptoasn.rs` — `IptoasnFeed: IntelProvider` w/ gzip auto-detect (`.gz` URL → 2-step swap via `flate2`).
- `crates/waf-engine/src/relay/providers/mod.rs` — export `TorExitMatcher`, `TorSet`.
- `crates/waf-engine/src/relay/registry.rs` — wire `tor_exit` in `signals.enabled`; graceful empty-set degradation.
- `crates/waf-engine/src/relay/mod.rs` — `RelayDetector::start_refresh_tasks(Vec<(Arc<dyn IntelProvider>, Duration)>) -> Vec<JoinHandle<()>>` + `intel_refresh_loop` that retains last-good on Failed.

## Verification
- `cargo check -p waf-engine` clean.
- `cargo clippy -p waf-engine --all-targets --all-features -- -D warnings` clean.
- `cargo test -p waf-engine --lib relay` → **60 passed, 0 failed**.
- All `relay/**` files ≤200 LOC (largest 167).
- Zero `.unwrap() / todo!() / unimplemented!()` introduced (production code).

## Acceptance Criteria Met (phase-04)
- TorSet parses comments + blanks, skips malformed, caps at 1M entries.
- TorExitMatcher hits → `Signal::TorExit`; miss → empty.
- atomic_swap rejects out-of-bounds Content-Length pre-write; cleans tmp on error.
- TorFeed `url=None` → `RefreshOutcome::NotModified` (air-gap).
- TorFeed `Updated` path reloads `TorSet` and publishes via `ArcSwap`.
- IpinfoLiteFeed + IptoasnFeed implement `IntelProvider::refresh` w/ ETag + bounds.
- IptoasnFeed gzip path uses `flate2::read::GzDecoder` in `spawn_blocking`, then atomic rename.
- `start_refresh_tasks` spawns one loop per provider; loop survives `Failed`.

## Design Notes
- HTTPS-only validator (`tor_feed::require_https`) provided but enforcement deferred to phase-05 config-load time (no behavioural change here).
- ETag stored in-memory only — restart re-fetches once (YAGNI per plan §Common Pitfalls).
- `IpinfoLiteMmdb` reader untouched; phase-05 watcher rebuilds reader from new file.
- `intel_refresh_loop` skips first immediate tick — boot eager-load is responsibility of phase-05 wiring, not this primitive.

## Deferred to Phase-05/07
- Notify watcher integration (file rename → ArcSwap rebuild for ASN db).
- Wiremock-backed integration tests (smoke air-gap test only here per plan §10).
- HTTPS scheme enforcement at YAML load.

## Open Questions
None. All decisions in plan §Common Pitfalls + §Implementation Steps applied as written.
