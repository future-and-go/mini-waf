# Phase 04 — Tor Exit Matcher + Intel Refresh Tasks

## Context Links
- Design: brainstorm §4.2 (intel layout), §4.7 (refresh + atomic swap), §4.9 (air-gap), §6 (feed-compromise risk)
- Reuse: `crates/waf-engine/src/access/reload.rs` (notify watcher pattern)

## Overview
**Priority:** P0 · **Status:** completed · **Effort:** 1 d

`TorExitMatcher` provider + async refresh tasks for Tor list and ASN feeds. HTTP fetch w/ ETag, atomic file swap (tmp + `rename(2)`), graceful degradation on failure.

## Key Insights
- Refresh task = `tokio::spawn` long-running loop: sleep `interval` → fetch (HEAD or `If-None-Match`) → on 200 write `*.tmp` → `fsync` → `rename` → on 304 noop. Watcher (phase-05) picks up rename and triggers ArcSwap.
- Air-gap auto-detect: `refresh.url` absent (None) → file-only mode; watcher still picks up operator drops.
- ETag stored in-memory (not persisted) — restart re-fetches once, accepted cost.
- TorSet = `HashSet<IpAddr>` behind `ArcSwap` for O(1) lookup.
- Content-length sanity bounds: Tor list 10KB–10MB; mmdb 100KB–500MB; iptoasn 1MB–200MB. Outside bounds → reject + warn, keep last good.

## Requirements

### Functional
- `TorExitMatcher::evaluate`: `if tor_set.contains(real_ip) { emit TorExit }`.
- `TorFeed::refresh`: HTTP GET `cfg.tor.refresh.url` w/ `If-None-Match` (if ETag known). 200 → atomic swap; 304 → noop; other → `Err`, keep last good.
- `AsnFeed::refresh` (IPinfo Lite): same pattern, target file path is `cfg.asn.mmdb_path`.
- `IptoasnFeed::refresh`: same pattern for TSV.
- All refresh tasks emit `tracing` events: `relay.intel.refresh{provider, outcome, etag, bytes, duration_ms}`.
- All return `RefreshOutcome { Updated | NotModified | Failed(anyhow::Error) }`.
- Spawn governance: `RelayDetector::start_refresh_tasks(handle: &tokio::runtime::Handle)` returns `Vec<JoinHandle<()>>` so caller can shutdown.

### Non-functional
- HTTP timeout: connect 5s, total 60s (configurable per feed).
- Body streaming → write to tmp file as it arrives; do NOT load all into RAM.
- File ≤200 LOC each.

## Architecture

```
trait IntelProvider {
    fn name(&self) -> &'static str;
    async fn refresh(&self) -> Result<RefreshOutcome>;
}

struct TorFeed {
    url: Option<Url>,
    list_path: PathBuf,
    interval: Duration,
    last_etag: Mutex<Option<String>>,
    http: reqwest::Client,
}

struct AtomicFileSwap;
impl AtomicFileSwap {
    async fn write(&self, target: &Path, body: impl AsyncRead) -> Result<()>;
    // 1. write to target.with_extension("tmp")
    // 2. fsync tmp
    // 3. rename tmp -> target  (atomic on POSIX; fallback documented for Windows)
}
```

## Related Code Files

### Create
- `crates/waf-engine/src/relay/providers/tor_exit.rs` — `TorExitMatcher` + `TorSet` loader
- `crates/waf-engine/src/relay/intel/tor_feed.rs` — `TorFeed: IntelProvider`
- `crates/waf-engine/src/relay/intel/atomic_swap.rs` — generic atomic-write helper
- `crates/waf-engine/src/relay/intel/http.rs` — shared `reqwest::Client` builder w/ timeouts + ETag handling

### Modify
- `crates/waf-engine/src/relay/intel/asn_feed.rs` — implement `IntelProvider::refresh` using `atomic_swap`
- `crates/waf-engine/src/relay/intel/asn_feed_iptoasn.rs` — same
- `crates/waf-engine/src/relay/mod.rs` — `RelayDetector::start_refresh_tasks`

### Verify deps
- `reqwest` (likely workspace dep already — verify; needed with `stream` + `rustls-tls` features only).
- `url` (transitive via reqwest, fine).

## Implementation Steps

1. **`http.rs`** — shared `reqwest::Client` w/ `connect_timeout(5s)`, `timeout(60s)`, `https_only(false)` (Tor URL is HTTPS but ipinfo URL list may be plain). User-agent: `mini-waf/<version>`.
2. **`atomic_swap.rs::write_atomic(target, body_stream, content_length_bounds) -> Result<()>`**:
   - Reject if Content-Length outside bounds before opening tmp file.
   - Stream to `target.tmp`.
   - `tokio::fs::File::sync_all`.
   - `tokio::fs::rename(tmp, target)`.
   - On any error, attempt `remove_file(tmp)` cleanup.
3. **`tor_exit.rs::TorSet::load(path) -> Result<TorSet>`** — read file, one IP per line, skip `#` comments + blank lines, collect into `HashSet`. Reject if size > 1M entries.
4. **`tor_exit.rs::TorExitMatcher`** — holds `Arc<ArcSwap<TorSet>>`; `evaluate` reads `real_ip` from `ctx.derived`, checks set, emits `TorExit`.
5. **`tor_feed.rs::TorFeed::refresh`**:
   - If `url.is_none()` → return `RefreshOutcome::NotModified` (file-only mode).
   - Build request w/ `If-None-Match` if `last_etag`.
   - On 304 → `NotModified`.
   - On 200 → call `atomic_swap::write_atomic` w/ bounds (10KB..10MB). Update `last_etag` from response header.
   - On other → `Failed`.
6. **`asn_feed.rs::IpinfoLiteMmdb::refresh`** — same pattern; bounds 100KB..500MB.
7. **`asn_feed_iptoasn.rs::IptoasnTsv::refresh`** — same pattern; bounds 1MB..200MB; gzip support if URL ends `.gz`.
8. **`RelayDetector::start_refresh_tasks(handle) -> Vec<JoinHandle>`** — for each enabled intel provider, spawn loop: `loop { sleep(interval); match provider.refresh().await { ... log ... } }`. Loop survives `Failed` (warn + continue).
9. **Graceful degradation** — Tor list missing at startup: log WARN, register `TorExitMatcher` w/ empty set; degraded mode does not error.
10. **Unit + wiremock tests** (full coverage in phase-07; smoke tests here).

## Todo List
- [x] `http.rs` shared client builder
- [x] `atomic_swap.rs` w/ bounds + cleanup
- [x] `TorSet` loader (file parser, comment skip, size cap)
- [x] `TorExitMatcher` provider
- [x] `TorFeed::refresh` w/ ETag
- [x] `IpinfoLiteFeed::refresh`
- [x] `IptoasnFeed::refresh` + gzip
- [x] `start_refresh_tasks` runtime spawn
- [x] Air-gap mode (url=None) auto-detect
- [x] Smoke unit tests; full wiremock in phase-07
- [x] `cargo check` + clippy clean

## Success Criteria
- Unit: TorSet parses file w/ 100 IPs + comments correctly; oversize → Err.
- Unit: `TorExitMatcher` w/ `real_ip ∈ set` → emits `TorExit`.
- Unit: `atomic_swap::write_atomic` w/ Content-Length out-of-bounds → Err, no tmp file left.
- Unit: `TorFeed::refresh` w/ url=None → `NotModified` immediately.
- Smoke wiremock: 200 → `Updated` + file exists; 304 → `NotModified`; 500 → `Failed`, prior file untouched.
- File LOC ≤200 each.

## Common Pitfalls
- Windows `rename` not atomic — document; OK for prod (Linux-only target).
- `reqwest` default features pull `native-tls`; force `rustls-tls` to match workspace policy if applicable.
- Forgetting to `fsync` tmp before rename → crash-loss risk.
- Storing ETag persistently is over-engineering — accept cold-start re-fetch (YAGNI).

## Risk Assessment
**High** — feed compromise / wrong list. Mitigated by ETag + content-length bounds + operator override (phase-03) winning over feed.

## Security Considerations
- HTTPS only for refresh URLs (validate scheme at config load).
- No secret logging (ETag is fine; URLs sanitized of any future query-token).
- `rename(2)` ensures readers always see consistent file (per CLAUDE.md SQL-style integrity rule applied to files).

## Next Steps
Phase 05 — wire `notify` watcher to ArcSwap config + Tor + AsnDb pointers.
