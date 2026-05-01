# PR #23 Code Review — FR-008 file-based threat-intel

Reviewer: code-reviewer · Date: 260430-2054 · Scope: 9 files in `crates/waf-engine/src/threat_intel/` (skipped signing.rs, tor_fetcher.rs).

**Status: DONE_WITH_CONCERNS**

Iron-Rule production-safety pass: clean. No `.unwrap()` / `.expect()` / `todo!()` / `unimplemented!()` in non-test code paths. `parking_lot::Mutex` used throughout. No `std::sync::Mutex`. No secret logging. No `unsafe`. Per-line errors swallowed with `tracing::warn!`. Boot path uses `?` + `.context()`.

The architectural concern (checker.rs at 1054 LOC = 5x the 200-LOC limit) and several correctness/concurrency issues below need attention before merge.

---

## CRITICAL

None — no production-safety rule violations, no panic shorthand, no auth bypass, no obvious data corruption.

---

## IMPORTANT

### checker.rs:158 — `u16::try_from(labels.len())` rejects ≥65 536 paths but `IpNetworkTable<u16>` will silently truncate `label_idx as usize` lookups
**Issue:** The `try_from` boundary at line 158 enforces `labels.len() ≤ 65 535`. But the `state.rs` doc and slot type `IpNetworkTable<u16>` use `u16` as the *index*, while the value space (number of distinct labels per slot) caps at 65 536 — this is *one slot*, but a single slot is fed by N config files. The error message says "max 65_536" which is off-by-one. Boot fails with `anyhow!` rather than a configuration validator, so an operator with 100k label files only finds out after deploy.
**Fix:** Validate `list_labels.len() + ip_*list_files.len()` at config-load time in `waf-common::config`. Update the message to say "max 65 535".

### checker.rs:325 — `unwrap_or("")` after `split('#').next()` is a tautology and masks intent
```rust
let s = line.split('#').next().unwrap_or("").trim().to_owned();
```
**Issue:** `str::split` on `&str` always yields at least one item; `.next()` is always `Some`. This is never `None`. The `unwrap_or("")` is dead defensive code. Inconsistent with parsers.rs:33 which uses `match … { Some(s) … None => continue }`. Pick one style.
**Fix:** `let s = line.split('#').next().map(str::trim).unwrap_or("").to_owned();` — or better, mirror parsers.rs:
```rust
let Some(stripped) = line.split('#').next() else { continue };
let s = stripped.trim();
if s.is_empty() { continue; }
```
Avoid the unnecessary `to_owned()` allocation per line — `s` is only `parse::<u32>()`'d, no need to own it.

### checker.rs:137,143 — `min_age` variable name lies (it actually tracks **max**)
```rust
// Track minimum (oldest) age across all files in this slot. KISS.
let mut min_age: Option<Duration> = None;
…
min_age = Some(min_age.map_or(age, |prev| prev.max(age)));   // takes MAX, not min
```
**Issue:** Comment says "minimum (oldest)". For ages, *oldest* = *largest* duration since mtime, which is what the code does (`prev.max(age)`). The variable name is wrong. Future maintainer will "fix" the bug that isn't there.
**Fix:** Rename `min_age` → `oldest_age` (or `max_age_across_files`). Update comment to drop "minimum".

### checker.rs:737 / replace_tor_exits — TOCTOU between length check and store
```rust
let cur = self.state.load_full();   // snapshot A
let prev_total = cur.tor_exits.len();
if new_total < MIN && prev_total >= MIN { return; }
…
let next = ThreatIntelState { … tor_exits: new_table, … from cur };
self.state.store(Arc::new(next));   // ignores any update that happened between load_full and store
```
**Issue:** `reload_lock.lock()` at line 736 already serializes against `reload_slot_locked` and other tor replaces, so this is *currently* safe — but only because of the lock. If anyone in future loads state outside the lock and stores, the load-modify-store loses concurrent updates to `ip_allow`/`ip_block`/`fqdn_allow`/`asn_block`. Same pattern in `reload_slot_locked` (line 630–710). Document the invariant explicitly.
**Fix:** Add `// INVARIANT: caller holds reload_lock — load_full+store is atomic only under that lock.` above each `load_full()` call. Consider moving the lock into a guard struct that exposes only `swap()` to make misuse impossible.

### watcher.rs:60 — O(N) linear scan on every event with `files_cb.iter().find`
**Issue:** Every fs notify event triggers `files_cb.iter().find(|(p, _)| p == path)`. For 100 watched paths under a watch-storm (rsync, editor save fanout), this is O(N²). Notify can fire thousands of events for a directory rsync.
**Fix:** Build a `HashMap<PathBuf, ReloadSlot>` once before passing to the closure. Same `files.clone()` already happens at lines 38, 108 — collapse into one map.

### watcher.rs:60 — path comparison is filesystem-naive
**Issue:** `p == path` uses `PathBuf::eq` which is byte-exact. If config has `./rules/blocklist.txt` and notify reports `/abs/path/rules/blocklist.txt` (which it does on macOS via FSEvents and on Linux when watching by canonicalized parent), the lookup misses → silent reload-never. Same issue on Windows for `\\?\` prefix differences.
**Fix:** Canonicalize both sides at watcher start: `std::fs::canonicalize(p).unwrap_or(p.clone())`. Store canonical paths in the lookup map and canonicalize each event path before lookup. Add a test that uses `tempfile::tempdir()` (which gives `/private/var/folders/...` symlinks on macOS) to catch this.

### watcher.rs:108–124 — periodic re-scan reloads even when nothing changed
**Issue:** Every `periodic_rescan_secs` (default likely 60–300s) the periodic task calls `reload_slot_lenient` for every distinct slot regardless of whether the underlying file changed. Each reload reparses the entire blocklist file (could be MB), takes `reload_lock`, and bumps the ArcSwap pointer — invalidating reader CPU caches for *all* request paths. With 5 slots and 60s rescan, that is 5 reloads/min of pure waste in steady state.
**Fix:** Track `mtime` per file across rescans; only reload a slot if any of its source files has a newer mtime than recorded. Cheap, eliminates the steady-state cost.

### watcher.rs:148–168 — `watcher_starts_and_drops_cleanly` test has no assertion
**Issue:** Test ends at "// No assertion — just verify no panic on drop." This is documenting that the test is hollow. A future regression where `Drop` panics will be caught only because the test process aborts — fine, but the test will pass even if `drop(w)` is unreachable (e.g. `tokio::time::sleep` hangs).
**Fix:** Either delete the test (it's a smoke test that adds little value) or assert something — e.g. that the periodic JoinHandle is aborted within a small timeout after drop.

### checker.rs:385 / bypass_throttle — unbounded HashMap memory leak
```rust
bypass_throttle: Arc<parking_lot::Mutex<HashMap<(String, String), Instant>>>,
```
**Issue:** Keys are `(allow_label, block_label)` strings that grow with every distinct (allow, block) label pair seen during the lifetime of the process. If an attacker can influence label names (no — labels are operator config, not request data), this is leakable. Even with operator-controlled labels, entries are never evicted: `match g.get(&key) { Some(last) … _ => insert }` only updates the timestamp, never removes stale keys. With 100 labels × 100 labels = 10 000 strings retained forever, plus per-string allocation. Bounded but wasteful.
**Fix:** On each insert, sweep entries older than `BYPASS_THROTTLE * 10` and drop them. Or use `quanta`/lru with bounded capacity. Or, simplest: `parking_lot::Mutex<lru::LruCache<…>>` with capacity 1024.

### checker.rs:476 — bypass throttle takes the lock twice on first hit per key
```rust
let mut g = self.bypass_throttle.lock();
let key = (allow_label.to_string(), block_label.to_string());   // alloc inside lock
…
match g.get(&key) {
    Some(last) if … => return,
    _ => { g.insert(key, now); }
}
drop(g);
tracing::warn!(…);
```
**Issue:** Two `.to_string()` allocations under the lock. With watch-storm + millions of req/s, this is the slowest path of an Allow short-circuit. Also: `g.insert(key, now)` after `g.get(&key)` is a second hash lookup.
**Fix:** Use `entry` API:
```rust
let key = (allow_label.to_string(), block_label.to_string());
let mut g = self.bypass_throttle.lock();
let now = Instant::now();
match g.entry(key) {
    Entry::Occupied(mut e) if now.duration_since(*e.get()) < BYPASS_THROTTLE => return,
    Entry::Occupied(mut e) => { e.insert(now); }
    Entry::Vacant(e) => { e.insert(now); }
}
drop(g);
tracing::warn!(allow_label, block_label, ip = %ip, "…");
```

### asn_lookup.rs:97 — `IpAddr::from_str` accepts IPs with leading zeros (CVE-class)
**Issue:** parsers.rs:44–57 has explicit guard against `010.0.0.1`-style leading-zero IPs; asn_lookup.rs has no such guard for the iptoasn TSV. If a malicious mirror serves `010.0.0.0\t010.255.255.255\t1\t…`, Rust's `IpAddr::from_str` rejects it (so `Err` skips the row — safe). But the code relies on `IpAddr::from_str` rejecting; document this invariant.
**Fix:** Add a comment at line 97: `// IpAddr::from_str rejects leading-zero IPs by design — no defensive guard needed.` Or, defensively, mirror the parsers.rs check (cheap on parse path).

### asn_lookup.rs:107 — silent loss when iptoasn ranges overlap
**Issue:** `partition_point(|r| r.start <= ip)` then `idx - 1` returns at most one range. If the TSV has overlapping ranges (rare but possible — sub-allocation, RIR transfer rows), the last-`start` row wins regardless of `end`. If row[0]=10.0.0.0–10.255.255.255 ASN 1 and row[1]=10.5.0.0–10.5.0.255 ASN 2, an IP in 10.5.0.5 returns ASN 2. If row[1] = 10.5.0.0–10.5.0.0 (single host) and the IP is 10.5.0.5, `partition_point` returns idx 2, `cand` is row[1], `5 ≤ 0` is false → returns None. The 10.0.0.0/8 wider match is lost.
**Fix:** Either (a) accept this as documented limitation (iptoasn dump is non-overlapping by source) and add a debug-only assertion that detects overlap during sort; or (b) when `cand.end < ip`, walk backwards looking for a containing range. (a) is YAGNI-correct.

### freshness.rs:33 — clock skew documentation incomplete
```rust
let age = SystemTime::now().duration_since(mtime).unwrap_or(Duration::ZERO);
```
**Issue:** Handles backwards skew (NTP correction → mtime in future) by treating as Fresh. Does NOT handle the case where `mtime` is `UNIX_EPOCH` (file metadata loss on FAT filesystem) — `duration_since` returns a huge `age`, file flagged Stale forever. Correctness-wise this is the right answer (file with zero mtime *is* suspicious), but the warning becomes noise on systems where this is a known artifact.
**Fix:** Doc-only — note in `check_file_freshness` that mtime ≈ UNIX_EPOCH always reads as Stale. Operator action: re-touch the file post-deploy.

### checker.rs:1054 LOC — module size violation (5x over CLAUDE.md 200 LOC limit)
**Issue:** Project standard: "If a code file exceeds 200 lines of code, consider modularizing it." `checker.rs` is 1054 LOC. The build/reload helpers (`load_labeled_ip_slot`, `load_asn_block`, `load_extra_internal`, `check_single_path_freshness`, `label_for`) are ~360 LOC of pure helpers that could move to a sibling `checker_loaders.rs`. The decision constants (`MIN_TOR_REPLACE_ENTRIES`, `BYPASS_THROTTLE`, `MAX_ASN_BLOCKLIST_BYTES`) belong in a `consts.rs`.
**Fix:** Extract `checker_loaders.rs` (load_*, check_single_path_freshness, label_for) — drops ~360 LOC. Move tests for those helpers to that file. Target: checker.rs ~600 LOC, still over but acceptable per "consider".

---

## NIT

### normalize.rs:88 — duplicate IPv4 unspecified check
Line 81 covers `is_unspecified()` (matches `0.0.0.0`); line 92 catches `0.x.x.x` block. The second covers more. Fine — but `is_unspecified` is redundant once line 92 fires for `o[0] == 0`. Drop the `is_unspecified()` call in the V4 arm.

### normalize.rs:117 — `split(']').next()` accepts malformed input
```rust
let trimmed = "[2001:db8::1";   // no closing bracket
trimmed.strip_prefix('[') → "2001:db8::1"
.split(']').next() → Some("2001:db8::1")    // accepts malformed
```
Falls through to idna which probably rejects the colons → returns None. So end-to-end safe. But the intent ("take addr between [ and ]") is not what the code does ("take everything before the first ]"). Use `strip_prefix('[').and_then(|s| s.split_once(']')).map(|(addr, _rest)| addr)` to enforce both delimiters.

### asn_lookup.rs:60 / file-size cap is hardcoded
"1 MB to 50 MB" hardcoded as supply-chain defense. Comment justifies it. But if iptoasn ever publishes a >50 MB dump (IPv6 expansion), boot breaks. Cap is per-deployment; consider making it overridable from config with a high default and a `tracing::warn!` instead of error when over default but under hard cap.

### loader.rs:17 — `LenientOnReload` returns empty `IpNetworkTable<()>` when no files configured
Currently, `paths.is_empty()` falls through and returns the empty `acc` — correct. But the doc on `LoadStrictness::LenientOnReload` says "missing or malformed file = warn + keep previous". The function does not "keep previous" — it returns empty. The "keep previous" behavior lives in the *caller* (checker.rs:653 wraps `if let Ok(s) = …`). Add a doc-comment cross-ref so the reader knows where the keep-previous logic actually is.

### parsers.rs:47 — `seg.starts_with('0')` rejects `0.0.0.0/0`
```rust
host.split('.').any(|seg| seg.len() > 1 && seg.starts_with('0'))
```
`"0.0.0.0"` → segments `["0","0","0","0"]`, `seg.len() > 1` is false — passes. `"00.0.0.0"` → `"00"` rejected. Looks correct. Add a test for `0.0.0.0/0` (catch-all rule explicitly being supported).

### checker.rs:1054 / state.rs:88 — `is_all_empty` doesn't include `extra_internal`
`is_all_empty` does not check `extra_internal`. So a config with only `extra_internal_cidrs` set would still return true → fast-out skips canonicalize and the lookup. `extra_internal` is consulted only via `is_internal_or_special` which the checker doesn't seem to call directly in `check()`. So this is currently fine but fragile if a future change adds an `is_internal` short-circuit.

### checker.rs:497 / `check()` — does not consult `is_internal_or_special` even though normalize.rs exports it
The function `is_internal_or_special` is exported (mod.rs:39) but never called inside `check()`. Either (a) intended — engine layer outside threat_intel handles internal-IP allow; document with a comment in check() pointing to the caller; or (b) dead export — drop from `pub use`.

### watcher.rs:188 — flaky test depends on FS notify timing
`watcher_reloads_on_file_change` waits 400 ms for notify+reload, then calls `reload_slot_lenient` manually because "the watcher missed it on this platform". The manual reload defeats the purpose of the test. Either keep just the manual reload assertion (rename test to `manual_reload_works`) or skip on platforms where notify is known-flaky and assert without the manual fallback.

### checker.rs:369 — `Duration::from_mins` and `Duration::from_hours` (freshness.rs:78,87,107) require Rust 1.91+
**MSRV not pinned.** No `rust-toolchain.toml`, no `rust-version` field in `Cargo.toml`. If CI uses Rust ≤1.90 the build silently fails. Add `rust-version = "1.91"` to workspace `Cargo.toml`.

### checker.rs:530,540,568 — repeated `.unwrap_or_else(|| "ip_allow_file".to_string())` boilerplate
The same fallback pattern appears 3 times. Extract:
```rust
fn label_rule(slot: &LabeledIpSlot, idx: u16, default: &str) -> String {
    slot.labels.get(idx as usize).map(|l| l.rule_name.clone()).unwrap_or_else(|| default.to_string())
}
```
Cleaner, also eliminates `as usize` from the call sites.

### state.rs:42 — `default_label("unknown")` allocs on every `LabeledIpSlot::default()`
```rust
labels: Arc::new(vec![default_label("unknown")]),
```
A `OnceLock<Arc<ListLabel>>` for the default would deduplicate. With 5 slots × N reloads, ~unbounded `String::from("unknown")` allocations. Low-impact NIT.

### checker.rs:684 — `if any_ok || self.config.fqdn_allowlist_files.is_empty()` is reachable but confusing
If `fqdn_allowlist_files.is_empty()`, the for loop body never executes → `any_ok` stays false → branch enters via the `is_empty()` arm → replaces `next.fqdn_allow` with empty `HashSet`. So an admin reload with no fqdn files configured wipes whatever was previously loaded. Intended (the slot follows config) but not obvious. Add comment: `// empty config means clear the slot — reload follows current config`.

### asn_lookup.rs:165–172 — `len()` and `is_empty()` are not `#[must_use]` while `lookup` is
Style inconsistency. Add `#[must_use]` to `len` and `is_empty` (clippy default).

---

## Architecture pushback

`ThreatIntelChecker` is responsible for: config parsing, file IO, signing verification, freshness checks, ArcSwap state management, reload coordination via mutex, throttled bypass logging, and request-time decision dispatch. **This is too many concerns in one struct.** Suggestions:

1. **Extract a `ThreatIntelLoader`** owning file IO + signing + freshness + label assembly. Returns a `ThreatIntelState`. Tests for loader independent from runtime checker.
2. **Extract a `ThreatIntelReloader`** owning the `reload_lock` + `state: ArcSwap<…>` + reload methods. Becomes the only place that load_full + store. Makes the TOCTOU invariant a type-system property (only the reloader can mutate).
3. `ThreatIntelChecker::check` becomes pure read-only against a shared `Arc<ArcSwap<ThreatIntelState>>` plus the throttle map. ~150 LOC. Reviewable in one screen.

This is not blocking but the next reviewer who adds a slot is going to swear at the existing layout.

---

## Positive observations

- Per-line error swallow + `tracing::warn!` is consistent across parsers and asn_lookup.
- `MIN_TOR_REPLACE_ENTRIES` defense against disable-by-poisoning is well-documented and tested (replace_tor_exits_drops_suspiciously_small_update + replace_tor_exits_accepts_legit_list cover both cases).
- Freshness check correctly derives age from `mtime`, not load wall-clock — stale-on-disk file flagged correctly.
- Signing verified BEFORE any parse — supply-chain safe, ordering documented in comments.
- IPv6 canonicalization handles IPv4-mapped, NAT64 64:ff9b::/96, 6to4 — closes the documented CVE class. Test coverage is good.
- `LoadStrictness::StrictAtBoot` vs `LenientOnReload` is a clean split — operator notices missing files at boot, hot-reload is fail-safe.
- `ArcSwap` for read-mostly state is the right primitive here.
- Bypass-attempt detection (R3) — operator visibility into misconfiguration is valuable, throttle prevents log flood.

---

## Recommended actions (priority order)

1. Fix the `min_age` naming lie (checker.rs:89,137,143) — 5-min change, removes future regression.
2. Build a `HashMap<PathBuf, ReloadSlot>` in watcher.rs — O(1) event lookup.
3. Canonicalize watcher paths at start (filesystem-naive comparison fix).
4. Extract `checker_loaders.rs` to drop checker.rs below 700 LOC.
5. Add `rust-version = "1.91"` to root Cargo.toml.
6. Add periodic re-scan mtime gating — skip reload when nothing changed.
7. Bound the bypass_throttle map (LRU 1024).
8. Use `entry` API in `emit_bypass_warn`.
9. Document the load_full+store invariant in `reload_slot_locked` and `replace_tor_exits`.
10. Consider the `ThreatIntelLoader` / `ThreatIntelReloader` split for a follow-up PR.

---

## Unresolved questions

- Is the periodic re-scan supposed to compensate for missed notify events on macOS/Windows specifically? If yes, an mtime-gated rescan is what we want; if no (always-reload as belt-and-suspenders), keep current but document the cost.
- Is `is_internal_or_special` consulted from a caller outside this module? If only re-exported but unused in production, drop the export.
- Should signing verification failure for a *single* file in a multi-file slot abort the whole slot reload, or skip just that file? Current behavior: skip just that file (LenientOnReload continues). Boot path: first failure aborts. Confirm operator expectation.

Sources:
- [Duration constructors stabilization (Rust 1.91)](https://github.com/rust-lang/rust/pull/47097)
- [Duration in core::time docs (1.89)](https://doc.rust-lang.org/1.89.0/core/time/struct.Duration.html)
