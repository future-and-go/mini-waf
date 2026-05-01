# PR #23 — FR-008 Threat-Intel — Adversarial Red-Team Review

**Branch HEAD:** `31b201afedfeda54e4123edaaeacf6a0ed69fcec`
**Reviewer focus:** break it, not bless it. Quality-reviewer handles nits.
**Verdict legend:** ACCEPT = must fix · REJECT = false positive · DEFER = follow-up

Bottom line: **2 CRITICAL** (one is a near-deal-breaker correctness gap), **6 IMPORTANT**, **5 DEFERRABLE**. Code is generally well-defended against the obvious attacks; the failure modes that remain are silent ones.

---

## CRITICAL

### C1. `extra_internal_cidrs` is never consulted in the request hot path — config silently has no effect
**VERDICT:** ACCEPT — security boundary that exists in name only.
**Files:** `crates/waf-engine/src/threat_intel/checker.rs:447,457,706`; `crates/waf-engine/src/threat_intel/state.rs:80`; `crates/waf-engine/src/threat_intel/normalize.rs:68`; `crates/waf-engine/src/threat_intel/mod.rs:39`.

`is_internal_or_special` is `pub`, exercised by `tests/threat_intel_acceptance.rs:383`, and `state.extra_internal` is loaded + reload-aware in `load_extra_internal` / `ReloadSlot::ExtraInternal`. But `ThreatIntelChecker::check()` (lines 497–614) **never** reads `st.extra_internal` and never calls `is_internal_or_special`. The whole field is plumbed into the snapshot then ignored.

Operator effects of this gap:
- A doc-promised security knob (config.rs:874–877: "Additional CIDRs treated as internal/private — ADDITIVE to RFC-defined ranges") does nothing. Operators added it to their TOML; behavior is unchanged.
- No lookup currently classifies an IP as "internal" → no SSRF / origin-leak gating — but FR-008 spec'd this as a hardening lever. Either the spec was de-scoped and the field/loader/reload-slot are dead code (YAGNI), or the integration was forgotten (security gap).

**Attack scenario (silent-misconfig class):** operator sets `extra_internal_cidrs = ["10.42.0.0/16"]` thinking metadata IPs in a private cluster are now treated as internal for some allowlist short-circuit. Nothing changes; the operator believes a hardening control exists where none does.

**Suggested fix:** Pick one. Either (a) rip out `extra_internal_cidrs`, `extra_internal`, `ReloadSlot::ExtraInternal`, `load_extra_internal`, and `is_internal_or_special` (YAGNI; KISS) and remove from docs; or (b) wire it: in `check()`, **before** ip_allow lookup, if `is_internal_or_special(ip, &st.extra_internal)` returns true, return `Pass` (or a documented explicit short-circuit) so an internal-only request is never matched against external blocklists. Whichever is chosen, the field cannot exist as documented-but-inert: that *is* the attack surface (operator confidence > reality).

---

### C2. `list_max_age_hours * 3600` arithmetic is unchecked — operator can crash boot or trigger DoS by config
**VERDICT:** ACCEPT.
**Files:** `crates/waf-engine/src/threat_intel/checker.rs:392, 629`.

```rust
let max_age = Duration::from_secs(config.list_max_age_hours * 3600);
```

`list_max_age_hours: u64` is parsed verbatim from TOML (config.rs:887) and **never validated/clamped** (`ThreatIntelConfig::validate()` at config.rs:934 does not touch it). With `list_max_age_hours = u64::MAX / 3600 + 1`, the multiplication overflows → **panic in debug build / silent wrap to small Duration in release** → freshness check unexpectedly fires Stale on every fresh file → log spam DoS via `tracing::warn!` per file per reload.

Also: `Duration::from_secs(some_huge)` is fine, but a wrap-to-tiny means the freshness "stale" path triggers continuously — not a memory DoS, but a noise DoS that hides real warnings (observability gap).

**Suggested fix:**
1. In `ThreatIntelConfig::validate()`, clamp `list_max_age_hours` to e.g. `[0, 24 * 365]` (1 year) with a `tracing::warn!` on coerce.
2. In checker.rs:392 and 629, use `Duration::from_secs(config.list_max_age_hours.saturating_mul(3600))` to belt-and-suspender against future config-validate regressions.

---

## IMPORTANT

### I1. Multi-source Tor fetch is last-write-wins, not union — a single legitimate small source silently *replaces* the larger one when guard threshold doesn't bite
**VERDICT:** ACCEPT (silent correctness gap that the docs partially acknowledge but the code design hides).
**Files:** `crates/prx-waf/src/main.rs:1701–1719`; `crates/waf-engine/src/threat_intel/checker.rs:735–766`.

The architecture promises "multi-source: redundancy if torproject.org is down, dan.me.uk still feeds the list" (config.rs:691) and the impl docs say "results are union'd" (config.rs:847). But each task calls `replace_tor_exits(new_table)` independently — the **whole slot** is replaced, not unioned. The `MIN_TOR_REPLACE_ENTRIES = 100` guard only blocks tiny lists when the previous list was ≥100; once both sources are healthy, A's 8000 entries are immediately wiped by B's 6000 entries, leaving only B's coverage until A's next refresh. There's no real redundancy — only a window-of-the-most-recent-success.

**Attack scenario (poisoning-via-truthful-data):** attacker compromises one feed (B) so it returns a real-but-trimmed list (subset of B's true exits, still > 100 entries). After every B fetch, the live slot is overwritten with B's curated subset. Tor exits in A's list but not in B's are unblocked. Defenses claim "two sources for redundancy"; reality is "two sources fighting for slot ownership."

The footnote in main.rs:1701–1702 admits this ("operators wanting union semantics should configure a single source pointing at a pre-merged file") — but config.rs:847 contradicts it ("union'd"), and operators reading the config docs will not see the main.rs comment.

**Suggested fix:** Either drop the multi-source feature (KISS — it does not deliver what it promises) **or** change the architecture to per-source slots that are merged on read / on update (each fetcher owns a slot key; checker queries union of all per-source tables). Update config.rs:847 to match the chosen reality. As-is, the surface area is misleading.

---

### I2. `engine.rs` Allow-short-circuit on FR-008 ip_allow / cdn_asn_allow / fqdn_allow bypasses **all** subsequent security checks (rate limiting, rule engine, CrowdSec, etc.)
**VERDICT:** ACCEPT (significant behavior change, possibly intended — but not bounded).
**Files:** `crates/waf-engine/src/engine.rs:333–341, 681–689`.

```rust
if let Some(ti) = self.threat_intel.get()
    && let Some(decision) = translate_threat_intel(ti.check(ctx), ctx)
{
    if !decision.is_allowed() { ... }
    return decision;          // ← Allow path returns from inspect()
}
```

When `ThreatIntelDecision::Allow` is returned (ip_allow CIDR, FQDN allowlist, or CDN ASN match), the engine returns immediately, skipping URL blacklist, CrowdSec, community blocklist, rate limit, sensitive-data, hotlink, and full rule engine. This is much stronger than the existing DB IP whitelist (Phase 1) which only short-circuits when it's an explicit Phase::IpWhitelist match.

**Real attack scenarios:**
1. Operator puts Cloudflare's egress range in `ip_allowlist_files` (common — they trust their CDN). All real attacker traffic transiting Cloudflare bypasses every other WAF rule, including SQLi/XSS rules. (Cloudflare's ranges are also auto-allow'd via cdn_asn_allow — same problem.)
2. Operator allowlists their own bastion IP for ops; bastion is later compromised → attacker has whole-WAF bypass.
3. FQDN allowlist `example.com` matches `Host: example.com` — but ctx.host is *attacker-controlled* (Host header). Path-based attacks against the same FQDN are now uninspected.

The `cdn_asn_allow` documented intent is "prevents legit-traffic blocks" (checker.rs:509) — i.e., letting CDN traffic through the IP/Tor/ASN block phases, **not** through the rest of the WAF. The over-broad Allow short-circuit is dangerous.

**Suggested fix:** Differentiate "skip-the-rest-of-FR-008" from "skip-the-entire-WAF". The cleanest approach: `ThreatIntelDecision::Allow` should signal "FR-008 had no concern, continue pipeline", not "Allow now". Alternatively, return a structured decision (`AllowFromThreatIntel`) and only honor it as Allow at the very last check — but that's invasive. Minimum fix: change cdn_asn_allow to return Pass (it's a **pass-through** — i.e., "don't block here, but other checks still run"), and document explicitly that `ip_allow` is a full WAF bypass.

---

### I3. ip_block path can panic on `label_idx as usize` out-of-bounds is impossible-by-construction, but `as u16` truncation in `load_labeled_ip_slot` is silently wrong above 65k labels
**VERDICT:** ACCEPT (defensive — the `try_from` is correct but the surrounding indexing is not entirely safe).
**Files:** `crates/waf-engine/src/threat_intel/checker.rs:158, 524–529, 562–568`.

`label_idx: u16 = u16::try_from(labels.len())?` — good, errors past 65535. But `*label_idx as usize` is used to index `st.ip_allow.labels.get(...)`. If a slot's `table` carries an index that is somehow wider than its `labels` Vec (e.g., incomplete reload swap, table built from one slot but labels from another), the `.get()` returns None and we fall back to `"ip_allow_file"` — fine. So in practice only `try_from` errors at boot.

But: in `replace_tor_exits` test path (line 977–980), `label_idx = 0u16` is inserted into `tor_exits` table. The `check()` for `tor_exit` (line 588) does `st.tor_exits.longest_match(ip).is_some()` — does NOT use the label. So `tor_exits` is a `LabeledIpTable<u16>` wasting 16 bits per entry across 8k entries (~16 KB). Minor, not security.

Real concern: `parse_ip_list_into` *does not* limit how many entries it inserts. A 10 MB attacker-supplied IP list with millions of /32 entries can OOM the worker. There's `MAX_ASN_BLOCKLIST_BYTES = 10 MiB` for ASN list, but **no equivalent file-size cap for IP list files**. AsnLookup has its own [1 MB, 50 MB] gate; IP list files are unconstrained.

**Attack scenario:** operator-supplied path that is later attacker-writable (e.g., NFS share, supply-chain) replaces `ip_blocklist_files[0]` with a 2 GB file. Watcher fires `reload_slot_lenient(IpBlock)` → `parse_ip_list_into` reads it line by line via BufReader — won't OOM in one shot, but the resulting `IpNetworkTable<u16>` will hold tens of millions of entries → OOM on insertion or massive memory spike. No defensive cap.

**Suggested fix:** Apply the same `metadata.len()` size cap to `parse_ip_list_into` (e.g., 100 MiB hard cap, matching the AsnLookup precedent). Cap entry count too (e.g., 5M entries — an attacker pre-constructing a single-line file with `0.0.0.0/0` + 5M comments would still bypass a size cap; need both axes).

---

### I4. Tor fetcher creates a fresh `reqwest::Client` on **every** fetch — connection-pool churn + fd leak under flapping endpoint
**VERDICT:** ACCEPT (resource hygiene + supply-chain concern).
**Files:** `crates/waf-engine/src/threat_intel/tor_fetcher.rs:29–32`.

```rust
async fn fetch_once(...) -> ... {
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(30))
        .build()?;
    ...
}
```

Each call rebuilds the TLS context + DNS resolver + connection pool. Under fast-flap (initial backoff = 30s clamp; exponential to max 21600s clamp), this can be many hundreds of clients per day across all sources. Each unfinished/aborted client carries TLS session caches and resolver state until dropped. With multiple Tor sources and a recurring 503 from the upstream, a memory & file-descriptor walk-up happens until the next idle reset. Under DNS-resolution failures (TCP socket leaked while resolver retries) this can leak fds.

Also: `reqwest::Client::builder().build()` returns `Result` — currently propagated. Good. But no `redirect_policy` configured → an attacker MITM'ing http://check.torproject.org/torbulkexitlist could 302 → arbitrary URL → request leaks Authorization/Cookie headers (none here, so muted), but the body cap doesn't apply transitively to redirect chains because reqwest's default is to follow 10 redirects.

**Suggested fix:** Build the `reqwest::Client` ONCE in `spawn()` and pass it into `fetch_once` by reference. Add `.redirect(reqwest::redirect::Policy::limited(2))` and `.danger_accept_invalid_certs(false)` (default but explicit). Add `User-Agent` so torproject.org can rate-limit by UA distinctly.

---

### I5. SIGHUP handler `tokio::spawn` is leaked (no Drop / cancellation) — combined with reload_lock contention can hang shutdown
**VERDICT:** ACCEPT (minor).
**Files:** `crates/prx-waf/src/main.rs:1717–1719, 1745–1759`.

Tor fetcher handles: `std::mem::forget(handle)` — explicitly leaked. SIGHUP handler: `tokio::spawn(async move { ... })` with no handle saved at all. Both tasks live forever and only die when the runtime drops. On graceful shutdown (Ctrl-C → tokio runtime shutdown) the SIGHUP handler may be in the middle of `reload_all_lenient()` holding the parking_lot mutex; the runtime's worker thread blocks on the lock waiter while the holding thread is being told to abort. parking_lot's mutexes are not poisoned and will not deadlock at runtime drop, but tests of graceful shutdown will see logs about "task aborted while holding mutex" or hung observers.

**Real concern:** in long-running servers this never matters. But test harnesses that build/drop a `WafEngine` repeatedly will leak tokio tasks (tor fetcher) every time, accumulating fd & memory until the test process exits. CI flake risk.

**Suggested fix:** Track all spawned task handles on the `ThreatIntelChecker` (or engine-level holder) and `abort()` them on drop. Don't leak.

---

### I6. `bypass_throttle: HashMap<(String, String), Instant>` never evicts — operator-controlled growth bound but garbage stays forever
**VERDICT:** ACCEPT (low-impact but unnecessary).
**Files:** `crates/waf-engine/src/threat_intel/checker.rs:385, 471–493`.

The map keys are `(allow_rule_name, block_rule_name)` strings cloned per warn. With N allow labels × M block labels, the steady-state map is N×M entries. Operator-bounded — not attacker-bounded — so technically OK. But no GC ever runs; entries from labels removed by config reload stick.

**Suggested fix:** On insert, if the map exceeds e.g. 1024 entries, do an in-place expiry sweep (drop entries older than 10 minutes). Or use `lru` crate.

---

## DEFERRABLE

### D1. IPv4-compatible IPv6 (`::a.b.c.d`, deprecated RFC 4291 §2.5.5.1) is not canonicalized
**VERDICT:** DEFER.
**File:** `crates/waf-engine/src/threat_intel/normalize.rs:11–40`.

`canonicalize` covers IPv4-mapped, 6to4, NAT64, but not IPv4-compatible (`::a.b.c.d`, deprecated 2006). Most stacks reject these at parse time, but a tolerant proxy that accepts and forwards them will let them slip through the IPv4 blocklist. If the gateway already canonicalizes these (FR-007), this is moot; if not, add the check. Given deprecation and limited attack surface, defer.

**Suggested fix (when addressed):** add to `canonicalize()`:
```rust
// ::a.b.c.d (deprecated IPv4-compatible). All-zero high 96 bits, low 32 = v4.
if s[0..6].iter().all(|&x| x == 0) && (s[6] != 0 || s[7] > 1) {
    return IpAddr::V4(Ipv4Addr::new(...));
}
```
Excluding `::1` and `::`.

### D2. ASN sanity bounds `[1 MB, 50 MB]` and `[100k, 1M]` are reasonable but not aligned with current iptoasn (~6 MB / ~430k rows). A future legitimate iptoasn doubling exceeds 1M rows and breaks boot.
**VERDICT:** DEFER.
**File:** `crates/waf-engine/src/threat_intel/asn_lookup.rs:60, 124`.

The 1M row ceiling will eventually be tight (BGP table doubled in ~10 years; iptoasn rows grow with route deaggregation). Document that operators can override (currently they can't — non-configurable per the comment). When that day comes, add a config knob with safer defaults. Not urgent.

### D3. `parse_ip_list_into` leading-zero guard rejects "0.0.0.0/0" because "0" is a single digit (so the guard skips it correctly), but rejects "010.0.0.1" (good) and **also** "0.0.0.10" (good — single digit "0"). Edge case: "0.0.0.0" passes — but `IpAddr::from_str("0.0.0.0")` succeeds. Wait: re-read: `seg.len() > 1 && seg.starts_with('0')` — "0" has len 1 so passes. "00" has len 2 starts with '0' → rejected. "01" rejected. Correct. No issue.
**VERDICT:** REJECT (was suspicious; on close read, the guard is correct).

### D4. `reqwest 0.13.2` brings default features including `default-tls` (rustls or native-tls depending on platform) — fine. `idna 1.1.0` includes the new transitional/non-transitional ToASCII; `domain_to_ascii` is non-transitional which is what we want (rejects deprecated mappings). No CVE in pinned versions as of cutoff.
**VERDICT:** REJECT — clean as of 2026-04 cutoff.

### D5. Watcher uses `notify::recommended_watcher` (notify 6.1.1) — on macOS this is FSEvents which **coalesces events** during heavy churn. The periodic re-scan safety net mitigates the miss but introduces a 4h max staleness window for missed events. Documented in code (watcher.rs:99–101). Acceptable.
**VERDICT:** DEFER. If mttd matters on macOS, drop to `PollWatcher` with a 30s poll. Not urgent for Linux.

### D6. `replace_tor_exits` `MIN_TOR_REPLACE_ENTRIES = 100` is hard-coded. Newly-bootstrapped Tor list with 50 entries is accepted (test `replace_tor_exits_accepts_legit_list`); but a healthy list that drops to 50 (real Tor network drop) is rejected. Edge case is documented and tested — accept.
**VERDICT:** REJECT.

---

## REJECTED concerns I checked and dismissed

- **Ed25519 `verify_sidecar` TOCTOU**: `fs::read` is atomic from the kernel's view (mmap is single-shot read). The file is closed before the sidecar is opened. An attacker swap mid-read is impossible (read returns the snapshot at open-time). **REJECT.**
- **`signing_required = true` with empty `signing_pins`**: `verify_sidecar` is gated on `!pins.is_empty()` (checker.rs:106, 258). So with `signing_required = true` + empty pins, signature checks are silently **skipped**. Looks like a bug — but config.rs:949–969 validates only pin format, not the (signing_required + empty pins) combination. **Worth flagging — adding to IMPORTANT below as I7.**
- **Sidecar `.sig` replay across versions**: Sig is over file bytes verbatim. A new file = different sig. Old `.sig` won't verify against new file. Version-pinning via metadata not needed. **REJECT.**
- **Empty Tor list 200 OK**: `MIN_TOR_REPLACE_ENTRIES` guard catches it. **REJECT.**
- **TSV with valid headers + attacker rows**: AsnLookup's row-count ≥100k gate plus the hardcoded ASN-0-skip means an attacker would need to inject ≥100k synthetic legitimate-looking rows for a successful supply-chain replace. Plus signing closes this. **REJECT.**
- **Symlink targeting outside config dir**: `fs::read`/`fs::File::open` follow symlinks, so an attacker who can write `lists/blocklist.txt` symlink → `/etc/shadow` could trigger sensitive-file reads via reload. Mitigated by file-system permissions on `lists/`. Out of scope unless threat model explicitly includes "attacker has write to lists/". **DEFER.**

---

## I7 (folded out from rejected list — actually IMPORTANT)

### I7. `signing_required = true` with `signing_pins = []` silently disables verification
**VERDICT:** ACCEPT.
**Files:** `crates/waf-engine/src/threat_intel/checker.rs:106, 258`; `crates/waf-common/src/config.rs:934–971`.

```rust
if signing_required && !signing_pins.is_empty() { verify_sidecar(...) }
```

The check is `&&` — if pins is empty, we just don't verify. Operator config like:

```toml
[threat_intel]
signing_required = true
signing_pins = []
```

Boots successfully and proceeds **with no signature verification at all**. The intent of `signing_required = true` is fail-closed; the impl is fail-open.

**Attack scenario:** operator who turns on `signing_required` thinks they have supply-chain protection. They forgot to add pins (or a config-merge mistake erased them). All file loads succeed unverified.

**Suggested fix:** in `ThreatIntelConfig::validate()`:
```rust
if self.signing_required && self.signing_pins.is_empty() {
    anyhow::bail!("signing_required=true but signing_pins is empty — would silently disable verification");
}
```
This is a textbook fail-open security misconfiguration. Worth pre-merge.

---

## Summary table

| # | Sev | Verdict | Topic |
|---|-----|---------|-------|
| C1 | CRITICAL | ACCEPT | extra_internal_cidrs is dead code at the runtime path |
| C2 | CRITICAL | ACCEPT | list_max_age_hours unchecked multiplication |
| I1 | IMPORTANT | ACCEPT | Multi-source Tor is last-write-wins, not union (docs lie) |
| I2 | IMPORTANT | ACCEPT | FR-008 Allow short-circuits the whole WAF pipeline |
| I3 | IMPORTANT | ACCEPT | No file-size / entry-count cap on IP list files (only ASN) |
| I4 | IMPORTANT | ACCEPT | reqwest::Client built per-fetch (resource churn, redirect policy) |
| I5 | IMPORTANT | ACCEPT | Tor fetcher + SIGHUP handler tasks leaked, no shutdown |
| I6 | IMPORTANT | ACCEPT | bypass_throttle map never evicts |
| I7 | IMPORTANT | ACCEPT | signing_required=true + empty pins silently fails open |
| D1 | DEFERRABLE | DEFER | IPv4-compat IPv6 not canonicalized |
| D2 | DEFERRABLE | DEFER | ASN row count ceiling 1M will eventually pinch |
| D3 | — | REJECT | leading-zero guard correct on inspection |
| D4 | — | REJECT | dep versions clean |
| D5 | DEFERRABLE | DEFER | macOS notify coalescing — periodic rescan covers |
| D6 | — | REJECT | MIN_TOR_REPLACE_ENTRIES tradeoff is documented |

---

## Unresolved questions

1. Is `extra_internal_cidrs` *intended* to be enforced at runtime (C1), or is it leftover plumbing from an earlier spec rev? Plan / spec authority needed before deciding remove vs wire.
2. Is the FR-008 `Allow` short-circuit (I2) intended to bypass the whole WAF, or only the rest of FR-008? Spec amendment needed; behavior change to docs at minimum.
3. Should `signing_required=true && pins.is_empty()` be fail-fast at config load (recommended), or fail-fast at first list-load attempt? The former is better UX; the latter matches "lazy" pattern elsewhere in the codebase.
4. Multi-source Tor (I1): is the documented behavior (union) or the implemented behavior (last-write-wins) the desired one? They diverge.

---

**Status:** DONE_WITH_CONCERNS
**Summary:** PR has solid hardening primitives but ships two CRITICAL silent-misconfig classes (`extra_internal_cidrs` is dead, `list_max_age_hours * 3600` overflows) and a fail-open in `signing_required` with empty pins. Recommend block merge until C1/C2/I7 are resolved.
