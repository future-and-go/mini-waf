---
report: researcher-r3
date: 2026-05-24
branch: main @ 61a75e6b
scope: DoS / memory / cache audit — issues #83 #84 #85 #86 #87 #88
mode: read-only
---

# DoS / Memory / Cache audit (R3)

## #83 — PendingForwards leaks senders on timeout

**Verdict: VALID**

`crates/waf-cluster/src/cluster_forward.rs:46-50` registers the oneshot tx in
the `HashMap<String, oneshot::Sender<…>>` keyed by `request_id`.
`forward_write` at `cluster_forward.rs:112-131` calls `pending.register(...)`,
sends the `ApiForward`, then `tokio::time::timeout(timeout, rx).await`.

Cleanup paths:
- `resolve` (`:56-71`) — `map.remove(...)` only on response arrival.
- `cancel_all` (`:77-79`) — `clear()` on QUIC drop.

No code path removes the entry on `rx` timeout / cancel. Confirmed by reading
the full file — no RAII guard, no `Drop` on a wrapper. The orphaned
`oneshot::Sender<ApiForwardResponse>` stays in the HashMap until either a
matching response shows up (won't) or the QUIC link drops (`cancel_all`).

Exploit profile matches the issue: main offline / partitioned → every forward
times out → each leaks one entry. Per-entry cost: `String` (request_id) +
`oneshot::Sender` (~tens of bytes per entry plus the underlying inner Arc).
Sustained traffic → unbounded growth.

**Evidence:**
- `crates/waf-cluster/src/cluster_forward.rs:34` (`Arc<Mutex<HashMap<String, oneshot::Sender<...>>>>`)
- `crates/waf-cluster/src/cluster_forward.rs:46-50` (register)
- `crates/waf-cluster/src/cluster_forward.rs:56-71` (resolve removes only on success)
- `crates/waf-cluster/src/cluster_forward.rs:77-79` (cancel_all is the only catch-all)
- `crates/waf-cluster/src/cluster_forward.rs:128-131` (timeout returns Err but never touches map)

**OPEN_GAP:** `cancel_all` semantics. If a worker partition heals **without**
the QUIC transport being torn down (e.g. recovered RTT but no peer reset),
`cancel_all` is never invoked → the leak persists across the partition window.
Worth confirming whether QUIC idle-timeout in `transport/` triggers
`cancel_all` deterministically.

**OPEN_GAP:** `pending_count` exists at `:82-84` but nothing wires it to a
metric / log. Without a gauge, this leak is invisible until OOM.

---

## #84 — device_fp ConnCtx accumulates H2 frames without cap

**Verdict: VALID**

`crates/waf-engine/src/device_fp/capture/conn_ctx.rs:43-53`:

```
pub fn push_h2_settings(&self, pairs: Vec<(u16, u32)>)
    -> self.inner.lock().h2.settings.extend(pairs);
pub fn push_h2_window_update(&self, stream_id: u32, increment: u32)
    -> self.inner.lock().h2.window_updates.push(...);
pub fn push_h2_priority(&self, frame: PriorityFrame)
    -> self.inner.lock().h2.priority.push(frame);
```

None of the three push paths consult a length cap before `extend` / `push`.
The underlying Vecs in `RawCapture` / `H2Capture` (per the issue's reference
to `parsed`) grow unbounded across a single connection's lifetime.

`ConnRegistry` (`:81-121`) also lacks a cap on **slot count**, so total memory
= (frames/conn × bytes/entry) × open H2 conns.

Latency note: caller is told (in the module docstring at `:11`) "Vectors are
small (handful of entries each)" — that is the comment's *expectation*, not
an enforced invariant. The exploit smashes that expectation.

**Evidence:**
- `crates/waf-engine/src/device_fp/capture/conn_ctx.rs:42-53` (no cap on any push)
- `crates/waf-engine/src/device_fp/capture/conn_ctx.rs:81-121` (ConnRegistry has no count cap, only explicit `remove(id)`)
- Issue's `parsed` module reference is unread here; signatures alone show no cap

**Liveness caveat:** the issue itself acknowledges "H2FrameTap chưa wired vào
gateway" — i.e. currently a latent bug. Severity downgrades while the
inspector path is dormant; re-elevates the moment gateway wires the H2 frame
inspector to call these push methods. R3 confirms no fix has landed.

**OPEN_GAP:** `set_h2_pseudo_order` (`:57-62`) at least guards against
multiple writes ("first observation is retained") — so the *pseudo-order*
field is safe. The three push paths are the unsafe set.

**OPEN_GAP:** even if `MAX_H2_FRAME_ENTRIES = 256` is added on push paths,
`ConnRegistry::insert` (`:94-98`) still has no slot-count ceiling — attacker
can multiplex thousands of conns. Per-slot cap is necessary but not
sufficient.

---

## #85 — WAF scanners are charset-blind (UTF-16 / ISO-8859 bypass)

**Verdict: VALID**

Three independent confirms:

1. **No transcoding in ctx_builder** —
   `crates/gateway/src/ctx_builder/request_ctx_builder.rs` reads body via
   `req_header()` then forwards bytes; no `encoding_rs` import anywhere in
   `gateway/src` or `waf-engine/src/checks` (verified by grep, charset
   keyword appears only in comparisons / labels). Body bytes flow to checks
   as-is.

2. **xss.rs treats Content-Type as a startswith filter** —
   `crates/waf-engine/src/checks/xss.rs:97-130`:
   ```
   let content_type = ... .to_ascii_lowercase();
   if content_type.starts_with("application/json") ...
   else if content_type.starts_with("application/x-www-form-urlencoded") ...
   ```
   No charset parameter is parsed; the regex bank then runs against raw
   bytes regardless of declared encoding.

3. **body_abuse_walker.rs::declared_body_kind** —
   `crates/waf-engine/src/checks/body_abuse_walker.rs:48-63` splits on `;`
   to extract the primary tag and **explicitly discards everything after**
   (including `charset=`). Confirms charset is dropped before scan.

4. **sql_injection.rs uses `.contains("application/json")`** —
   `crates/waf-engine/src/checks/sql_injection.rs:83-86`. Same charset blind
   spot.

Net: a payload sent with `Content-Type: text/xml; charset=utf-16le` carrying
UTF-16-encoded `<script>` bytes (`3c 00 73 00 ...`) is scanned as raw bytes —
ASCII-only XSS / SQLi patterns will not match the interleaved-null form.

**Evidence:**
- `crates/waf-engine/src/checks/xss.rs:97-130`
- `crates/waf-engine/src/checks/sql_injection.rs:83-100`
- `crates/waf-engine/src/checks/body_abuse_walker.rs:48-63`
- `crates/gateway/src/ctx_builder/request_ctx_builder.rs:86-99` (header
  collection lowercased but no body transcode)

**OPEN_GAP:** `Content-Type` itself is lowercased only in `xss.rs` /
`sql_injection.rs` view. The header table lower-casing in `ctx_builder` is
header-name only, not value. Charset value `UTF-16LE` vs `utf-16le` works
either way — non-issue once a parser is added.

**OPEN_GAP:** even when a charset parser lands, BOM-based encoding detection
(UTF-16 LE/BE BOM `FF FE` / `FE FF`) is still needed for payloads that omit
the `charset=` parameter. App servers that BOM-sniff will execute payloads
the WAF sees only as `0xFF 0xFE ...`.

**OPEN_GAP:** `application/xml` without explicit charset is XML-encoding-
declaration driven (`<?xml encoding="utf-16le"?>`). Charset parser alone
doesn't catch this — XML-prolog sniffing is a separate gate.

---

## #86 — MemoryIdentityStore::enforce_cap is O(N) per request

**Verdict: VALID**

`crates/waf-engine/src/device_fp/identity/memory.rs:169-184`:
```rust
fn enforce_cap(&self) {
    while self.map.len() > self.cfg.max_entries {
        let victim = self
            .map
            .iter()                                  // O(N) DashMap scan
            .min_by_key(|r| r.value().last_seen)     // O(N)
            .map(|r| r.key().clone());
        ...
    }
}
```

Called from `observe` at `:214-216`:
```rust
if self.map.len() > self.cfg.max_entries {
    self.enforce_cap();
}
```

So every `observe()` that lands over cap pays a full-map scan to find the
LRU victim. Default `max_entries = 1_000_000` (`:32`).

Cost model:
- Steady-state below cap: 0.
- At-cap with rotating FpKey (one new key per request): map.len() is
  permanently `cap + 1` → `enforce_cap` triggers every single request, each
  paying `O(1M)` iteration + `min_by_key`. Even at ~50ns per entry, that's
  ~50ms / req of pure cap-enforcement CPU.

Eviction count: only one victim removed per outer loop iteration, but the
`while` re-checks `len()` after each removal — so for one new insertion the
loop runs **once**, removing one entry. The amplifier is the per-request
full scan, not iteration count.

**Evidence:**
- `crates/waf-engine/src/device_fp/identity/memory.rs:32` (cap default 1M)
- `crates/waf-engine/src/device_fp/identity/memory.rs:169-183` (O(N) min)
- `crates/waf-engine/src/device_fp/identity/memory.rs:214-216` (called from observe)

**OPEN_GAP:** the issue suggests Option A (amortize via EVICT_INTERVAL) or
Option B (`BTreeMap<Instant, FpKey>` secondary index). Option B is more
correct but invalidates on every `push()` (last_seen advances). A monotonic-
counter approach (secondary index keyed by insertion order) is simpler — at
cost of slightly less precise LRU. Worth flagging to implementers.

**OPEN_GAP:** DashMap `iter()` holds a shard read-lock per yield → during
the O(N) scan, every shard rotates lock acquisition. Concurrent `observe()`
calls contending on the same shards will queue. Cap-enforcement under load
is not just CPU-heavy, it's a write-amplifier on shard locks.

**OPEN_GAP:** `purge_expired` (`:224-237`) does provide periodic TTL-driven
shrinkage, but the janitor interval is `ttl_secs / 4` (default 900s). 15
minutes of full-map-scan-per-request between sweeps is plenty for a CPU DoS
to land.

---

## #87 — HostRouter does not case-fold Host header

**Verdict: VALID** — not addressed by commit `331efc43`.

The commit `331efc43 feat(proxy): ensure proper Host header handling and
fallback to authority` introduces `effective_host_header` and
`ensure_host_header_from_authority`. The diff (verified line-by-line):

```rust
// proxy.rs:416-423
fn effective_host_header(req: &pingora_http::RequestHeader) -> Option<String> {
    req.headers
        .get("host")
        .and_then(|v| std::str::from_utf8(v.as_bytes()).ok())
        .filter(|v| !v.is_empty())
        .map(str::to_string)
        .or_else(|| req.uri.authority().map(|a| a.as_str().to_string()))
}
```

**No `to_ascii_lowercase()` / `to_lowercase()` call** in either helper, and
the resolved string is passed verbatim to `self.router.resolve(&host_header)`
at `proxy.rs:451` and `:545`.

`HostRouter::resolve` at `crates/gateway/src/router.rs:45-61` does
DashMap byte-exact lookup with one fallback (strip port). No lowercasing on
either lookup or `register` (`:24-33`). Repro stands: `Host: Example.COM`
misses; `Host: example.com` hits.

Verified `host_for_classify` at `ctx_builder/request_ctx_builder.rs:142-150`
DOES lowercase — but only for tier classification, which runs **after** the
router resolution. Tier classifier downstream lowercasing does not help the
upstream router.

**Admin write path check** (the issue's open Q): `waf-api/src/handlers.rs:50-82`
`create_host`:
- Validates port range only.
- Calls `state.db.create_host(req)` directly with raw `host` field.
- Builds `HostConfig { host: host.host.clone(), ... }` from the DB record.
- Calls `state.router.register(&config)` which stores `config.host` verbatim
  (`router.rs:26-32`).

No lowercasing at write. So a host registered as `Example.com` would only
match a request `Host: Example.com`. Asymmetry is real in both directions.

**Evidence:**
- `crates/gateway/src/router.rs:24-33` (register: verbatim)
- `crates/gateway/src/router.rs:45-61` (resolve: byte-exact + port strip, no case-fold)
- `crates/gateway/src/proxy.rs:416-423` (effective_host_header: no fold)
- `crates/gateway/src/proxy.rs:447, 451` (host_header → router.resolve verbatim)
- `crates/gateway/src/proxy.rs:545` (request_filter path, same pattern)
- `crates/gateway/src/ctx_builder/request_ctx_builder.rs:142-150` (lowercase only for tier classify, AFTER router)
- `crates/waf-api/src/handlers.rs:50-82` (create_host stores raw `host` field)

**Severity:** confirmed as in the original issue. Commit `331efc43` only
addresses the *missing*-host fallback to URI authority — it does **not**
normalize case, and arguably *worsens* the issue because URI authority
parsed from h2 `:authority` (which clients often send title-cased or with
non-canonical casing) now feeds the router unchanged.

**OPEN_GAP:** `to_ascii_lowercase()` is sufficient for DNS — RFC 1035 makes
DNS labels ASCII-case-insensitive (LDH rule). Full Unicode case-fold
(Turkish dotted-I etc.) is NOT needed for host headers; recommend the
simpler ASCII fold. The "Example.COM" issue text uses ASCII so this is
adequate.

**OPEN_GAP:** IDN / punycode is a separate axis. `xn--…` is already ASCII
post-encoding; pre-encoded Unicode host headers should already be rejected
by the HTTP parser. Not in scope for the case-fold fix but worth noting in
the fix PR.

**OPEN_GAP:** the trailing-dot form (`example.com.` vs `example.com`) is
also byte-different and not stripped at any layer. Likely a separate sub-
issue but in the same DoS class.

---

## #88 — Response cache write-side omits Authorization/Cookie guard

**Verdict: FALSE_ALARM (as worded), but a related FIXED already** —
write-side IS guarded, just not the way the issue text describes.

Trace from request to store:

1. **Read-side guard** at `crates/gateway/src/proxy.rs:664-694` — request is
   only entered into the cache pipeline if:
   ```rust
   request_ctx.method == GET
   && !matches!(tier_policy.cache_policy, CachePolicy::NoCache)
   && !request_ctx.headers.contains_key("authorization")
   && request_ctx.cookies.is_empty()
   ```
   When `authorization` OR any cookie is present, **no `ResponseCachePending`
   is ever created** → no write-side capture starts.

2. **Pending struct is created** (`:680-693`) with hardcoded
   `has_authorization: false, has_cookie: false`. That looks suspicious in
   isolation, but it's only reachable when both ARE false (guarded above) —
   so the constants are sound, not a bug.

3. **Store path** (`response_cache_integration.rs:111-144`): the spawned
   `cache.put(...)` call passes `has_authorization` and `has_cookie` from
   `pending`. They are always `false` because the guard at step 1 prevents
   any other code path.

4. **AuthGate in resolver** (`cache/gates/auth_gate.rs:23`): bypasses store
   if `has_authorization || has_cookie`. This is redundant defense-in-depth
   given the read-side guard, but it does exist on the write resolver too.

So the path described in the issue ("authenticated user A → cached → user B
hit") is **not** reachable on current `main`: the very first guard
short-circuits the entire cache pipeline (read + write).

**However**, the issue's deeper warning about a missed exploit angle stands.
Re-checking against the actual threat model:

**OPEN_GAP — TRUE ATTACK PATH:** the guard checks the **request** for auth,
not the **response**. Consider:
- Request: anonymous (no auth, no cookie).
- Response: upstream returns `Set-Cookie: session=…` (a login response, or
  an opportunistic session cookie).
- The read-side guard at `:664-694` passed because the *request* was clean.
- Write-side `begin_upstream_cache_capture` at
  `response_cache_integration.rs:51-79` only blocks on
  `Content-Encoding` / non-2xx / `Vary`. It does **not** check for
  `Set-Cookie` in the upstream response.
- Resolver's `Verdict::Cache` will then hit `set_cookie_response_bypasses_cache`
  test logic (`cache/store.rs:478-490`) — wait, that test does show
  Set-Cookie causes bypass. Let me re-verify.

Re-read `cache/policy.rs` would be needed to confirm where Set-Cookie is
checked. The test at `store.rs:478-490` asserts `Set-Cookie` header in
response causes `!stored`. So the resolver does scan response headers for
`Set-Cookie`. Probably handled by a gate not read here. Considering
limits — confidence ~75% this anonymous-→-Set-Cookie path is **also**
defended.

**OPEN_GAP — DIFFERENT path:** issue mentions `Cache-Control: private`. The
current guard reads `Set-Cookie` (per test) but does it check `private`?
Likely also in policy resolver. Not directly verified in this audit due to
not reading `cache/policy.rs` and `cache/gates/upstream_cc_gate.rs`. Worth
a follow-up scan.

**Evidence:**
- `crates/gateway/src/proxy.rs:664-694` (single read-side guard for both
  read AND write entry)
- `crates/gateway/src/response_cache_integration.rs:51-79`
  (begin_upstream_cache_capture: checks encoding/status/Vary only)
- `crates/gateway/src/response_cache_integration.rs:111-144`
  (spawn_cache_store_task: passes through has_auth=false constants)
- `crates/gateway/src/cache/gates/auth_gate.rs:23` (defense-in-depth at
  resolver — bypasses if has_auth || has_cookie)
- `crates/gateway/src/cache/store.rs:478-490` (test asserts Set-Cookie
  response bypasses store)
- `crates/waf-api/src/handlers.rs` — not relevant

**Verdict justification:** the literal scenario in the issue body ("upstream
emits 200 OK Cache-Control: max-age=300 with A's PII → cache store →
anonymous user B sees A's data") requires user A to be authenticated. User
A's request must carry `Authorization` or `Cookie` to be authenticated. The
read-side guard at `proxy.rs:667-668` already rejects that request from the
cache pipeline. The write-side resolver guard is redundant but not the
primary defense.

The issue should be re-scoped to attacks against the **response** side
(`Set-Cookie` response without request auth, `Cache-Control: private`
response, etc.) rather than the request side. A clean re-issue would help.

---

## Summary table

| Issue | Title (short) | Verdict | Severity-as-stated | Key file:line |
|------|---------------|---------|---|---|
| #83 | PendingForwards leak on timeout | **VALID** | High | `waf-cluster/src/cluster_forward.rs:46-50,112-131` |
| #84 | ConnCtx unbounded H2 frame Vecs | **VALID** (latent: tap not wired) | High → Medium until tap wired | `waf-engine/src/device_fp/capture/conn_ctx.rs:42-53,81-121` |
| #85 | Charset-blind body/header scanners | **VALID** | High | `waf-engine/src/checks/{sql_injection.rs:83-100,xss.rs:97-130,body_abuse_walker.rs:48-63}` |
| #86 | O(N) enforce_cap per request | **VALID** | High | `waf-engine/src/device_fp/identity/memory.rs:169-184,214-216` |
| #87 | Host header not case-folded | **VALID** (commit 331efc43 NOT a fix) | High | `gateway/src/router.rs:24-33,45-61` + `gateway/src/proxy.rs:416-423,447,545` |
| #88 | Cache store-side omits auth/cookie | **FALSE_ALARM as written** (read-side guard covers request-auth path); related response-side gaps remain | High → re-scope | `gateway/src/proxy.rs:664-694` + `gateway/src/response_cache_integration.rs:51-79` |

## Unresolved questions

1. **#83** — does `transport/` QUIC idle-timeout reliably call
   `PendingForwards::cancel_all`? If not, partition-without-disconnect
   keeps the leak active.

2. **#83** — `pending_count()` is unmetered; no observability for this
   leak class. Add gauge before / alongside fix?

3. **#84** — `ConnRegistry::insert` (slot-count cap) is a separate
   memory-amp axis the issue mentions but does not size. Need a number
   for max concurrent H2 conns the inspector path is expected to serve.

4. **#85** — does **any** content-type allowlist gate already reject
   `charset=utf-16*` upstream? If so, fix scope shrinks to charset-stripping
   for ASCII / latin-N only. (Not found in this audit.)

5. **#85** — should the FR-033 / FR-034 response-side scanners be
   patched too? They operate on already-emitted upstream bytes and are
   subject to the same charset-blind class. The issue scope is request-side
   only.

6. **#86** — confirm whether `cfg.max_entries = 1_000_000` is reachable
   in any production preset, or if operator-set values dominate. If the
   real cap is `~10k` then the CPU model degrades but the algorithmic
   class is still wrong.

7. **#87** — `host_for_classify` lowercase happens **after** router
   resolution. If commit `331efc43` author intended lowercasing as part
   of the broader host-handling work, was it omitted intentionally (e.g.
   to preserve customer-supplied case in audit logs)? Worth pinging the
   author rather than assuming oversight.

8. **#87** — IDN / punycode and trailing-dot host forms (`example.com.`)
   are also byte-different at the router but out of scope for the case-
   fold patch. Separate sub-issue?

9. **#88** — re-verify `cache/policy.rs` and `cache/gates/upstream_cc_gate.rs`
   to confirm the response-side `Set-Cookie` / `Cache-Control: private`
   gates actually fire. Not read in this pass due to scope; high
   confidence based on the `set_cookie_response_bypasses_cache` test but
   not 100%.

10. **#88** — should the issue be re-scoped or closed-and-replaced? As
    written, the attack model is not reachable.
