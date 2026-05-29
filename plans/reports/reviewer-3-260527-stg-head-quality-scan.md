# reviewer-3 — release/stg HEAD code-quality + security scan

**Branch:** release/stg @ e8331bcb
**Scope:** in-scope per `analysis/requirements.md`, skipping items 70/75/76 + carry-overs #1/#2/#3/#8
**Date:** 2026-05-27

## Iron-rule baseline (Rust 2024 — CLAUDE.md)
- `.unwrap()` in production code: **0** (all matches gated by `#[cfg(test)]` / `tests/` / `conformance*.rs`)
- `.expect()` in production code: **5** — all justified (`BUG:`-prefixed compile-time invariants in
  `sql_injection_patterns.rs:108`, `ssrf_scanners.rs:37`, `tier_policy_registry.rs:90`,
  `response_body_mask_filter.rs:135` (comment only), and the `XSS_SET` fail-open path uses `tracing::error!` + `RegexSet::empty()` instead — clean)
- `todo!()`/`unimplemented!()`: **0** in production paths
- `std::sync::Mutex`: **0** in production paths (all are `parking_lot::Mutex` or `tokio::sync::Mutex`)
- `panic!()` in production: **0**

Iron-rule posture is clean. Findings below are correctness / security / hardening gaps.

---

## CRITICAL

### CR-1 — XFF trust silently honours every peer when `trusted_proxies` list is empty

`crates/gateway/src/ctx_builder/request_ctx_builder.rs:223`

```
let peer_trusted = trusted_proxies.is_empty() || trusted_proxies.iter().any(|net| net.contains(&peer_ip));
```

When the operator enables `trust_proxy_headers = true` but leaves `trusted_proxies = []`
(both defaults to false/empty per `crates/waf-common/src/config.rs:231-232`), the OR-with-`is_empty`
branch trusts the leftmost XFF token from **any** TCP peer — direct-from-internet clients can
spoof `client_ip` to whatever they want. Spoofed `client_ip` then propagates into rate-limit
keys (`rate_limit/check.rs:84`), brute-force counters, risk scoring, and access-control
allow/block tables.

FR mapping: FR-004 (rate limit per IP), FR-007 (XFF validation), FR-008 (whitelist/blacklist),
FR-025 (cumulative risk per IP) — all read from a spoofed client IP under this config.

Iron-rule violation: none — correctness failure of the trust boundary itself.

Recommendation: when `trust_proxy_headers = true` AND `trusted_proxies` is empty, either
**(a) refuse to honour XFF** (fail-secure) and log a single startup warning, or
**(b) reject startup** until the operator enumerates trusted proxies. Both are surgical changes
to the same one-liner.

Solo-loop eligible: **YES** (single-file behavioural fix + targeted unit test).

---

### CR-2 — Admin IP allowlist middleware fails open when `ConnectInfo` is missing

`crates/waf-api/src/security.rs:207-218`

```
let ip = req.extensions()
    .get::<axum::extract::connect_info::ConnectInfo<SocketAddr>>()
    .map_or(IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED), |ci| ci.0.ip());
if !is_admin_ip_allowed(&ip, &state.security_config.admin_ip_allowlist) { ... 403 ... }
```

If the axum router is reached without `ConnectInfo` extension populated (e.g. wrapping by
another upstream proxy, internal `oneshot`, integration code paths), the resolved IP becomes
`0.0.0.0`. Unless `0.0.0.0` is explicitly outside the allowlist, the request passes — bypassing
the allowlist that is the only network control on the admin API.

FR mapping: FR-031 (hot config admin gate), FR-032 (audit log access).

Iron-rule violation: none — fail-open on trust signal absence.

Recommendation: when `ConnectInfo` is absent **and** `admin_ip_allowlist` is non-empty, deny by
default (return 403 + log). Empty allowlist may keep allow-all behaviour.

Solo-loop eligible: **YES**.

---

## IMPORTANT

### IM-1 — `walk()` in JSON field redactor uses unbounded recursion

`crates/gateway/src/filters/response_json_field_redactor.rs:214-243`

`walk()` is recursive (Object → child via `walk(child, ...)`, Array → item via `walk(item, ...)`).
Bound on input depth comes only from `serde_json`'s default `RECURSION_LIMIT=128` in
`from_slice` at line 172, which is not configured here. Worst-case stack is bounded but the
control is implicit — a future change relaxing serde_json parser settings would silently allow
deep nesting to overflow the stack.

FR mapping: FR-034 (response field redaction).

Iron-rule violation: rule #6 (explicit error handling at boundary — implicit dependency on
serde_json's internal default is the problem).

Recommendation: rewrite `walk()` as iterative using an explicit `Vec<&mut Value>` stack, mirroring
`crates/waf-engine/src/checks/body_abuse_walker.rs:99-123` (`walk_count_keys`). Both for
defence-in-depth and to remove the hidden coupling to serde_json's parser config.

Solo-loop eligible: **YES** — single function rewrite + the existing nested-object test asserts behaviour.

---

### IM-2 — `walk_json` in SQLi scanner recurses on parsed bodies bypassing body-abuse depth gate

`crates/waf-engine/src/checks/sql_injection_scanners.rs:58-90`

`scan_json_body` calls `serde_json::from_slice` (line 18) then recurses through `walk_json`.
Unlike the body-abuse check (`body_abuse_walker.rs::precheck_json_depth`), no depth cap is
checked before recursion, AND the SQLi check runs **regardless of whether body-abuse is
enabled** (see `sql_injection.rs:82-100`). An operator who turns off `body_abuse` but leaves
`sqli` on loses the depth pre-check entirely; bound depends on serde_json's 128 default.

FR mapping: FR-013 (SQL injection — JSON body scan), FR-020 (body abuse).

Iron-rule violation: none — defence-in-depth gap.

Recommendation: convert `walk_json` to an iterative stack walk (same pattern as IM-1), or add an
explicit depth counter that bails at `cfg.json_parse_cap`-derived max depth. Same shape applies
to `xss_scanners::scan_json_body_xss` — review for the same pattern.

Solo-loop eligible: **YES**.

---

### IM-3 — Admin UI CSP allows `'unsafe-inline'` AND `'unsafe-eval'` for script-src

`crates/waf-api/src/security.rs:46-51`

```
Content-Security-Policy: default-src 'self'; script-src 'self' 'unsafe-inline' 'unsafe-eval'; style-src 'self' 'unsafe-inline'
```

Both `unsafe-inline` and `unsafe-eval` defeat CSP's main XSS defence. Any reflected/stored XSS
in handlers (`handlers.rs`, `rules_api.rs` returning user-provided rule names, event details,
plugin metadata) would execute. With FR-029 live request feed rendering arbitrary header values
and FR-032 audit-log JSON, the XSS surface is non-trivial.

FR mapping: FR-029 (dashboard live feed), FR-030 (attack viz), FR-032 (audit log viewer).

Iron-rule violation: none — defence-in-depth.

Recommendation: switch the React build to nonce- or hash-based CSP (`script-src 'self' 'nonce-...'`).
Removes `'unsafe-inline'` from inline `<script>` and `'unsafe-eval'` from the runtime. If a
short-term change is preferred, drop `'unsafe-eval'` first — most modern bundlers don't need it.

Solo-loop eligible: **NO** — requires coordinated change to web/admin-panel build to emit nonces.

---

### IM-4 — WebSocket auth never re-validates JWT during connection lifetime

`crates/waf-api/src/websocket.rs:115-176`

`auth_and_upgrade` validates the JWT once at upgrade then `handle_ws` streams forever (line 138
infinite loop, no token check). If the JWT expires, the user role is revoked, or the user is
deleted, the WebSocket keeps streaming audit/security events. JWT default lifetime is 24h
(`auth.rs:41`).

FR mapping: FR-029 (live feed), FR-032 (audit log streaming).

Iron-rule violation: none — auth boundary correctness.

Recommendation: re-validate the JWT on each heartbeat tick (30s, the existing
`ping_interval`). If validation fails, close the socket. Optionally also check
`is_active` on the admin user — for clean revocation.

Solo-loop eligible: **YES** — small change in the `tokio::select!` block.

---

### IM-5 — WebSocket auth does not gate on `role == "admin"`

`crates/waf-api/src/websocket.rs:115`

`validate_access_token` only verifies signature + expiry. The `/ws/events` and `/ws/logs`
streams expose full security event payloads (including PII, attacker IPs, redacted-or-not body
samples). Compare with `logs.rs:88` which gates HTTP log queries on `role == "admin"`. WebSocket
streams have **no role check** — any valid JWT (viewer, future read-only roles) can subscribe.

FR mapping: FR-029 (live request feed), FR-032 (audit log access control).

Iron-rule violation: rule #6 — every sensitive operation must validate authorisation, not just
authentication.

Recommendation: extract a `require_admin_token(token, secret)` helper (lifting `logs.rs::require_admin`'s
role check) and use it in both HTTP audit handlers and the WS upgrade path.

Solo-loop eligible: **YES**.

---

## MODERATE

### MO-1 — `FR-033` per-host hits-counter map has no eviction policy

`crates/gateway/src/filters/response_body_content_scanner.rs:243-268`

```
static HITS: OnceLock<Mutex<HashMap<(String, &'static str), u64>>> = OnceLock::new();
```

`host_label` comes from `HostConfig::host` (proxy.rs:973), so the map is bounded by configured
hosts × 4 categories — **not** by attacker input. The cardinality concern is therefore moderate
not critical. The `String` key allocation per `record_hit` call (one per match) is, however, a
hot-path overhead that already has a deferred Prometheus-TODO at line 242. No correctness bug,
but worth noting.

FR mapping: FR-033 (response body content scan).

Iron-rule violation: none.

Recommendation: as part of the deferred FR-033b Prometheus wiring, switch the key to `(&'static
str, &'static str)` once host_label is interned, or use `DashMap<(Arc<str>, Category), AtomicU64>`
to avoid per-hit string allocation.

Solo-loop eligible: NO — depends on the Prometheus surface decision.

---

### MO-2 — `strip_port` does not handle unbracketed IPv6 with port — silent whitelist miss

`crates/waf-engine/src/checks/header_injection.rs:152-166`

The function returns the original `host` unchanged when `host.matches(':').count() > 1`. An
operator-configured whitelist entry of `::1` matches an inbound `Host: ::1` but **not** the
practical `Host: ::1:8080` (impossible to express without brackets, true) — so this is
defensive at best. Acceptable but worth flagging: if you ever accept unbracketed IPv6
authorities, the whitelist will silently miss.

Iron-rule violation: none.

Recommendation: document the bracket requirement explicitly in `host_inbound_whitelist` config
schema, or reject unbracketed IPv6 Host headers in `is_valid_host_header` (currently they pass
when `host.matches(':').count() == 0 || 1`).

Solo-loop eligible: YES (documentation-only).

---

### MO-3 — Directory traversal pattern TRAV-007 may catch benign request paths

`crates/waf-engine/src/checks/dir_traversal.rs:42`

```
r"(?i)/(etc|proc|var/log|usr/local|root|home|tmp|dev|sys)(/|$)"
```

Matches **any** path beginning with `/home/`, `/sys`, `/etc/...`, `/dev/...`. A legitimate
public route like `/home/user/profile`, `/dev/community`, `/sys/admin/login`, `/tmp/upload`
would all trip TRAV-007. Anti-FP test `allows_benign_passwd_route` only covers `/api/passwd-reset`.

FR mapping: FR-015 (directory traversal).

Iron-rule violation: none — false-positive risk.

Recommendation: anchor TRAV-007 to a context that distinguishes traversal from a normal URL
namespace — e.g. require a preceding `../` segment or `%2e%2e` decoded sequence in the same
target. The other TRAV rules (TRAV-001..004) already require the `..` precondition; TRAV-007
shouldn't fire standalone.

Solo-loop eligible: YES.

---

### MO-4 — `precheck_json_depth` treats `{` inside string literals as nesting

`crates/waf-engine/src/checks/body_abuse_walker.rs:76-93`

Comment at line 73-75 acknowledges this is over-approximation. A legitimate JSON payload
containing the string `{"text": "this {has} 100 braces inside {"}` increments the depth
counter on every `{` byte, regardless of whether it's in a string. With `max_depth = 100`
default, a JSON string body containing ~100 unescaped braces inside a string is rejected.

FR mapping: FR-020 (request body abuse — deeply nested objects).

Iron-rule violation: none — acknowledged trade-off.

Recommendation: accept current behaviour (documented). If false-positives surface in
production, walk strings properly (track `in_string` toggle on `"` not preceded by `\`). Cost
is ~10 lines, low risk.

Solo-loop eligible: YES if FPs surface.

---

### MO-5 — `ws_connections` counter compensates after over-increment

`crates/waf-api/src/websocket.rs:120-128`

`fetch_add` increments unconditionally then compares to `MAX_WS_CONNECTIONS=50` and rolls back
with `fetch_sub`. Under a burst of 100 concurrent connects, the counter briefly spikes to 100
before settling. Standard increment-and-rollback CAS pattern, no correctness issue, but the
gauge briefly lies for monitoring purposes.

FR mapping: FR-032 (dashboard live feed).

Iron-rule violation: none.

Recommendation: switch to CAS loop (`compare_exchange_weak`) if monitoring accuracy of the
gauge matters. Otherwise keep as-is.

Solo-loop eligible: YES.

---

### MO-6 — `ensure_read_only` LogsQL keyword filter is conservative but pipe-only

`crates/waf-api/src/logs.rs:102-122`

The filter only inspects tokens immediately after `|`. A LogsQL expression with a forbidden
keyword *not* preceded by `|` (e.g. an undocumented mutation syntax future-proof gap) would
pass. Conservative whitelist of the **command surface** (rather than blacklist of keywords)
would be more durable. Acceptable for now — VictoriaLogs has no SQL-style DML so the attack
surface is small.

FR mapping: FR-032 (audit log read-only enforcement).

Iron-rule violation: none — depth-of-defence.

Recommendation: stay conservative. When upgrading VictoriaLogs, re-audit the pipe grammar
against `FORBIDDEN_LOGSQL_PIPES`.

Solo-loop eligible: NO — design discussion.

---

## Positive observations

- `url_decode_recursive` (`checks/mod.rs:157`) caps at 3 iterations — bounded by design,
  prevents pathological multi-encoded inputs.
- `request_targets` produces raw + single-decoded + recursively-decoded variants — caught
  `%252e%252e` style evasions consistently across SQL injection / XSS / dir-traversal scanners.
- `extract_client_ip_from_session` correctly defaults `trust_proxy_headers = false`, so the
  XFF-honouring path is opt-in (mitigates CR-1 for the default deployment).
- Response body content scanner has good bounded-regex discipline: every secret pattern has
  `{min,max}` quantifiers, `pattern_within_bounds` rejects unbounded patterns at compile, and
  `MAX_REGEX_LEN = 1024` ≤ straddle tail buffer — chunk-boundary leak primitive closed.
- Iron-rule discipline is consistently observed: every `.expect()` outside tests is either a
  compile-time invariant (`BUG:` prefix) or a documented exception (regex-set fail-open with
  `RegexSet::empty()` instead of panic).
- SSRF check resolves via `url::Url::parse` so the `user@host` userinfo bypass (Capital One
  2019) cannot smuggle a metadata IP through substring matching (`ssrf.rs:49`).

## Metrics

- Files inspected (full read): 12
- Files grep-audited: ~40 (production paths only — `tests/`, `benches/`, `conformance*.rs`
  excluded)
- Production `.unwrap()`: 0
- Production `.expect()`: 5 (all justified)
- `std::sync::Mutex`: 0
- `todo!`/`unimplemented!`: 0
- New CRITICAL findings: **2**
- New IMPORTANT findings: **5**
- New MODERATE findings: **6**

## Unresolved questions

1. **CR-1 fix direction** — fail-secure (silently disable XFF when list empty) vs fail-loud
   (refuse startup)? Hackathon judges may prefer the loud refusal; production deploys often
   need the silent one.
2. **IM-3 CSP scope** — `'unsafe-eval'` requirement comes from the React/AntD bundler or the
   `unsafe-inline` style attributes. Confirm before recommending a Vite config change.
3. **IM-4 / IM-5** — should role checks be done at the route layer (axum middleware) instead
   of inline in each handler? Centralising would simplify both fixes and audit traceability.
