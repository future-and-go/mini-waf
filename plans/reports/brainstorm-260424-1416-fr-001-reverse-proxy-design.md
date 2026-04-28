# FR-001 Full Reverse Proxy — Design Doc

**Date:** 2026-04-24
**Source:** `analysis/requirements.md` FR-001
**Scope confirmed with user:** HTTP/1.1 + HTTP/2 + HTTP/3 + WebSocket; XFF-based client IP; block WAF-identifying headers, internal-ref leaks, preserve backend headers byte-identical.

---

## 1. Problem Statement

FR-001 requires a **full reverse proxy** where:
- **All** requests/responses pass through the WAF (no bypass, no selective inspection).
- **Backend is unaware** of the WAF (transparent at the application layer).

Acceptance row in requirements is one sentence. This doc decomposes it into verifiable sub-criteria and maps each to code.

---

## 2. Decomposed Acceptance Criteria (AC-Matrix)

| # | Criterion | Verify method |
|---|-----------|--------------|
| AC-01 | All HTTP methods proxied (GET/POST/PUT/DELETE/PATCH/OPTIONS/HEAD) | Per-method integration test |
| AC-02 | Request body streams end-to-end (small, large, chunked, multipart) | Upload 1 KiB, 1 MiB, 100 MiB; chunked TE |
| AC-03 | Response body streams end-to-end (fixed-length, chunked, SSE) | SSE 60s, chunked transfer, 1 GiB file |
| AC-04 | Headers preserved byte-identical (order + casing where protocol allows) | Diff backend vs client capture |
| AC-05 | Status codes preserved (1xx–5xx including 100-continue, 101 switching) | Synthetic backend returns each class |
| AC-06 | Query + path params untouched | Fuzz: unicode, %-encoded, `+` vs space |
| AC-07 | Keep-alive + connection reuse works | `curl --http1.1 -v` multi-request, h2 stream |
| AC-08 | HTTP/1.1 | Baseline |
| AC-09 | HTTP/2 (h2c + h2 over TLS) | Force `--http2`, multiplex test |
| AC-10 | HTTP/3 / QUIC | Force `--http3`, Alt-Svc advert |
| AC-11 | WebSocket upgrade + bidirectional frames | `wscat` echo, 10-min idle |
| AC-12 | Backend sees **real client IP** via `X-Forwarded-For` | Backend logs IP, compare to curl source |
| AC-13 | `X-Forwarded-Proto`, `X-Forwarded-Host`, `X-Real-IP` populated | Header inspection |
| AC-14 | Existing XFF chain **appended, not replaced** | Chain 2 WAFs; expect `client, waf1` |
| AC-15 | No WAF-identifying headers leak (`Via`, `Server: prx-waf`, `X-Powered-By-WAF`, etc.) | Response header diff |
| AC-16 | Backend `Server` header either passes through untouched OR is stripped (no substitution) | Test both modes |
| AC-17 | No internal backend hostname/IP in response **body** (HTML abs-URLs, JSON `self` links) | Body scan for `10.0.*`, backend FQDN |
| AC-18 | `Location` redirect rewriting — internal URLs rewritten to public | 302 to `http://backend:8080/x` → `https://public/x` |
| AC-19 | Error pages do not expose WAF (Pingora default error pages replaced) | Trigger 502/504, inspect body |
| AC-20 | Hop-by-hop headers correctly handled (`Connection`, `TE`, `Upgrade`, `Keep-Alive`) per RFC 7230 | Test each |
| AC-21 | Timing overhead p99 ≤ 5ms (links NFR, but user-observable transparency) | `wrk` + histogram |
| AC-22 | Every request reaches WAF inspection — **no bypass path** | Assert counter == request count under load |
| AC-23 | Client TLS terminates at WAF; backend connection independent | tcpdump backend link |
| AC-24 | Client disconnect mid-request doesn't crash or leak connections | Abort test |
| AC-25 | Backend sees `Host` header per configured policy (preserve client Host vs rewrite to backend) | Config-driven test |

**25 sub-criteria.** All must pass for FR-001.

---

## 3. Gap Analysis vs Current `crates/gateway/src/proxy.rs`

| AC | Status | Evidence / Gap |
|----|--------|----------------|
| AC-01..08 | **Likely PASS** | Pingora handles method/body/headers/status/keep-alive/h1 natively |
| AC-09 h2 | **UNKNOWN** | Need to confirm listener bound with h2 ALPN in `prx-waf` main |
| AC-10 h3 | **PARTIAL** | `http3.rs` exists — verify it routes through same `WafProxy::request_filter` |
| AC-11 WebSocket | **GAP** | No `Upgrade`-aware branch in `proxy.rs`; Pingora supports it but needs explicit wiring + verify WAF inspects handshake, not frames |
| AC-12 XFF injection | **GAP** | `extract_client_ip` *reads* XFF (line 57–81) but I see **no code that writes** `X-Forwarded-For` to the upstream request. Backend likely sees only WAF's IP. |
| AC-13 XFProto/Host/Real-IP | **GAP** | Not set |
| AC-14 XFF append | **GAP** | Depends on AC-12 fix |
| AC-15 Via/Server leak | **GAP** | No `upstream_response_filter` / `response_filter` stripping Pingora-default `Server` or `Via` |
| AC-16 Server passthrough | **GAP** | Same — no response header filter |
| AC-17 Body internal-ref leak | **GAP** | No body-rewrite pipeline (ties to FR-033 outbound filter) |
| AC-18 Location rewrite | **GAP** | No redirect rewriter |
| AC-19 Error-page fingerprint | **GAP** | `session.respond_error(200)` and `ResponseHeader::build` use Pingora defaults — fingerprintable |
| AC-20 Hop-by-hop | **UNKNOWN** | Pingora likely correct; verify `Upgrade` not stripped in WS path |
| AC-21 p99 ≤ 5ms | **TBD** | Benchmark required |
| AC-22 No bypass | **RISK** | `request_filter` returns `Ok(false)` on `ctx.request_ctx == None` (line 188). A request with no upstream resolution skips WAF. Confirm unreachable or patch. |
| AC-23 TLS term | **Likely PASS** | `ssl.rs` + `HttpPeer::new(.., use_tls, ..)` |
| AC-24 Abort | **UNKNOWN** | Pingora handles; add explicit test |
| AC-25 Host policy | **GAP** | `host_config` has `remote_host` but no clear preserve-vs-rewrite flag on the outgoing `Host` header |
| Bug | **BUG** | `is_tls: false` hardcoded at `proxy.rs:125` — WAF rules keyed off `is_tls` are blind for HTTPS |

**Verdict:** ~12 of 25 criteria have real gaps. FR-001 is **not currently passing**.

---

## 4. Design — What Needs to Exist

### 4.1 Request-side transforms (new filter: `upstream_request_filter`)

```
on upstream_request_filter(session, upstream_req, ctx):
    client_ip = ctx.request_ctx.client_ip         // real client, already resolved
    peer_ip   = session.client_addr peer IP       // immediate hop
    // AC-12/14: append-not-replace
    existing = upstream_req.headers.get("x-forwarded-for")
    new_xff  = existing ? f"{existing}, {peer_ip}" : f"{client_ip}"
    upstream_req.insert_header("x-forwarded-for", new_xff)
    // AC-13
    upstream_req.insert_header("x-real-ip", client_ip)
    upstream_req.insert_header("x-forwarded-proto", ctx.is_tls ? "https" : "http")
    upstream_req.insert_header("x-forwarded-host", session.req_header().host)
    // AC-25: Host policy
    if host_config.preserve_host:
        pass   // leave as client sent
    else:
        upstream_req.insert_header("host", host_config.remote_host)
    // strip hop-by-hop we must not forward (AC-20)
    for h in ["proxy-connection", "te", "transfer-encoding"]:
        ...handle per RFC 7230
```

### 4.2 Response-side transforms (new filter: `upstream_response_filter` + `response_body_filter`)

```
on upstream_response_filter(session, upstream_resp, ctx):
    // AC-15: strip WAF/proxy fingerprint
    upstream_resp.remove_header("via")
    // AC-16: user-chosen — either passthrough or strip backend Server
    if config.strip_server_header:
        upstream_resp.remove_header("server")
    // AC-18: rewrite Location if internal
    if loc = upstream_resp.headers.get("location"):
        rewritten = rewrite_internal_to_public(loc, host_config)
        upstream_resp.insert_header("location", rewritten)
    // never add WAF-identifying header

on response_body_filter(session, body_chunk, eos, ctx):
    // AC-17: scan + mask internal hostnames/IPs
    // bounded by outbound-filter budget; tie into FR-033
    body_chunk = mask_internal_refs(body_chunk, host_config.internal_patterns)
```

### 4.3 Error-page override (AC-19)

Replace `session.respond_error` with a **neutral** page:
- Status 502/503/504 → generic HTML or JSON per `Accept` header
- No `Server: Pingora` default
- No stack frames

### 4.4 Protocol listeners (AC-08/09/10/11)

Confirm `prx-waf` main registers:
- H1 listener (port 16880)
- H2 listener with ALPN (port 16843)
- H3/QUIC listener (UDP 16843) — `http3.rs`
- WebSocket: ensure Pingora `Upgrade` passthrough is on **and** WAF still sees the handshake request

All four paths **must** flow through `WafProxy::request_filter`. Regression test: counter increment per protocol.

### 4.5 No-bypass invariant (AC-22)

Patch `request_filter`:
```
let request_ctx = ctx.request_ctx.as_ref()
    .ok_or_else(|| pingora err "WAF context missing — refusing request")?;
```
Fail-closed if the upstream resolver somehow didn't populate ctx. No silent `Ok(false)`.

### 4.6 `is_tls` fix (bug)

`build_request_ctx` must set `is_tls` from session digest:
```
is_tls: session.digest().and_then(|d| d.ssl_digest).is_some()
```

---

## 5. Test Plan — How We Prove Each AC

**Harness:** `crates/gateway/tests/fr001_*.rs` + an `httpbin`-style synthetic backend + `reqwest` / `h2` / `quiche` / `tokio-tungstenite` clients.

1. **Per-method matrix** — AC-01
2. **Body size sweep** (1 KiB / 1 MiB / 100 MiB / chunked / multipart) — AC-02
3. **Response shapes** (fixed / chunked / SSE / 1 GiB file) — AC-03
4. **Header fidelity** — capture at synthetic backend, diff against client send — AC-04
5. **Status sweep** (backend returns 100/101/200/204/301/304/400/404/500/502/504) — AC-05
6. **URL fuzz** (unicode, %-encoding, `+`) — AC-06
7. **Connection reuse** — `wrk -c1 -t1` N requests, one TCP conn — AC-07
8. **Protocol matrix** — 4 clients hitting same endpoint, compare response — AC-08..11
9. **XFF semantics** — direct client, 1-hop, 2-hop (WAF chained behind another WAF) — AC-12..14
10. **Leak scan** — regex `Server|Via|X-Powered-By|backend\.internal|10\.0\.` on response headers+body — AC-15..18
11. **Error page** — hit a closed backend → inspect body contains **no** "Pingora" / stack — AC-19
12. **Hop-by-hop** — send `Connection: close, X-Custom`, verify `X-Custom` also stripped per `Connection` list — AC-20
13. **Bench** — `wrk -c100 -t4 -d60s` with latency histogram — AC-21 (p99 ≤ 5ms overhead vs direct-to-backend)
14. **No-bypass** — induce null `ctx.request_ctx` (if reachable) → must 5xx, never forward — AC-22
15. **TLS term** — `openssl s_client` WAF, plain tcpdump backend — AC-23
16. **Abort** — client `curl --max-time 0.1` mid-upload, assert no goroutine/thread leak (100 iterations) — AC-24
17. **Host policy** — both modes flagged via `host_config.preserve_host` — AC-25

All 17 test groups must be green for FR-001 ✅.

---

## 6. Risks

| Risk | Impact | Mitigation |
|------|--------|-----------|
| Body rewriting (AC-17) blows NFR latency budget | Perf fail | Stream-process with bounded regex; only enable per-tier |
| WS frames bypass WAF (only handshake inspected) | Security fail | Accepted per scope; document explicitly; rate-limit per conn |
| HTTP/3 code path diverges from H1/H2 filter chain | FR-001 fail silently | Single shared `WafProxy` trait impl; integration test per listener |
| `preserve_host` breaks backends with vhost routing | Prod fail | Config default = preserve; opt-in rewrite |
| XFF spoofing (client sends XFF on direct connection) | Client-IP lie → rule bypass | Already handled via `trusted_proxies` gate (proxy.rs:64–78) |

---

## 7. Success Metrics

- 25/25 AC-Matrix items green in CI
- p99 overhead ≤ 5ms at 5k req/s (shared with NFR-Perf)
- Zero identifying headers/body refs in leak-scan output
- Backend access-log shows **client IP**, not WAF IP, across ≥ 95% of test requests

---

## 8. Next Steps

1. Confirm design with user (this doc)
2. Run `/ck:plan` to decompose into phased implementation tasks
3. Prioritize: **AC-12/14 (XFF injection)**, **AC-15 (leak headers)**, **AC-22 (no-bypass)**, **is_tls bug** — these are the highest-value gaps
4. Defer AC-17 body-rewrite to FR-033 phase (overlapping scope)

---

## 9. Unresolved Questions

1. Does FR-001 require WS **frame-level** inspection, or is handshake-only inspection acceptable? (Spec silent; scope impact significant)
2. `preserve_host` default — preserve (transparent) or rewrite (safer vhost collapse)?
3. AC-16: strip backend `Server` header yes/no — hides backend tech but breaks byte-identical preservation (AC-04 tension)
4. For HTTP/3, does the Attack Battle traffic actually negotiate QUIC, or is scoring H1/H2 only?
5. Error-page format — HTML, JSON, or content-negotiated? No requirement line specifies.
