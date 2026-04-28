# Phase 02 — Request-side Transforms

## Context Links
- Design doc §4.1
- Phase 01 (filter pipeline + ctx builder)
- ACs: AC-12 XFF inject, AC-13 X-Forwarded-Proto/Host/Real-IP, AC-14 XFF append, AC-20 hop-by-hop, AC-25 Host policy

## Overview
- **Priority:** P1
- **Status:** pending
- **Description:** Implement five request filters + one Host policy strategy. All run inside `upstream_request_filter` via the chain from phase-01. Backend sees real client IP, correct forwarded metadata, hygienic hop-by-hop headers, and the configured Host value.

## Key Insights
- XFF must **append** when peer is a trusted proxy already adding XFF; otherwise **set** to client IP. The `extract_client_ip` logic already separates trusted vs untrusted peer — reuse that signal.
- `Host` policy is per-host-config; default = preserve (open Q answered: transparent default).
- Hop-by-hop list per RFC 7230 §6.1: `Connection, Keep-Alive, Proxy-Authenticate, Proxy-Authorization, TE, Trailer, Transfer-Encoding, Upgrade`. Plus any header named in the request's `Connection:` token list (per-message hop-by-hop). **Exception:** `Upgrade` for WebSocket must survive — gate by detection.

## Requirements
**Functional**
- `X-Forwarded-For`: append peer IP if header exists; else set to client IP.
- `X-Real-IP`: set to resolved client IP (overwrite).
- `X-Forwarded-Proto`: `https` if `ctx.is_tls`, else `http`.
- `X-Forwarded-Host`: original `Host` header.
- Host policy: `HostHeaderPolicy::Preserve` leaves request `Host` untouched; `Rewrite(target)` sets `Host: <remote_host>`.
- Hop-by-hop hygiene: strip standard list **and** Connection-token-named headers. Preserve `Upgrade` + `Connection: upgrade` when WS handshake detected (`Upgrade: websocket`).

**Non-Functional**
- Each filter file ≤ 100 LoC.
- Pure functions on `&mut RequestHeader` for unit testability.

## Architecture
**Pattern application**
- *Strategy* (`HostHeaderPolicy` enum + impl) keyed off `HostConfig.preserve_host` flag (NEW field).
- *Pipeline*: filters registered in this order — `xff → real-ip → forwarded-proto → forwarded-host → host-policy → hop-by-hop-hygiene`.

**Data flow**
```
upstream_request_filter(req):
  for f in request_chain:
      f.apply(req, fctx)?
  // req now has correct forwarded headers + clean hop-by-hop
```

## Related Code Files
**Create**
- `crates/gateway/src/filters/request-xff-filter.rs`
- `crates/gateway/src/filters/request-real-ip-filter.rs`
- `crates/gateway/src/filters/request-forwarded-proto-filter.rs`
- `crates/gateway/src/filters/request-forwarded-host-filter.rs`
- `crates/gateway/src/filters/request-hop-by-hop-filter.rs`
- `crates/gateway/src/policies/host-header-policy.rs`

**Modify**
- `crates/gateway/src/proxy.rs` — register filters into `request_chain`
- `crates/gateway/src/filters/mod.rs` — pub mod
- `crates/gateway/src/policies/mod.rs` — pub mod
- `crates/waf-common/src/lib.rs` (or wherever `HostConfig` lives) — add `preserve_host: bool` (default true)

## Implementation Steps
1. Add `preserve_host: bool` to `HostConfig` (default = true). Update existing constructors / serde defaults.
2. Implement `HostHeaderPolicy` strategy: enum `Preserve | Rewrite(String)`; `apply(&self, req: &mut RequestHeader)`.
3. Implement `RequestXffFilter`:
   - Read existing `X-Forwarded-For`.
   - If present → append `, {peer_ip}`.
   - If absent → set to `{client_ip}` (resolved client, not peer — AC-12).
4. Implement `RequestRealIpFilter` — overwrite `X-Real-IP` with `client_ip`.
5. Implement `RequestForwardedProtoFilter` — set from `fctx.is_tls`.
6. Implement `RequestForwardedHostFilter` — copy original `Host` (read once before host-policy mutates it).
7. Implement `RequestHopByHopFilter` — strip RFC 7230 list + Connection-tokens; preserve `Upgrade` if `Upgrade: websocket`.
8. Wire registration in `WafProxy::new` (or a `build_request_chain(host_config)` factory).
9. Unit tests per filter using a stub `RequestHeader` builder — no Pingora session needed.
10. Integration test (in phase 06) chains XFF through 2 hops.

## Todo List
- [ ] `HostConfig.preserve_host` field
- [ ] `HostHeaderPolicy` strategy + tests
- [ ] `RequestXffFilter` + tests (set, append, multi-hop)
- [ ] `RequestRealIpFilter` + tests
- [ ] `RequestForwardedProtoFilter` + tests (TLS on/off)
- [ ] `RequestForwardedHostFilter` + tests
- [ ] `RequestHopByHopFilter` + tests (Connection-token names, Upgrade preservation)
- [ ] Register all in chain
- [ ] Unit coverage ≥ 95% on the six new files

## Success Criteria
- AC-12: backend mock receives `X-Forwarded-For: <client-ip>` matching curl source IP.
- AC-13: backend mock receives all three forwarded headers populated.
- AC-14: chained-WAF test shows `X-Forwarded-For: client, waf1` (append).
- AC-20: client `Connection: close, X-Custom` → `X-Custom` stripped at backend; WS Upgrade preserved.
- AC-25: both `preserve_host=true` and `false` modes verified by config-driven test.

## Risk Assessment
| Risk | Likelihood | Impact | Mitigation |
|------|-----------|--------|-----------|
| Stripping `Upgrade` breaks WebSocket | M | H | Explicit WS detection branch; test in phase 05 |
| Adding `preserve_host` breaks existing serde configs | M | M | Default = true via `#[serde(default)]`; test deserialization without the field |
| Order-dependence: `forwarded-host` must read original Host before `host-policy` mutates it | H | M | Encode order in chain registration; test asserts order |

## Security Considerations
- Untrusted-peer XFF spoofing already gated by `extract_client_ip` (proxy.rs:64–78). XFF filter must use **resolved** `client_ip` from `RequestCtx`, not raw header.
- Never log full XFF chain at INFO (PII).

## Next Steps
- Phase 03: response-side counterpart.
