---
phase: 2
title: "Peer-addr IP semantics"
status: completed
priority: P1
effort: "3h"
dependencies: [1]
---

# Phase 2: Peer-addr IP semantics

## Overview

Make the audit `ip` field the **TCP peer address** (D2), never the XFF-derived
client IP, so the benchmarker's `127.0.0.x` loopback aliases correlate by real
TCP source. Closes US-1203.

## Requirements

- Functional: audit-record `ip` = `peer_addr.ip()`, independent of
  `trust_proxy_headers`. Distinct `127.0.0.x` aliases produce distinct `ip`
  values. `Host` validated against expected hostname (verify existing host-gate
  covers this; do not weaken).
- Non-functional: must **not** change proxy-path routing/rate-limit/risk behavior
  that legitimately uses the trust-resolved `client_ip`. Only the audit `ip`
  reporting changes.

## Architecture

`RequestCtx` currently exposes only `client_ip` (trust-resolved at
`extract_client_ip_from_session`). The raw peer is computed but discarded at
`request_ctx_builder.rs:88` (`peer_addr.ip()`). Add a raw peer field and thread
it to the audit record:

```
request_ctx_builder.build():
    peer_addr.ip()  ──►  RequestCtx.peer_ip   (new field, raw TCP source)
                          RequestCtx.client_ip (unchanged: trust-resolved)

engine.send_audit_event / emit_minimal_audit_stub:
    AuditEvent.ip       = ctx.peer_ip   (NEW — §6/§10 contract ip)
    AuditEvent.client_ip = ctx.client_ip (extra field, FE)
```

- `AuditEvent` currently has only `client_ip`, and `build_audit_record` sets both
  the §6 `ip` and the extra `client_ip` from it. Add `AuditEvent.peer_ip: String`
  (or reuse a single `ip` field). `build_audit_record`: `ip` ← `peer_ip`,
  `client_ip` ← `client_ip`.
- For the error-path stub (`emit_minimal_audit_stub`, `engine.rs:470`), pass the
  peer IP at the call site too (it currently takes `client_ip: &str`). Add a
  `peer_ip` param or pass `ctx.peer_ip` where the stub is invoked.

## Related Code Files

- Modify: `crates/waf-common/src/types.rs` (add `pub peer_ip: IpAddr` to
  `RequestCtx`; update any struct-literal constructors / `Default`/test builders)
- Modify: `crates/gateway/src/ctx_builder/request_ctx_builder.rs` (set
  `peer_ip: peer_addr.ip()` in `build()` and in the pure `assemble` fn signature)
- Modify: `crates/waf-engine/src/engine.rs` (`AuditEvent.ip`/`peer_ip` from
  `ctx.peer_ip` at `send_audit_event` ~1048 and `emit_minimal_audit_stub` ~483)
- Modify: `crates/waf-engine/src/logging/audit_sender.rs` (`AuditEvent.peer_ip`
  field; `build_audit_record` maps `ip` ← peer_ip)
- Verify (no change expected): host-gate validation path for `Host`

## Implementation Steps

1. Add `peer_ip: IpAddr` to `RequestCtx`; fix every constructor/test builder the
   compiler flags (search struct literals of `RequestCtx`).
2. Set `peer_ip` from `peer_addr.ip()` in `request_ctx_builder.rs` `build()` and
   thread through the `assemble`/pure helper signature.
3. Add `peer_ip` to `AuditEvent`; in `build_audit_record`, set §6 `ip` ←
   `peer_ip`, keep `client_ip` extra ← `client_ip`.
4. At both engine call sites, populate `AuditEvent.peer_ip` from `ctx.peer_ip`.
5. Confirm `Host` validation already runs (host-gate); note location in proof. No
   weakening.
6. Update unit test `vl_payload_has_contract_ip_field` → assert `ip` comes from
   peer while `client_ip` can differ (add a case where peer ≠ client_ip).
7. `cargo build --workspace` (gateway + engine + common touched);
   `cargo test -p waf-engine audit`.

## Success Criteria

- [ ] `RequestCtx.peer_ip` carries the raw TCP source; `client_ip` unchanged.
- [ ] Audit record `ip` == peer addr even when `trust_proxy_headers=true` and an
      `X-Forwarded-For` header is present (unit test with peer ≠ client_ip).
- [ ] Distinct `127.0.0.1` / `127.0.0.2` peers → distinct `ip` values.
- [ ] No change to proxy routing / rate-limit / risk keys (still use `client_ip`).
- [ ] `cargo build --workspace` succeeds.

## Risk Assessment

- **Accidentally routing on peer_ip** instead of client_ip would change WAF
  behavior — mitigated by only consuming `peer_ip` in the audit record; all other
  consumers keep `client_ip`.
- **Constructor fan-out**: adding a `RequestCtx` field breaks every struct
  literal — mitigated by compiler-driven fix pass; prefer a default in test
  builders where present.
