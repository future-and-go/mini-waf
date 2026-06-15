# 0009 Persist audit records to a JSONL file sink (`./waf_audit.log`)

Date: 2026-06-15

## Status

Accepted

## Context

Interop contract v2.3 §6/§8 require the WAF to write structured audit records as
JSONL to `./waf_audit.log` (configurable path), append-only, created on first
request; the benchmarker reads this file after each run for correlation and score
validation. §10 requires the audit `ip` field to be the TCP `peer_addr`, never
parsed from `X-Forwarded-For`/`X-Real-IP`.

Current implementation (`crates/waf-engine/src/logging/audit_sender.rs`) builds the
correct §6 JSON object but ships it **only** to VictoriaLogs over HTTP via
`BatchSender` (network sink). No on-disk file exists. This blocks E12 entirely,
blocks E16 US-1603 ("audit log created on first request"), and makes E10 US-1004's
"audit_log_preserved" claim vacuous (there is nothing to preserve).

## Decision

Make a **JSONL file sink the sole audit sink**, replacing the VictoriaLogs network
sink in `AuditSender::send`. Specifically:

- New config (default `./waf_audit.log`) controls the audit file path + enable flag.
- File opened append-only (`append(true).create(true)`), created lazily on the first
  processed request.
- The JSONL `ip` field is sourced from the TCP `peer_addr`, independent of proxy-trust
  resolution, to satisfy §10.
- `reset_state` continues to never touch the file (append-only preserved by
  construction).
- The VictoriaLogs network sink is removed, not run in parallel. The wider VL
  teardown (tracing layer, sidecar/installer, read API, config) is recorded in
  decision 0010 and implemented as E12 US-1205.

Three implementation sub-choices (write mechanism, peer-addr threading, config
placement) are documented with recommendations in
`docs/stories/epics/E12-audit-log/US-1201-jsonl-file-writer/design.md` (D1–D3) and
will be locked at implementation start.

## Alternatives Considered

1. **VictoriaLogs as the sole audit sink** — rejected: a network sink does not
   satisfy §6's local-file requirement nor the benchmarker's read-back.
2. **File alongside VictoriaLogs (dual sink)** — rejected: keeping VL only for audit
   adds a network transport, a sidecar, and an installer for no contract benefit once
   the file exists; the file alone satisfies §6/§8/§10. See decision 0010.
3. **Tee inside `BatchSender`** — moot: `BatchSender` is removed with the VL transport.
4. **Write from the `logs.rs` read API** — moot: `logs.rs` is the VL read proxy and is
   removed; the writer belongs at the existing audit send call sites.

## Consequences

Positive:

- Closes E12 (US-1201..1204); unblocks E16 US-1603 and validates E10 US-1004.
- Contract-pure `ip` semantics regardless of proxy-trust config.
- Single audit transport; no network sink to operate, secure, or keep healthy.

Tradeoffs:

- New file-I/O surface on (or near) the request path; mechanism chosen to keep it
  off the hot path.
- One more configurable path operators must understand.
- Removing VL also removes the admin log-query/streams views — tracked in 0010.

## Follow-Up

- Implement after approval; record proof with `harness-cli story update` and register
  this decision with `harness-cli decision add`.
- Optional later: append a `reset_state` marker line; slim file records to §6-only.
