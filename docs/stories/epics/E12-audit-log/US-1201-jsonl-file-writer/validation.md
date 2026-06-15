# Validation

## Proof Strategy

Before the story is done: the audit file is created on first request, every line is
one valid JSON object with the §6 fields, the file is never truncated/rotated
(including across `reset_state`), the `ip` field equals the TCP peer, and
`request_id`/`mode` match the response headers. Unit + integration green; recorded
via `harness-cli story update`.

## Test Plan

| Layer | Cases |
| --- | --- |
| Unit | (1) `AuditFileSink::append` writes exactly one line per record, valid JSON, trailing `\n`. (2) Record carries the 8 §6 fields with correct types. (3) Path-truncation boundary (reuse existing UTF-8 logic). (4) `ip` field set from peer_addr, not XFF. |
| Integration | (1) File absent at idle startup, present after first request. (2) N requests → N parseable JSON lines. (3) Append-only: capture bytes, call `reset_state`, assert file unchanged/not truncated and still appended-to afterward. (4) Line `request_id` == `X-WAF-Request-Id`, `mode` == `X-WAF-Mode` for same request. (5) Two `127.0.0.x` aliases → distinct `ip` values. |
| E2E | Post-run parse of `./waf_audit.log`: every line `json.loads`-able; required fields present. |
| Platform | `./waf run` smoke: process boots, file created on first proxied request in cwd. |
| Performance | Hot-path write adds no blocking I/O (mechanism A); spot-check p99 unchanged on loopback. |
| Logs/Audit | No secrets/credentials/session tokens/stack traces in any line (§6 prohibition). |

## Fixtures

- Deterministic requests from `127.0.0.1` and `127.0.0.2` loopback aliases.
- Temp working dir per test so `./waf_audit.log` is isolated and asserted directly.
- Fixed clock / injected `ts_ms` where feasible for stable assertions.

## Commands

Add after implementation (disk-space permitting — workspace test build currently
blocked by a full disk / ENOSPC):

```text
cargo test -p waf-engine audit
cargo test -p waf-api  interop_control
cargo test --workspace
```

## Acceptance Evidence

Add results after verification. Story stays `in_progress` until unit + integration
are green and recorded with numeric proof booleans
(`--unit 1 --integration 1 --e2e 0 --platform 0`).
