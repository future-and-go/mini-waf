# US-1203 `ip` = TCP peer_addr (not XFF); distinct 127.0.0.x clients; Host validation

## Status

implemented

## Lane

high-risk

## Product Contract

The audit `ip` field MUST be the TCP `peer_addr`/`remote_addr` taken from the
socket, never parsed from `X-Forwarded-For` or `X-Real-IP` (interop v2.3 §6, §10).
`X-Forwarded-For`/`X-Real-IP` are supplementary context only, never identity.
Different `127.0.0.x` loopback aliases MUST be treated as distinct clients for rate
limiting and risk scoring. `Host` is validated against the expected hostname;
unexpected values are rejected or sanitized.

## Relevant Product Docs

- `docs/product/audit-log.md`
- interop contract v2.3 §6 (audit `ip` field), §10 (source-IP trust model)

## Acceptance Criteria

- `ip` is the TCP `peer_addr`/`remote_addr` from the socket for every record.
- `ip` is never derived or parsed from `X-Forwarded-For` or `X-Real-IP`; those
  headers are supplementary context only, never identity.
- Distinct `127.0.0.x` source addresses are treated as distinct clients for rate
  limiting and risk scoring.
- `Host` is validated against the expected hostname; unexpected values are
  rejected or sanitized.

## Design Notes

- Commands: capture socket peer address per request; bind it to the audit record.
- Queries: read-back of `ip` is a direct parse of `./waf_audit.log`; the VictoriaLogs
  read proxy is removed (US-1205).
- API: source-IP resolution in
  `crates/waf-engine/src/logging/audit_sender.rs`.
- Tables: none — JSONL, one JSON object per line.
- Domain rules: `ip` = TCP peer_addr only; XFF/X-Real-IP excluded from identity;
  per-`127.0.0.x` client distinction; Host validated against expected hostname.
- UI surfaces: none.

## Validation

When updating durable proof status, use numeric booleans:
`scripts/bin/harness-cli story update --id <id> --unit 1 --integration 1 --e2e 0 --platform 0`.

| Layer | Expected proof |
| --- | --- |
| Unit | `ip` resolved from socket peer_addr; XFF/X-Real-IP ignored for identity. |
| Integration | peer_addr vs XFF: spoofed XFF does not change `ip`; distinct `127.0.0.x` distinct clients. |
| E2E | Post-run log parse confirms `ip` matches simulated loopback source per request. |
| Platform | |
| Release | |

## Harness Delta

Story registered under decision 0008-interop-contract-v2.3-adoption; durable proof
booleans set via harness-cli after verification.

## Evidence

Audit pipeline in crates/waf-engine/src/logging/audit_sender.rs. Durable proof
unset pending `harness-cli story verify`.
