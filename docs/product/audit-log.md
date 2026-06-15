# Product: Audit Log

Source: interop contract v2.3 §6, §10. Implementation: `crates/waf-engine/src/logging/audit_sender.rs`.
Epic: `E12`.

The WAF writes structured JSON logs to `./waf_audit.log` (configurable path).
Append-only, one JSON object per line (JSONL), SIEM-ingestible. The benchmarker
reads it after each run for correlation, diagnostics, and score validation. It
does NOT replace the §5 response headers.

## Required fields per entry

```json
{ "request_id":"uuid", "ts_ms":1714000000000, "ip":"1.2.3.4",
  "method":"POST", "path":"/login", "action":"block", "risk_score":75, "mode":"enforce" }
```

| Field | Type | Constraints |
| --- | --- | --- |
| `request_id` | string UUID v4 | MUST match `X-WAF-Request-Id` if both present. |
| `ts_ms` | int | Unix epoch milliseconds. |
| `ip` | string | TCP peer address (NOT XFF). IPv4 dotted decimal. |
| `method` | string | Uppercase HTTP method. |
| `path` | string | Request path **including query string**. |
| `action` | string | One of the six decision classes (§3). |
| `risk_score` | int 0–100 | Score at decision time. |
| `mode` | string | `enforce`/`log_only`; MUST match `X-WAF-Mode` when present. |

## IP semantics & source-IP trust model (§6, §10)

- `ip` MUST be the TCP `peer_addr`/`remote_addr` from the socket, never parsed
  from `X-Forwarded-For` or `X-Real-IP`. The benchmarker simulates source IPs via
  `127.0.0.x` loopback aliases and correlates by TCP source IP.
- `X-Forwarded-For` / `X-Real-IP` are supplementary context only, never identity.
- `Host` is validated against the expected hostname; unexpected values rejected/sanitized.
- Different `127.0.0.x` addresses MUST be treated as distinct clients (rate limit,
  risk scoring).

## Append-only invariant

`reset_state` MUST NOT delete, truncate, rotate, or rewrite the audit log. A
structured event MAY be appended noting `reset_state` was called.

## Additional fields (§6)

Extra JSON fields are allowed (device fp, rule, latency, etc.). They MUST NOT
weaken required fields, MUST NOT contain secrets/credentials/session tokens/stack
traces/sensitive data, and SHOULD keep one valid JSON object per line.
