# E16 — Startup & Binary Contract

Contract: interop v2.3 §8. Product doc: `docs/product/startup-contract.md`.
Lane: normal. Code: `crates/prx-waf` (CLI/bootstrap), `crates/waf-api` (health).

```text
Binary: ./waf   Start: ./waf run   Config: ./waf.yaml|toml   Logs: ./waf_audit.log
```

## Stories

| ID | Title | Lane | Status | §
| --- | --- | --- | --- | --- |
| US-1601 | `./waf run` starts and listens before startup timeout | normal | implemented | §8 |
| US-1602 | Config from ./waf.yaml|toml in cwd; upstream + port from config | normal | implemented | §8 |
| US-1603 | Health endpoint returns 200 when ready; audit log created on first request | normal | implemented | §8 |

## Acceptance criteria (per story)

- **US-1601**: WAF binary exists at `./waf`; `./waf run` begins listening before the
  startup timeout; otherwise the run is recorded `startup_failed`.
- **US-1602**: config file (`./waf.yaml` or `./waf.toml`) must exist in the working
  directory; WAF reads the upstream target and listen port from it. Reconcile packaged
  binary/config naming with §8 before a benchmark run (see product doc note).
- **US-1603**: benchmarker polls the configured health endpoint; first `200` = ready;
  `./waf_audit.log` is created once the first request is processed.

## Validation shape

Unit: config load + health handler. Integration: boot → health 200. Platform: `./waf run`
smoke + audit-log-on-first-request check.
