# US-1603 Health endpoint returns 200 when ready; audit log created on first request

## Status

in_progress

## Lane

normal

## Product Contract

After `./waf run`, the benchmarker polls the configured health endpoint until the
startup timeout expires; the first `200` response means the WAF is ready. Once the WAF
processes its first request, `./waf_audit.log` is created. This is the readiness +
audit half of the interop §8 startup contract.

## Relevant Product Docs

- `docs/product/startup-contract.md`
- interop contract v2.3 §8

## Acceptance Criteria

- The benchmarker polls the configured health endpoint after `./waf run`.
- The first `200` response signals readiness.
- If no `200` arrives before the startup timeout, the run is recorded `startup_failed`.
- `./waf_audit.log` is created once the first request is processed.
- The audit log path defaults to `./waf_audit.log` and is configurable in the config file.

## Design Notes

- Commands: bootstrap in `crates/prx-waf` opens the audit log on first processed request.
- Queries: health handler in `crates/waf-api` returns `200` when ready.
- API: health on admin port `9527`/`16827` via `GET /health`; proxy ports
  `16880`/`16843`.
- Tables: none.
- Domain rules: first health `200` = ready; first processed request creates audit log.
- UI surfaces: none.

## Validation

When updating durable proof status, use numeric booleans:
`scripts/bin/harness-cli story update --id <id> --unit 1 --integration 1 --e2e 0 --platform 0`.

| Layer | Expected proof |
| --- | --- |
| Unit | health handler returns 200 when ready |
| Integration | boot → health 200; first request creates `./waf_audit.log` |
| E2E | |
| Platform | `./waf run` smoke + audit-log-on-first-request |
| Release | |

## Harness Delta

Story registered under decision 0008-interop-contract-v2.3-adoption; durable proof
booleans set via harness-cli after verification.

## Evidence

CLI/bootstrap in `crates/prx-waf`; health in `crates/waf-api`. Durable proof unset
pending `harness-cli story verify`.
