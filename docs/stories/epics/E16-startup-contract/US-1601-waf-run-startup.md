# US-1601 `./waf run` starts and listens before startup timeout

## Status

in_progress

## Lane

normal

## Product Contract

The WAF ships as a binary at `./waf` and is launched with `./waf run`. After launch
the WAF must begin listening before the benchmarker's startup timeout expires; the
first `200` from the configured health endpoint marks readiness. If no `200` arrives
before the timeout, the run is recorded as `startup_failed`. This is the boot half of
the interop §8 startup contract scored by the benchmarker.

## Relevant Product Docs

- `docs/product/startup-contract.md`
- interop contract v2.3 §8

## Acceptance Criteria

- WAF binary exists at `./waf` in the benchmark working directory.
- `./waf run` starts the process and begins listening on the configured port.
- Listening begins before the startup timeout; readiness is confirmed by the first
  health `200`.
- If no health `200` is observed before the startup timeout, the run is recorded as
  `startup_failed`.
- A failed bootstrap (bad config, port bind failure) does not hang past the timeout.

## Design Notes

- Commands: `./waf run` entrypoint in `crates/prx-waf` (CLI/bootstrap).
- Queries: health readiness served by `crates/waf-api` (`GET /health`).
- API: default proxy ports `16880`/`16843`; admin+health on `9527`/`16827`.
- Tables: none.
- Domain rules: listen-before-timeout or `startup_failed`.
- UI surfaces: none.

## Validation

When updating durable proof status, use numeric booleans:
`scripts/bin/harness-cli story update --id <id> --unit 1 --integration 1 --e2e 0 --platform 0`.

| Layer | Expected proof |
| --- | --- |
| Unit | bootstrap/CLI run command parses and starts the listener |
| Integration | boot → health endpoint returns 200 within timeout |
| E2E | |
| Platform | `./waf run` smoke + audit-log-on-first-request |
| Release | |

## Harness Delta

Story registered under decision 0008-interop-contract-v2.3-adoption; durable proof
booleans set via harness-cli after verification.

## Evidence

CLI/bootstrap in `crates/prx-waf`; health in `crates/waf-api`. Durable proof unset
pending `harness-cli story verify`.
