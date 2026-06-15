# US-1602 Config from ./waf.yaml|toml in cwd; upstream + port from config

## Status

implemented

## Lane

normal

## Product Contract

The WAF reads its configuration from `./waf.yaml` or `./waf.toml`, which MUST exist in
the working directory. The upstream proxy target and the listen port are read from this
config file, not hardcoded. This config-in-cwd surface is part of the interop §8 startup
contract; the packaged binary and config naming must be reconciled with §8 before a
benchmark run.

## Relevant Product Docs

- `docs/product/startup-contract.md`
- interop contract v2.3 §8

## Acceptance Criteria

- A config file (`./waf.yaml` or `./waf.toml`) must exist in the working directory;
  absence is a startup error.
- WAF reads the upstream proxy target from the config file.
- WAF listens on the port specified in the config file.
- Both YAML and TOML forms load to the same effective config.
- Packaged binary/config naming is reconciled with §8 before a benchmark run (this
  repo defaults differ from the `./waf` / `./waf.yaml|toml` contract surface).

## Design Notes

- Commands: config load during `./waf run` bootstrap in `crates/prx-waf`.
- Queries: none.
- API: upstream target + listen port resolved from config; default proxy ports
  `16880`/`16843`, admin+health `9527`/`16827` (`GET /health`).
- Tables: none.
- Domain rules: config file required in cwd; upstream + port sourced from config.
- UI surfaces: none.

## Validation

When updating durable proof status, use numeric booleans:
`scripts/bin/harness-cli story update --id <id> --unit 1 --integration 1 --e2e 0 --platform 0`.

| Layer | Expected proof |
| --- | --- |
| Unit | config load parses upstream + port from yaml/toml |
| Integration | boot with config → listener bound to configured port |
| E2E | |
| Platform | `./waf run` smoke + audit-log-on-first-request |
| Release | |

## Harness Delta

Story registered under decision 0008-interop-contract-v2.3-adoption; durable proof
booleans set via harness-cli after verification.

## Evidence

CLI/bootstrap in `crates/prx-waf`; health in `crates/waf-api`. Durable proof unset
pending `harness-cli story verify`.
