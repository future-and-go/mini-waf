# Product: Startup & Binary Contract

Source: interop contract v2.3 §8. Epic: `E16`.

```text
Binary:   ./waf
Start:    ./waf run
Config:   ./waf.yaml (or ./waf.toml) — MUST exist in working directory
Logs:     ./waf_audit.log (default, configurable in config file)
```

## Benchmarker expectations

1. WAF binary exists at `./waf`.
2. `./waf run` starts the WAF and begins listening before the startup timeout.
3. WAF reads the upstream target from its config file.
4. WAF listens on the port specified in config.
5. `./waf_audit.log` is created once the first request is processed.

## Health check

After `./waf run`, the benchmarker polls the configured health endpoint until the
startup timeout expires. The first `200` response means the WAF is ready. If no
`200` arrives before the timeout, the run is recorded as `startup_failed`.

> Note: this repo's default config and README use ports `16880`/`16843` (proxy)
> and `9527`/`16827` (admin+health, `GET /health`). The benchmark working-directory
> contract (`./waf`, `./waf.yaml|toml`, `./waf_audit.log`) is the surface scored
> here; reconcile the packaged binary/config names with §8 before a benchmark run.
