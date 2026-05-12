# FR-039 Circuit Breaker — Docker E2E

Validates that the WAF returns `503 Service Unavailable` (with
`Retry-After: 5`) within the configured deadline when an upstream is
unreachable. Covers HTTP/1.1 and HTTP/2.

## Layout

```
circuit-breaker/
├── docker-compose.yml          # WAF + hang/healthy backends + curl asserter
├── waf-config.toml             # FR-039 timeouts scaled for tests (1.5s / 1s)
├── run.sh                      # Assertion script (E1..E5)
└── mocks/
    └── hang-backend/
        └── Dockerfile          # socat TCP listener that never replies
```

Refused-backend is intentionally NOT a service — E2 routes to a host that
no compose service binds, exercising the connect-refused path.

## Run

```sh
cd tests/e2e/circuit-breaker
docker compose up --abort-on-container-exit --exit-code-from asserter
```

The asserter exits non-zero on any failed assertion; `--abort-on-container-exit`
tears down WAF + backends as soon as the asserter is done.

## Scenarios

| ID | Scenario | Mock | Expected | Window |
|----|----------|------|----------|--------|
| E1 | Backend hangs | `hang-backend` | 503 | 1.0–4.5s |
| E2 | Connection refused | (no service) | 503 | <2.5s |
| E3 | Healthy backend | `healthy-backend` | 200 | n/a |
| E4 | `Retry-After: 5` header on 503 | `hang-backend` | header present | n/a |
| E5 | HTTP/2 hang | `hang-backend` over TLS | 503 | n/a (skipped if curl lacks H2) |

## Notes

- The WAF image `prx-waf:cov` is the local coverage build (already exists in
  the dev environment). To rebuild: `podman-compose build` from the project
  root or `docker build -t prx-waf:cov .`.
- HTTP/3 is not yet exercised by this suite; the H3 listener uses a separate
  `reqwest` client with FR-039 timeouts set on the `Client::builder()` —
  validated by inspection (`grep connect_timeout crates/gateway/src/http3.rs`).
  A future e2e can add E6 once curl-http3 is a stable dep.
