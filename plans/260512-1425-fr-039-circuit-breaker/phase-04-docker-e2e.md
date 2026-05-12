---
phase: 4
title: "Docker E2E + HTTP/2/3 Verification"
status: pending
priority: P0
effort: "3h"
dependencies: [3]
---

# Phase 4: Docker E2E

## Overview

Per `rules.md` line 7 ("Use Docker to build and run tests. The local environment does not have Rust installed"), validate end-to-end behavior in containerized environment. Cover HTTP/1.1, HTTP/2, and HTTP/3 (QUIC) paths since `gateway/src/http3.rs` is a separate listener. Reuse existing `tests/e2e/` Docker harness.

## Requirements

**Functional E2E scenarios:**

| # | Scenario | Method | Mock Backend | Expected |
|---|---------|--------|--------------|----------|
| E1 | H1 unresponsive backend | curl http://localhost:16880/ | nc -l (hang) | 503 + Retry-After:5 |
| E2 | H1 connection refused | curl http://localhost:16880/ | no backend running | 503 + Retry-After:5 |
| E3 | H1 healthy | curl http://localhost:16880/ | nginx static | 200 OK |
| E4 | H2 unresponsive | curl --http2 https://localhost:16843/ | mock h2 hang | 503 |
| E5 | H3 unresponsive | curl --http3 https://localhost:16843/ | mock h3 hang | 503 |
| E6 | Hot-reload timeout config | swap config; observe new behavior | hang backend | 503 within new timeout |

**Non-functional:**
- Tests reproducible via single shell script (`tests/e2e/circuit-breaker/run.sh`)
- Pass in CI (GitHub Actions) within ≤ 5 min
- No interference with existing e2e tests
- Docker-only — no Rust on host (per rules.md)

## Architecture

### Directory Layout

```
tests/e2e/circuit-breaker/
├── docker-compose.yml      # WAF + mock backends + assertions
├── run.sh                  # Entry: build, up, assert, down
├── waf-config.toml         # FR-039 timeouts scaled for tests (1s/2s)
├── mocks/
│   ├── hang-backend/       # Dockerfile: accept TCP; sleep
│   │   └── Dockerfile
│   ├── healthy-backend/    # Dockerfile: nginx serving 200 OK
│   │   └── Dockerfile
│   └── h2-hang-backend/    # Dockerfile: rustls h2 server that hangs
│       └── Dockerfile
└── README.md               # How to run locally
```

### docker-compose.yml (sketch)

```yaml
version: "3.8"
services:
  waf:
    build:
      context: ../../..
      dockerfile: Dockerfile.prebuilt
    ports:
      - "26880:16880"
      - "26843:16843"
      - "26827:16827"
    volumes:
      - ./waf-config.toml:/app/configs/default.toml:ro
    depends_on:
      - hang-backend
      - healthy-backend

  hang-backend:
    build: ./mocks/hang-backend
    expose: ["80"]

  healthy-backend:
    build: ./mocks/healthy-backend
    expose: ["80"]

  asserter:
    image: curlimages/curl:latest
    depends_on: [waf]
    entrypoint: ["sh", "-c", "sleep 3 && /assert.sh"]
    volumes:
      - ./run.sh:/assert.sh:ro
```

### run.sh (assertion-driven)

```bash
#!/usr/bin/env sh
set -eu

# E1: hang backend → expect 503 within 2s
start=$(date +%s%N)
status=$(curl -s -o /dev/null -w "%{http_code}" -m 5 http://waf:16880/hang/)
elapsed_ms=$(( ( $(date +%s%N) - start ) / 1000000 ))
[ "$status" = "503" ] || { echo "E1 FAIL: status=$status"; exit 1; }
[ "$elapsed_ms" -lt 2500 ] || { echo "E1 FAIL: ${elapsed_ms}ms"; exit 1; }

# E2: no backend → 503
status=$(curl -s -o /dev/null -w "%{http_code}" -m 5 http://waf:16880/no-backend/)
[ "$status" = "503" ] || { echo "E2 FAIL: $status"; exit 1; }

# E3: healthy → 200
status=$(curl -s -o /dev/null -w "%{http_code}" -m 5 http://waf:16880/ok/)
[ "$status" = "200" ] || { echo "E3 FAIL: $status"; exit 1; }

# E4: H2 hang → 503
status=$(curl -sk --http2 -o /dev/null -w "%{http_code}" -m 5 https://waf:16843/h2-hang/)
[ "$status" = "503" ] || { echo "E4 FAIL: $status"; exit 1; }

# E5: H3 hang (if curl has --http3)
if curl --version | grep -q HTTP3; then
  status=$(curl -sk --http3 -o /dev/null -w "%{http_code}" -m 5 https://waf:16843/h3-hang/)
  [ "$status" = "503" ] || { echo "E5 FAIL: $status"; exit 1; }
else
  echo "E5 SKIP: curl lacks HTTP/3"
fi

# E6: hot-reload — swap config and assert new behavior
# (out of scope for v1; placeholder)
echo "E6 SKIP: hot-reload e2e deferred"

echo "ALL FR-039 E2E PASS"
```

### HTTP/3 verification

**Risk:** `crates/gateway/src/http3.rs` may build its own `HttpPeer` separately from `WafProxy::upstream_peer()`.

**Phase 4 first task:** Read `crates/gateway/src/http3.rs`:
- If it routes through `WafProxy::upstream_peer()` → no extra work (E5 just works).
- If it constructs `HttpPeer` independently → mirror Phase 2 Edit 1 in `http3.rs`. Track as discovered task.

## Related Code Files

**Create:**
- `tests/e2e/circuit-breaker/docker-compose.yml`
- `tests/e2e/circuit-breaker/run.sh`
- `tests/e2e/circuit-breaker/waf-config.toml`
- `tests/e2e/circuit-breaker/mocks/hang-backend/Dockerfile`
- `tests/e2e/circuit-breaker/mocks/healthy-backend/Dockerfile` (or nginx:alpine reuse)
- `tests/e2e/circuit-breaker/mocks/h2-hang-backend/Dockerfile`
- `tests/e2e/circuit-breaker/README.md`

**Modify (potentially):**
- `crates/gateway/src/http3.rs` — only if it builds its own HttpPeer (verify first)
- `.github/workflows/nightly-e2e.yml` — register new e2e suite (optional; ask user before CI changes)

**Delete:** none

## Implementation Steps

1. **Audit H3 path first:** `Read crates/gateway/src/http3.rs`. Determine if HttpPeer is built there. If yes → mirror Phase 2 Edit 1.
2. Create directory `tests/e2e/circuit-breaker/`.
3. Write `mocks/hang-backend/Dockerfile` (alpine + `nc -l -p 80 -k` that does NOT respond).
4. Use `nginx:alpine` for healthy-backend (no custom Dockerfile needed).
5. Write `docker-compose.yml` with WAF + 2 backends + asserter.
6. Write `waf-config.toml` with FR-039 timeouts at 1s/2s scale.
7. Write `run.sh` covering E1–E5.
8. `cd tests/e2e/circuit-breaker && docker compose up --abort-on-container-exit` (or `podman-compose` per CLAUDE.md).
9. Iterate until all assertions green.
10. Document in `tests/e2e/circuit-breaker/README.md` how to run locally and what each E covers.

## Todo List

- [ ] Audit `crates/gateway/src/http3.rs` for separate HttpPeer construction
- [ ] If H3 builds own HttpPeer, mirror Phase 2 Edit 1
- [ ] Create directory + Dockerfiles
- [ ] `waf-config.toml` with FR-039 test-scale timeouts
- [ ] `docker-compose.yml`
- [ ] `run.sh` E1–E5 (E6 deferred)
- [ ] Local run: `docker compose up --abort-on-container-exit` → all asserts pass
- [ ] README documenting run procedure
- [ ] CI integration (only if user approves modifying nightly-e2e.yml)

## Success Criteria

- [ ] E1–E5 pass locally via `docker compose up --abort-on-container-exit`
- [ ] Total runtime ≤ 5 min (per CI budget)
- [ ] No interference with existing `tests/e2e/` runs
- [ ] H3 path verified (E5 green OR `http3.rs` confirmed routes through `WafProxy`)
- [ ] README enables one-command reproduction

## Risk Assessment

| Risk | Mitigation |
|------|-----------|
| HTTP/3 listener bypasses `upstream_peer()` | Audit step 1; mirror change in `http3.rs` if needed |
| Mock H2/H3 hang server complexity | Use simple rustls-h2 server in Rust (in repo) OR fall back to `nc` for TCP-level hang (still triggers connect-timeout) |
| curl HTTP/3 availability in CI image | Skip E5 with explicit log if curl lacks H3 |
| Existing e2e test conflicts with new compose | Use distinct port range (26xxx) |
| Docker compose vs podman-compose syntax drift | Per CLAUDE.md: use podman-compose; verify compose v3.8 compat |

## Security Considerations

- Test-only mock backends; no production exposure.
- `waf-config.toml` in repo MUST NOT contain real secrets (admin password OK as `admin123` literal, matches existing convention).
- Asserter container uses official `curlimages/curl` — no custom build attack surface.
