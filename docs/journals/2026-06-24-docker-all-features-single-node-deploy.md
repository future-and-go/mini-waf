# Docker All-Features Single-Node Deploy — Complete

**Date**: 2026-06-24 15:30  
**Severity**: N/A — Feature delivery  
**Component**: Docker deployment, prx-waf full-feature configuration  
**Status**: Resolved

## What Shipped

One-command local/demo deploy via `./scripts/deploy.sh` bringing up prx-waf with every single-node feature enabled:

- **HTTP/3** listener (QUIC)
- **Valkey standalone** cache backend
- **Outbound header-strip** enforcement
- **Audit JSONL** sink to `/var/log/prx-waf/audit.jsonl`
- **OWASP CRS** rule set loaded
- **Auto-block** on challenge failure
- **SQLi-scan** via libinjection engine
- **Juice Shop** routed behind the WAF as live test target
- **Self-signed TLS** (demo cert)

New artifacts:
- `configs/full-features.toml` — WAF configuration with all single-node features
- `configs/full-features-panel.toml` — Enforcement console panel config
- `docker-compose.deploy.yml` — Compose stack (WAF, Valkey, Juice Shop, nginx reverse proxy)
- `.env.example` — Environment template
- `scripts/deploy.sh` — One-command entry point
- `docs/all-features-docker-deploy.md` — Deployment guide and feature walkthrough

## The Real Obstacle: glibc Mismatch

Build host (Ubuntu 24.04) uses glibc 2.39. `Dockerfile.prebuilt` based on `debian:bookworm-slim` ships glibc 2.36. Prebuilt binary linked against glibc 2.38/2.39 crashed on container boot with:

```
/usr/local/bin/prx-waf: symbol `__libc_malloc_info', version `GLIBC_2.38' not found
```

The binary was alive, the runtime was too old.

## The Fix: Parameterized Base Image

Added `ARG BASE_IMAGE=debian:bookworm-slim` to `Dockerfile.prebuilt`, preserving default behavior for cluster/e2e/CI consumers. The deploy script passes `--build-arg BASE_IMAGE=debian:trixie-slim` (glibc 2.41), eliminating the symbol mismatch.

**Lesson**: Prebuilt binary deploys require runtime glibc >= build-host glibc. Version skew here is silent until container startup. Parameterizing the base image was the right trade-off: cluster users never see the arg, demo/local users get a working environment.

## Verification Live

- SQLi probe to `Host: juice.local` → **blocked HTTP 403**, recorded in `/api/security-events` with rule `SQLI-LIB` and libinjection confidence
- `/health` → **200 OK**
- Valkey standalone → **connected and serving cache**
- HTTP/3 listener → **active** (QUIC Alt-Svc advertised)
- Outbound fingerprints → **stripped** (e.g., `Server` header absent in response)
- Audit JSONL sink → **writing events**
- All acceptance criteria met

Code review completed; zero must-fix findings.

## Constraints Honored

- No edits to `configs/default.toml`
- No changes to any Rust crate
- Deployment isolation: new files only, no collateral modification

## Commit

Commit `e5a530f` on branch `main-harness`.

---

**Status: DONE**

Successfully deployed prx-waf all-features single-node Docker stack via parameterized base image strategy, fixing glibc version skew and validating all feature integrations live.
