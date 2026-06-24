---
phase: 3
title: "One-Click Script"
status: pending
effort: "M"
---

# Phase 3: One-Click Script

## Overview

`scripts/deploy.sh` — single command that builds the prebuilt artifacts on the host, generates secrets, brings up the Docker stack, gates on health, and prints access info. No manual migrate/seed (the `run` command auto-migrates + auto-seeds admin).

## Requirements

- Functional: `./scripts/deploy.sh` on a clean checkout → healthy stack, zero interactive prompts.
- Non-functional: idempotent (safe re-run), `set -euo pipefail`, clear preflight errors, kebab-case filename, POSIX-bash.

## Architecture

Flow:
```
preflight ──► build artifacts ──► secrets/.env ──► compose up ──► health-gate ──► smoke ──► print access
```

1. **Preflight** — assert `docker`, `docker compose` (v2), `cargo`, `npm` present; assert running from repo root (check for `Cargo.toml` + `docker-compose.yml`). Fail fast with the exact missing tool.
2. **Build artifacts** (prebuilt mode):
   - Frontend: `cd web/admin-panel && npm ci && npm run build` (produces `dist/` embedded by `Dockerfile.prebuilt`'s COPY).
   - Binary: `cargo build --release --features gateway/valkey` → `target/release/waf`.
   - Ensure `data/` exists (`mkdir -p data`) so `Dockerfile.prebuilt`'s `COPY data/` succeeds.
3. **Secrets** — if `.env` absent, copy `.env.example`; if `JWT_SECRET` empty, generate `openssl rand -hex 32` (fallback `head -c32 /dev/urandom | xxd -p`) and write it into `.env`. Never overwrite an existing non-empty secret.
4. **Compose up** — `docker compose -f docker-compose.yml -f docker-compose.deploy.yml up -d --build`.
5. **Health-gate** — poll `curl -ksf https://localhost:16827/health` up to ~90s; parse `status` and the component report (`database`, `waf_engine`, `cache`). Fail with last response + `docker compose logs --tail=50 prx-waf` on timeout.
6. **Smoke** (optional but recommended, gated behind success) — send a benign request and one SQLi probe through the proxy to the Juice Shop host, assert the probe is blocked (HTTP 403 or block body). Non-fatal warn if Juice Shop not ready yet.
7. **Print access** — table of URLs/ports, default creds (`admin`/`admin123` — warn to change), and the `Host: juice.local` test recipe.

Flags (keep minimal, YAGNI): `--no-build` (skip cargo/npm if artifacts fresh), `--down` (tear down). Nothing else unless asked.

## Related Code Files

- Create: `scripts/deploy.sh` (chmod +x)
- Read-only reference: `docker-compose.yml`, `docker-compose.deploy.yml`, `Dockerfile.prebuilt`, `README.md` (ports/creds), `crates/prx-waf/src/main.rs` (confirm `/health` shape, auto-migrate/seed)

## Implementation Steps

1. Scaffold `scripts/deploy.sh` with `#!/usr/bin/env bash` + `set -euo pipefail` + `cd` to repo root resolved from `${BASH_SOURCE[0]}`.
2. Implement preflight checks (functions returning clear errors).
3. Implement build steps; respect `--no-build`.
4. Implement `.env` + JWT generation (idempotent).
5. Implement compose up + health poll loop with timeout + log dump on failure.
6. Implement smoke probe (curl through `http://localhost:16880` with `Host: juice.local`; expect block on a `' OR 1=1` style query string).
7. Implement access-info printout.
8. `chmod +x scripts/deploy.sh`; run `bash -n scripts/deploy.sh` (syntax) and `shellcheck` if available.

## Success Criteria

- [ ] `bash -n scripts/deploy.sh` clean; `shellcheck` clean (or only intentional, documented suppressions).
- [ ] Fresh run reaches `status: healthy` with no manual steps and prints access info.
- [ ] Re-run does not clobber an existing `.env` secret and converges to healthy.
- [ ] `--down` tears the stack down cleanly.

## Risk Assessment

- **Slow first build** (cargo + npm) → long apparent hang. Mitigate: echo progress banners before each heavy step.
- **Health endpoint is HTTPS self-signed** → must use `curl -k`. Already accounted for.
- **Juice Shop slow to start** → smoke probe flaky. Mitigate: smoke is non-fatal, retried briefly.
- **`docker compose` v1 vs v2** → detect `docker compose` (space) first, error if only legacy `docker-compose` present (base files assume v2).
