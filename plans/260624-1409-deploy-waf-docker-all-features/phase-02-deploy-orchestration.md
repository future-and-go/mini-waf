---
phase: 2
title: "Deploy Orchestration"
status: pending
effort: "M"
---

# Phase 2: Deploy Orchestration

## Overview

Wire the prebuilt-binary image and the all-features config into Docker without duplicating the existing stack. Use `docker-compose.yml` as the base and add a thin **override** that (a) swaps the `prx-waf` build to `Dockerfile.prebuilt`, (b) runs `configs/full-features.toml`, (c) publishes `443/udp` for HTTP/3, (d) loads secrets from `.env`. Add a `.env.example`.

## Requirements

- Functional: `docker compose -f docker-compose.yml -f docker-compose.deploy.yml up -d` builds from the prebuilt binary and runs the all-features config.
- Non-functional: DRY (reuse base services postgres/valkey/tls-init/juice-shop), no secret values committed.

## Architecture

**`docker-compose.deploy.yml` (override, only the deltas):**
```yaml
services:
  prx-waf:
    build:
      dockerfile: Dockerfile.prebuilt      # override base's Dockerfile (needs target/release/waf on host)
    env_file: .env                          # JWT_SECRET, CACHE_BACKEND, RUST_LOG
    command: ["/usr/local/bin/waf", "--config", "/app/configs/full-features.toml", "run"]
    ports:
      - "16843:443/udp"                     # HTTP/3 QUIC (additive to base TCP maps)
```
Notes:
- Compose merges override port lists by appending, so base TCP `16880:80`, `16843:443`, `16827:9527` remain; the override only adds the UDP map. Confirm no duplicate-port conflict.
- Base already mounts `./configs:/app/configs` (rw) and sets `CACHE_BACKEND=standalone`, `DATABASE_URL`, `SSL_CERT_FILE`, `NET_ADMIN`, ulimits — inherited, no need to repeat.
- `Dockerfile.prebuilt` copies `target/release/waf`, `configs/`, `rules/`, `data/`, `web/admin-panel/dist`, `migrations/`. The script (Phase 3) must ensure those exist before build. If `data/` is absent, either create an empty `data/` or adjust the COPY — verify during implementation.

**`.env.example`:**
```dotenv
# Copy to .env; deploy.sh auto-generates a strong JWT_SECRET if unset.
JWT_SECRET=
CACHE_BACKEND=standalone
RUST_LOG=info
```

## Related Code Files

- Create: `docker-compose.deploy.yml`
- Create: `.env.example`
- Read-only reference: `docker-compose.yml`, `Dockerfile.prebuilt`, `.gitignore` (confirm `.env` is ignored; add it if not)

## Implementation Steps

1. Verify `.env` is git-ignored; if not, add `.env` to `.gitignore` (surgical one-line add).
2. Confirm `Dockerfile.prebuilt`'s `COPY data/ /app/data/` won't break when `data/` is empty/missing; note required pre-create in the phase report for Phase 3 to honor.
3. Write `docker-compose.deploy.yml` with only the four deltas above.
4. Write `.env.example`.
5. Dry-validate merge: `docker compose -f docker-compose.yml -f docker-compose.deploy.yml config` — must render without errors and show the UDP port, prebuilt dockerfile, and full-features command.

## Success Criteria

- [ ] `docker compose -f docker-compose.yml -f docker-compose.deploy.yml config` renders cleanly.
- [ ] Rendered `prx-waf` service uses `Dockerfile.prebuilt`, command `full-features.toml`, and publishes `16843:443/udp` plus the base TCP ports.
- [ ] `.env.example` present; `.env` git-ignored.
- [ ] Juice Shop service still present (local test target retained).

## Risk Assessment

- **`Dockerfile.prebuilt` COPY of missing `data/`** → build fails. Mitigate: pre-create `data/` in script, or guard the COPY.
- **UDP port not actually published** if override syntax wrong → HTTP/3 silently TCP-only. Mitigate: assert UDP map in `compose config` output and in Phase 4 smoke test.
- **Override accidentally overriding base env** (env_file vs environment merge). Compose merges `environment` over `env_file`; keep secrets only in `.env`, leave functional env in base.
