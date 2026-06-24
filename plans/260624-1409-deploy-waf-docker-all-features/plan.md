---
title: "Deploy WAF via Docker with all single-node features + one-click script"
description: "Self-signed local/demo Docker deployment of prx-waf with every single-node feature enabled, driven by one deploy script."
status: complete
priority: P2
branch: "main-harness"
tags: [deployment, docker, config]
blockedBy: []
blocks: []
created: "2026-06-24T07:14:28.638Z"
createdBy: "ck:plan"
source: skill
---

# Deploy WAF via Docker with all single-node features + one-click script

## Overview

Stand up `prx-waf` on a single host via Docker with **every single-node feature turned on**, reached through **one command**. Target is **local/demo**: self-signed TLS, the bundled Juice Shop stays as a live test target. No code changes to the Rust crates — this is config + orchestration + a deploy script.

Decisions locked with the user:
- **Target:** local/demo, self-signed TLS, keep Juice Shop.
- **Feature scope:** all single-node features. **Excluded** (need external setup / different topology): 3-node cluster, community threat-intel enroll, CrowdSec LAPI, ACME/Let's Encrypt, benchmark interop control.
- **Build mode:** prebuilt binary — `cargo build --release` on host, then `Dockerfile.prebuilt`.

Grounded facts from the codebase (do not re-litigate):
- `run` **auto-migrates** (`crates/prx-waf/src/main.rs:1553`) and **auto-creates the default admin** if none exists (`:1762`). No separate `migrate` / `seed-admin` step needed.
- Config schema is `AppConfig` in `crates/waf-common/src/config.rs`; all sections use `#[serde(default)]`, so omitted sections fall back to defaults. Builtin detectors (`enable_builtin_owasp` / `_bot` / `_scanner`) already default `true`.
- HTTP/3 is QUIC over **UDP** — the deploy must publish `443/udp`, which the current `docker-compose.yml` does not.
- Cache `backend` is overridable by the `CACHE_BACKEND` env var; compose already sets `standalone` to use the bundled Valkey.

## Phases

| Phase | Name | Status |
|-------|------|--------|
| 1 | [All-Features Config](./phase-01-all-features-config.md) | Complete |
| 2 | [Deploy Orchestration](./phase-02-deploy-orchestration.md) | Complete |
| 3 | [One-Click Script](./phase-03-one-click-script.md) | Complete |
| 4 | [Verify and Document](./phase-04-verify-and-document.md) | Complete |

## Dependencies

- Phase 2 depends on Phase 1 (compose references the new config file).
- Phase 3 depends on Phase 1 + 2 (script invokes the compose override and config).
- Phase 4 depends on all prior phases.
- No cross-plan dependencies (scanned `plans/` — no overlapping unfinished deploy plan).

## Acceptance Criteria

- `./scripts/deploy.sh` on a clean checkout brings the stack up and `curl -ksf https://localhost:16827/health` returns `status: healthy` with no manual steps.
- The running container loads `configs/full-features.toml` with HTTP/3, outbound header-strip, security hardening, sqli-scan, audit, OWASP CRS, auto-block, and Valkey cache all active — verified via `/health` component report and a config-parse check.
- A baseline attack through the proxy (e.g. SQLi to the Juice Shop host) is blocked and shows up in `/api/security-events`.
- No edits to `configs/default.toml` or any Rust crate.

## Out of Scope

Cluster HA, community/CrowdSec enrollment, ACME, production hardening (real domain, secret vaulting beyond a generated `.env`).

## Result (verified live)

Stack brought up via `docker-compose.yml` + `docker-compose.deploy.yml`; all acceptance criteria met:

- `/health` → HTTP 200 `{"status":"ok", ...}` (the binary reports `ok`, not the literal word `healthy`), `database` + `waf_engine` = `ok`. Auto-migrate + auto-create-admin confirmed — zero manual steps.
- `configs/full-features.toml` active: Valkey standalone cache connected (not memory fallback), HTTP/3 listener on `0.0.0.0:443`, outbound header-leak prevention enabled, audit JSONL sink writing, OWASP CRS + 2 host routes registered, `[interop]` off.
- SQLi probe to `Host: juice.local` blocked with **HTTP 403** and recorded in `/api/security-events` (`rule_id: SQLI-LIB`, `action: block`, libinjection). Benign request proxied 200. Outbound responses carry no `X-Powered-By`/`Server` fingerprint.
- No edits to `configs/default.toml` or any Rust crate.

**One deploy defect found and fixed during verification:** the host builds the release binary against glibc 2.39 (Ubuntu 24.04), but `Dockerfile.prebuilt` based on `debian:bookworm-slim` (glibc 2.36), so the host binary crash-looped with `GLIBC_2.38/2.39 not found`. Fix: parameterized `Dockerfile.prebuilt`'s base via `ARG BASE_IMAGE` (default unchanged `debian:bookworm-slim`, so cluster/e2e/CI consumers are untouched); the deploy override passes `BASE_IMAGE: debian:trixie-slim` (glibc 2.41). Code-reviewed DONE, no must-fix.
