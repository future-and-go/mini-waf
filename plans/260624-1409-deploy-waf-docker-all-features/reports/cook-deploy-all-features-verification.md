# Cook Verification Report — Deploy WAF (all single-node features, one-click)

Plan: `plans/260624-1409-deploy-waf-docker-all-features/plan.md`
Date: 2026-06-24
Mode: `/ck:cook` code (execute existing plan)
Branch: `main-harness`

## Outcome

All four acceptance criteria met, verified against a live stack
(`docker-compose.yml` + `docker-compose.deploy.yml`). Code-reviewed: DONE, no
must-fix.

## Verification matrix (live)

| # | Check | Result |
|---|-------|--------|
| 1 | `/health` reachable, healthy | HTTP 200 `{"status":"ok"}`, `database`+`waf_engine` = ok |
| 2 | full-features config loaded | 2 host routes registered; `[interop]` off |
| 3 | Valkey cache (standalone) | `ValkeyStore connected seeds=["valkey:6379"]` — not memory fallback |
| 4 | HTTP/3 (QUIC UDP 443) | `HTTP/3 listener on 0.0.0.0:443`; `16843:443/udp` published |
| 5 | Outbound header-strip + audit | `Outbound header-leak prevention (FR-035) enabled`; `Audit log file sink active` |
| 6 | Benign request through proxy | `Host: juice.local` → HTTP 200 (proxied to Juice Shop) |
| 7 | SQLi probe blocked | `/rest/products/search?q=1' OR '1'='1` → **HTTP 403** |
| 8 | Block recorded in events | `/api/security-events` → `rule_id:SQLI-LIB action:block` (libinjection) |
| 9 | Outbound fingerprint strip | proxied response has no `X-Powered-By` / `Server` |
| 10 | Audit JSONL written | `/app/waf_audit.log` 1918 bytes, block + allow event lines |

Acceptance criteria → all PASS. No edits to `configs/default.toml` or any Rust
crate (git diff confirms only `.gitignore`, `Dockerfile.prebuilt`, `README.md`
modified; configs/scripts/docs added).

## Deploy defect found and fixed

The plan's chosen build mode is "prebuilt binary": `cargo build --release` on the
host, then `Dockerfile.prebuilt`. On this host (Ubuntu 24.04, glibc 2.39) the
binary crash-looped in the container:

```
/usr/local/bin/waf: /lib/x86_64-linux-gnu/libc.so.6: version 'GLIBC_2.38' not found
```

`Dockerfile.prebuilt` based on `debian:bookworm-slim` (glibc 2.36) — too old for a
binary linked against the host's 2.39.

**Fix (minimal, backward compatible):**
- `Dockerfile.prebuilt`: `ARG BASE_IMAGE=debian:bookworm-slim` before
  `FROM ${BASE_IMAGE}`. Default preserves prior behavior, so the other consumers
  (`docker-compose.cluster.yml`, `tests/e2e/*`, nightly-e2e CI) that pass no
  build arg still build on `bookworm-slim`.
- `docker-compose.deploy.yml`: pass `build.args.BASE_IMAGE: debian:trixie-slim`
  (glibc 2.41 ≥ host 2.39).

Reviewer confirmed BASE_IMAGE is passed in exactly one place (the deploy
override), isolating blast radius.

## Change set

New: `configs/full-features.toml`, `configs/full-features-panel.toml`,
`docker-compose.deploy.yml`, `.env.example`, `scripts/deploy.sh`,
`docs/all-features-docker-deploy.md`.
Modified: `Dockerfile.prebuilt`, `README.md`, `.gitignore`.

## Code review

`code-reviewer` subagent — Status DONE, zero must-fix. Constraints 1–4 (no
default.toml/crate edits; ARG backward compatibility; no committed secrets;
deploy.sh idempotent) all verified at file:line. TOML configs validated against
`config.rs` / `panel_config.rs` (panel `deny_unknown_fields` clean; risk bands
51<74<75 ordered; `[interop] enabled=false` load-bearing).

One nice-to-have applied: corrected an inaccurate comment in
`full-features.toml` (the main config is not `deny_unknown_fields`, so unknown
keys silently no-op rather than failing the boot).

## Open items

- `data/ip2region_*.xdb` absent → GeoIP logs a warning and disables lookups (by
  design; `prx-waf geoip download` fetches them). Not a blocker.
- Juice Shop container reports `unhealthy` on its own healthcheck but serves
  traffic (200 through the proxy) — upstream image quirk, unrelated to the WAF.
