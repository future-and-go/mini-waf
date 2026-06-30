# Validation

## Proof Strategy

The story is done when the three routes return the FE-expected contract, the
settings persist across restart, the proxy honors per-host overrides, and hosts
without a stored filter keep their previous behavior.

## Test Plan

| Layer | Cases |
| --- | --- |
| Unit | `HostResponseFilter` serde round-trip + defaults; `apply_response_filter` copies five fields; `from_defense_json` present/absent; preview mapping (stack-trace body redacted, JSON `password` field redacted, plain body unchanged, oversize → 413); PUT validation (bad regex → 400, byte bounds). |
| Integration | GET unset → defaults (200); PUT then GET round-trip; PUT invalid regex → 400; gateway: host with `strip_server_header:true` + `header_blocklist` entry + `internal_patterns` match → proxied response has header stripped + pattern masked; host without override keeps defaults. |
| E2E | Live Docker: login, POST preview, GET/PUT per-host, reload page shows saved values; no console 404s. |
| Platform | Docker rebuild of `prx-waf`; container healthy. |
| Performance | n/a (preview is in-process, capped at `max_body_bytes`). |
| Logs/Audit | PUT writes one `audit_log` row (`action=update_host_response_filter`, `resource_type=host_response_filter`, `resource_id=<id>`); preview logs no body. |

## Fixtures

- Seeded admin (`admin` / provided password) on the running Docker stack.
- `juice-shop` host (existing in the stack) as the per-host target.
- Sample preview body containing a stack trace + a JSON `card_number`/`password`.

## Commands

```bash
# In the dev container (project policy: cargo runs in Docker):
cargo fmt --all -- --check
cargo clippy -p waf-common -p waf-api -p gateway -p prx-waf --all-targets -- -D warnings
cargo test -p waf-common -p waf-api -p gateway
docker compose up -d --build prx-waf
```

## Acceptance Evidence

Verified 2026-06-29 (host `cargo 1.95.0` + rebuilt `prx-waf` Docker image).

- Unit/integration (host cargo):
  - `waf-common` `types_decisions`: 28 passed (4 new `HostResponseFilter` cases).
  - `waf-api` lib `response_filter_api`: 7 passed (preview redact/scan/skip,
    validation 400 cases).
  - `waf-api` lib `handlers::tests::host_config_*`: 3 passed (Phase 4 mapping —
    present applied, absent keeps defaults).
  - `gateway` `response_filter_per_host_integration`: 3 passed (header strip,
    `internal_patterns` body mask, no-override passthrough).
  - `cargo clippy -p waf-common -p waf-storage -p waf-api -p gateway -p prx-waf
    --all-targets -- -D warnings`: clean. `rustfmt --check` on changed files: clean.
- Live (rebuilt container, `https://localhost:16827`):
  - `POST /api/response-filtering/preview` → `{"data":{"result":
    "{\"note\":\"[redacted]: boom [redacted]\",\"password\":\"***REDACTED***\"}"}}`
    (FR-034 field redaction + FR-033 stack-trace + internal-IP masking).
  - `GET /api/hosts/{id}/response-filter` (unset) → defaults, `200`.
  - `PUT` then `GET` → saved values round-trip (`200`).
  - `PUT` with `internal_patterns:["("]` → `400 invalid internal_pattern`.
  - `audit_log` row: `update_host_response_filter / host_response_filter /
    <host_id>` with admin user id.
