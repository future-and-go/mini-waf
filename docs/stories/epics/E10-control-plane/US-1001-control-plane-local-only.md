# US-1001 Mount control plane local-only, never proxied upstream

## Status

planned

## Lane

high-risk

## Product Contract

The `/__waf_control/*` route group is served by the WAF control plane, bound local/admin-only, and never forwarded to upstream on the proxy data path. Control requests terminate at the WAF; they must not leak into upstream traffic or appear as proxied responses. This isolates benchmark orchestration from the data plane (interop v2.3 §2.1).

## Relevant Product Docs

- `docs/product/waf-control-plane.md`
- interop v2.3 §2.1 (control plane endpoints, local/admin-only mount)

## Acceptance Criteria

- Requests under prefix `/__waf_control` are routed to `interop_control_routes`, not the proxy handler.
- The control plane is bound to local/admin-only listener, not the public proxy listener.
- A request matching `/__waf_control/*` is never forwarded to upstream.
- Proxy data path explicitly excludes the control prefix from forwarding.
- All four control endpoints (`capabilities`, `reset_state`, `set_profile`, `flush_cache`) mount under this prefix.

## Design Notes

- Commands: none.
- Queries: none.
- API: control route group mounted at prefix `/__waf_control` via `interop_control_routes` in `crates/waf-api/src/interop_control.rs`; wired in `crates/waf-api/src/server.rs`.
- Tables: none.
- Domain rules: control prefix terminates at WAF; never proxied upstream; bound local/admin-only.
- UI surfaces: none.
- Endpoint: (prefix) /__waf_control/*

## Validation

When updating durable proof status, use numeric booleans:
`scripts/bin/harness-cli story update --id <id> --unit 1 --integration 1 --e2e 0 --platform 0`.

| Layer | Expected proof |
| --- | --- |
| Unit | Route group builds with all four control routes under the prefix. |
| Integration | `crates/waf-api/tests/interop_control_integration.rs` asserts control prefix handled by control plane and not forwarded upstream. |
| E2E | Control request issued local-only; proxy data path shows no upstream forward for the control prefix. |
| Platform | Linux/macOS local listener binds local/admin-only. |
| Release | Control plane unreachable on public proxy listener. |

## Harness Delta

Story registered under decision 0008-interop-contract-v2.3-adoption; durable proof booleans set via harness-cli after verification.

## Evidence

Code present: `crates/waf-api/src/interop_control.rs`, `crates/waf-api/src/server.rs`, `crates/waf-common/src/config.rs`. Durable proof unset pending `harness-cli story verify`.
