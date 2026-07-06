# 2026-07-06 — FR-025 Risk Engine: Config Surface, Admin UI, E2E Testability Investigation

**Date:** 2026-07-06
**Severity:** Medium
**Component:** waf-engine (risk scoring, admin UI, e2e harness)
**Status:** Investigation complete; findings documented; follow-ups identified

## What Happened

Conducted a comprehensive investigation into FR-025 (cumulative risk scoring engine) to understand: (1) the full risk configuration surface and toggle inventory, (2) which settings the admin UI exposes and how they interact with the backend, (3) which configurations and toggles are meaningfully testable via the e2e harness. Read across 7 source files + e2e stack; verified all claims against live code. Two substantive findings surfaced.

## The Brutal Truth

The risk engine configuration story is more complex than it initially appears, and the e2e test stack has a silent failure that makes risk scoring unobservable in end-to-end tests. Both findings are actionable but require explicit decisions to fix. The first is a dead-code issue; the second is a harness bug that masks the entire risk scoring layer from e2e validation.

## Technical Details

### Config Surface Summary

Risk configuration lives in `risk.yaml` under top-level `risk:` section with two layers:

**Layer 1: risk.yaml top-level toggles** (`crates/waf-engine/src/risk/config.rs`):
- `enabled`, `ttl_secs`, `gc_interval_secs`, `session_cookie`, `header_name`, `emit_header`
- Subsections: `store` (backend + redis params), `decay`, `seed`, `ingest`, `canary`, `challenge`

**Layer 2: Per-tier decision thresholds** (outside risk config):
- `TierPolicy.risk_thresholds` (`crates/waf-common/src/tier.rs:48-52`) defines `allow`, `challenge`, `block` score boundaries per tier
- These are NOT in risk.yaml; they live in the tier policy config

**Admin UI exposure** (`web/admin-panel/src/pages/risk-scoring/index.tsx`):
- Edits only a subset of Layer 1: `enabled`, `ttl_secs`, `gc_interval_secs`, `store` backend choice, redis url/prefix, `decay.*`, `canary.*`
- Via PUT `/api/risk/config`, performs deep merge so file-only sections (`seed`, `ingest`, `challenge`) survive saves (`crates/waf-api/src/risk_api.rs:58-94`)
- Read endpoints `/api/risk/metrics` and `/api/risk/actors` are STUBS returning empty/zeros (`risk_api.rs:96-121`) — not wired to observability

### Finding 1: emit_header & header_name Are Dead Config

**Claim:** The risk-config toggles `emit_header` and `header_name` do not affect the wire header.

**Evidence:**
- The WAF gateway emits `X-WAF-Risk-Score` UNCONDITIONALLY with hardcoded name (`crates/gateway/src/waf_observability_headers.rs:8,43-57`):
  - Constant name: `const HEADER_RISK_SCORE = "X-WAF-Risk-Score"` (line 8)
  - Inject logic: `inject_waf_observability_headers` (line 43–57) calls `put(HEADER_RISK_SCORE, ctx.waf_decision_meta.risk_score)`
- The risk scorer's accessor methods `emit_header()`/`header_name()` (`crates/waf-engine/src/risk/scorer.rs:364-372`) are never called by the gateway in any path
- The accessors appear only in a unit test (`scorer.rs` test module)
- Setting `emit_header: false` or `header_name: custom-name` in risk.yaml has zero observable effect

**Impact:** Dead config clutters the schema and creates user confusion (setting it changes nothing).

### Finding 2: Risk Scoring Is Silently Disabled in E2E Stack

**Claim:** The e2e docker stack does not load risk.yaml, so risk scoring stays disabled in all e2e tests.

**Evidence:**
- Docker compose mounts config as `--config /app/e2e.toml` (`tests/e2e/docker-compose.e2e.yml:61,65`)
- Risk config path is resolved via TWO parent hops: `config_path.parent().and_then(Path::parent).join("configs/risk.yaml")` (`crates/prx-waf/src/main.rs:1651-1655`)
  - For production `configs/default.toml`: `.parent()`=`configs`, `.and_then(parent)`=repo root → `configs/risk.yaml` (correct)
  - For the top-level mount `/app/e2e.toml`: `.parent()`=`/app`, `.and_then(parent)`=`/` → seeks **`/configs/risk.yaml`**
- Neither `/configs/risk.yaml` nor any `risk.yaml` is mounted (`tests/e2e/configs/` holds only `e2e.toml`) — so `start_risk_watcher` finds nothing and risk scoring remains disabled
- Same path-resolution pattern affects `ddos.yaml` and `tx-velocity.yaml` (`main.rs:1618-1633`)

**Test coverage gap:**
- `run-interop.sh:88-96` asserts `X-WAF-Risk-Score` header PRESENCE only, never validates value
- All tests see risk score = 0 always (disabled in container)
- Browser suite (`tests/e2e/browser/challenge.spec.ts`) runs against a MOCK WAF server, not the real gateway — its `risk.yaml`/`challenge.yaml` fixtures are illustrative only

**Consequence:** Risk scoring layer is completely invisible in end-to-end validation.

## What We Tried

**Evidence gathering:**
1. Traced config bootstrap flow (`main.rs:1618–1655`) to understand path resolution
2. Grepped scorer accessors for call sites; found zero in gateway or observability code
3. Inspected docker compose mount and e2e config directory structure
4. Reviewed test assertions in `run-interop.sh` and browser suite fixtures

All claims verified by source inspection; no workarounds attempted (investigation only).

## Root Cause Analysis

**Finding 1 (dead config):**
- The `header_name` and `emit_header` fields were likely planned for future extensibility (header name customization, optional emission) but never wired into the gateway's observability header emission logic
- The gateway's hardcoded approach (`HEADER_RISK_SCORE` constant) was simpler and shipped without reversing the unused config fields
- This is a schema/code sync gap, not a complex interaction

**Finding 2 (e2e harness):**
- The path-resolution pattern `config_dir.parent()/configs/config_name.yaml` works fine for normal deployments (where config file and sibling configs are in the same directory)
- The docker mount strategy `--config /app/e2e.toml` at a top-level path breaks the assumption — it expects configs to live in `/app/configs/` but they were never mounted there
- This is a mount/orchestration bug, not a code logic error

## Lessons Learned

1. **Config inventory must be surfaced to operations.** When a codebase has toggles that do not affect behavior (Finding 1), document why (deprecated, planned, internal-only) or remove them. Expose only what is actionable.

2. **E2E test mocks must match real paths and mounts.** The docker compose setup should either (a) mount risk.yaml at the resolved path, or (b) override the path resolution for test containers. Silent disabling of entire subsystems wastes test runs.

3. **Test assertions need value checking, not just presence checking.** `run-interop.sh:88-96` asserts header presence; it should assert non-zero score for configured risk-scoring scenarios. This would have caught the disabled-scoring bug immediately.

4. **Path resolution for sidecar configs should be explicit in comments.** Relative paths like `config_dir.parent()` are fragile across different deployment topologies. Document the assumption or use an environment override.

## E2E Testability Summary (Once Harness Is Fixed)

**Easily testable via e2e:**
- `enabled` toggle (on/off, observable via presence/absence of Risk-aware decision paths)
- `canary.enabled` + `canary.paths` (returns 403 + score 100; `scorer.rs:145–168`)
- Per-tier `risk_thresholds` (allow/challenge/block transitions with synthetic risk scores)
- `risk_assessment` active/monitor mode gate (`engine.rs:962,1795–1803`; observable via `X-WAF-Mode` header, same pattern as SQLi log_only test in `run-interop.sh:111–125`)

**Testable with setup:**
- `seed.*_delta` (requires tor/asn file listing the test IP)
- `seed.whitelist_path` (whitelist file mount)
- Canary ban-on-next-request (requires DDoS ban logic active + stable test IP)
- `store: redis` (requires redis sidecar; start-time only, not hotloadable)

**Not e2e-observable:**
- `emit_header` / `header_name` (Finding 1: dead config)
- `decay.*` timing (requires controlled clock or hours to observe)
- `challenge.*` / `X-WAF-Cred` (no runtime issuer; gateway challenge uses `__waf_cc` cookie, separate subsystem)
- `ingest.*` async organic signals (requires hours/days of organic traffic, not e2e-friendly)
- Metrics/actors stubs (API endpoints not wired; zero data)

## Next Steps

1. **Fix e2e harness (blocking testability):**
   - Match the production layout the two-parent resolution expects: mount the TOML at `/app/configs/e2e.toml` (`--config /app/configs/e2e.toml` → resolves siblings to `/app/configs/risk.yaml`) and mount `risk.yaml` (+ `ddos.yaml`, `tx-velocity.yaml`) alongside it in `/app/configs/`
   - Upgrade `run-interop.sh:88–96` to assert score VALUES (non-zero for canary/high-risk paths, zero for safe paths) not just header presence
   - Verify docker compose resolves to correct path; add loud comment documenting assumption

2. **Decide fate of dead config (Finding 1):**
   - Option A: Remove `emit_header` and `header_name` from risk.yaml schema if they will never be used
   - Option B: Wire them into gateway header emission logic if the flexibility is intended
   - Option C: Document them as deprecated with migration notes
   - **Decision needed:** Which path?

---

## Unresolved Questions

1. **Finding 1 — emit_header / header_name:** Should these dead toggles be removed, wired, or documented as deprecated? The current state (present but non-functional) is a maintenance burden.

2. **Finding 2 — e2e harness:** When risk.yaml is mounted at the correct path, should the e2e setup verify that risk scoring is ENABLED before running interop tests? Currently there is no check.

