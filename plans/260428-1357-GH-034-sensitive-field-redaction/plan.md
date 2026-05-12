---
name: FR-034 Sensitive Field Redaction in Response JSON (v2 — origin/main architecture)
description: Per-host JSON field redactor for upstream response bodies. Mirrors AC-17 body-mask filter pattern (per-host config on HostConfig + compiled cache + chunk-streaming filter in gateway::filters). Code = field catalogs + family toggles, config = per-host activation + extras.
type: implementation
status: completed
created: 2026-04-28
revised: 2026-04-28T15:57+04:00
completed: 2026-04-28T17:36+04:00
branch: feat/fr-034-response-field-redaction
target_pr: https://github.com/future-and-go/mini-waf/pull/18
scope: FR-034 only (FR-033 still deferred)
blockedBy: []
blocks: []
follows: 260426-1919-GH-035-detection-hardening
research: research/researcher-01-best-practices.md, research/researcher-02-pingora-streaming.md
red_team_review: ../reports/code-review-260428-1404-GH-034-plan-redteam.md
---

# FR-034 — Sensitive Field Redaction in Response JSON (v2)

## Why v2

The original v1 plan (now in `v1-superseded/`) was authored against the colleague's `feat/fr-035-header-leak-prevention` branch state, which has a **global** `OutboundConfig` and a `waf-engine::outbound` module. **`origin/main` does not have any of that** — the FR-035 work is unmerged. Main's architecture (post FR-001 reverse-proxy refactor) is:

- **Per-host policy via `HostConfig`** in `waf-common::types` (the AC-17 body-mask, AC-15 header-blocklist, AC-16 server scrub all live here as flat fields).
- **Filter chain** for *header* transforms (`pipeline::ResponseFilterChain` of `Arc<dyn ResponseFilter>` impls).
- **Body filtering** is **not** in the chain — it's dispatched directly from `WafProxy::response_body_filter`, with state in `GatewayCtx::body_mask: BodyMaskState` and a per-host cache `Arc<DashMap<usize, Arc<CompiledMask>>>`.

FR-034 adopts the **AC-17 pattern verbatim**, sibling to it. No new architectural concepts.

The research artifacts (`research/researcher-01-best-practices.md` for the field catalog + redaction trade-offs, `research/researcher-02-pingora-streaming.md` for Pingora's `response_body_filter` semantics) **still apply**. The red-team report (`../reports/code-review-260428-1404-GH-034-plan-redteam.md`) drove the safe-by-default polarity, fail-open default, mask-string call-out, and EOS-unreliability guard — all preserved here.

## Design Anchor (mandatory contract)

```
Field-name catalogs        → const tables in gateway::filters::response_json_field_redactor (per family)
Per-host activation         → HostConfig fields (booleans + extras), compiled into CompiledRedactor
Composition with AC-17      → FR-034 buffers + parses + emits on EOS;
                              AC-17 then runs over the redacted bytes (single-chunk).
                              Both run in WafProxy::response_body_filter, FR-034 first.
```

No regex DSL. No JSONPath. No per-route policy. No upstream rewrite. No global TOML knob.

## Mirror-AC-17 Inventory

| Concern | AC-17 (existing) | FR-034 (new) |
|---|---|---|
| HostConfig field(s) | `internal_patterns: Vec<String>`, `mask_token: String`, `body_mask_max_bytes: u64` | `redact_pci/banking/identity/secrets/pii/phi: bool`, `redact_extra_fields: Vec<String>`, `redact_mask_token: String`, `redact_max_bytes: u64`, `redact_case_insensitive: bool` |
| Compiled type | `CompiledMask { regex, mask, max_bytes, keep_tail }` | `CompiledRedactor { fields: HashSet<String>, mask: Bytes, max_bytes: u64, case_insensitive: bool }` |
| GatewayCtx state | `body_mask: BodyMaskState { enabled, tail, processed, ceiling_logged }` | `body_redact: BodyRedactState { enabled, buffer, processed, done, overflow_logged }` |
| WafProxy cache | `body_mask_cache: Arc<DashMap<usize, Arc<CompiledMask>>>` | `body_redact_cache: Arc<DashMap<usize, Arc<CompiledRedactor>>>` |
| Resolve method | `resolve_mask(hc) -> Arc<CompiledMask>` | `resolve_redactor(hc) -> Arc<CompiledRedactor>` |
| Decision in `response_filter` | identity encoding + non-noop → enable; drop `Content-Length` | identity encoding + JSON content-type + non-noop → enable; drop `Content-Length` (only if not already dropped by AC-17) |
| Body filter API | `apply_chunk(state, compiled, body, eos)` (chunk-streaming) | `apply_chunk(state, compiled, body, eos)` (buffers until EOS or cap, then parses + redacts + emits) |
| Failure mode | fail-open (drop invalid regex; warn-log; cap → forward unchanged) | fail-open (cap → drain unchanged + warn; malformed JSON → forward original; non-JSON shouldn't reach us due to `response_filter` gate) |
| Filter file | `gateway/src/filters/response_body_mask_filter.rs` (282 LOC) | `gateway/src/filters/response_json_field_redactor.rs` (~300 LOC budget) |

## Detection Families (in code, not config)

| Toggle (HostConfig) | Hard-coded fields (case-insensitive exact match) | Default | Driver |
|--------|--------------------------------------------------|---------|-----------------|
| `redact_pci` | `card_number`, `cardnumber`, `credit_card`, `creditcard`, `cc_number`, `ccnumber`, `cvv`, `cvc`, `cvv2`, `expiration_date`, `exp_date`, `pin` | `false` | PCI-DSS Req 3.4 |
| `redact_banking` | `bank_account`, `bankaccount`, `account_number`, `accountnumber`, `routing_number`, `iban`, `bic`, `swift_code` | `false` | banking compliance |
| `redact_identity` | `ssn`, `social_security_number`, `tax_id`, `passport_number`, `driver_license`, `national_id` | `false` | OWASP PII |
| `redact_secrets` | `password`, `api_key`, `apikey`, `secret`, `client_secret`, `token`, `auth_token`, `access_token`, `refresh_token`, `private_key` | `false` | OWASP A02:2021 |
| `redact_pii` | `phone_number`, `phonenumber`, `email`, `email_address`, `dob`, `date_of_birth`, `mother_maiden_name` | `false` | high false-positive surface |
| `redact_phi` | `patient_id`, `medical_record_number`, `insurance_id`, `health_record` | `false` | HIPAA niche |

`redact_extra_fields: Vec<String>` extends every active family with operator-supplied names.

**Defaults all OFF.** This matches AC-17's posture (`internal_patterns` defaults empty → noop). Operators opt in per-host. Zero behavior change for hosts that don't configure any redact_* toggle.

## Walk Semantics

- Walk recursively through `serde_json::Value::Object` and `Value::Array`.
- Match field NAMES (keys) against the active set; values irrelevant.
- Match is **case-insensitive** when `redact_case_insensitive=true` (default).
- Replace matched value with the configured `redact_mask_token` string regardless of original JSON type (string / number / bool / null / nested object / array — all collapse to a JSON string).
- Empty body, JSON array root, JSON scalar root → still walk; no crash.
- Hard cap on input size: `redact_max_bytes` (default 256 KiB). Over cap → fail-open + warn-log once.
- Detection of "no field matched" → return `None` from `redact_bytes` so caller forwards the original buffer cheaper than re-serialising the parsed value.

## Composition with AC-17 (decided)

In `response_body_filter`, run **FR-034 first**, then **AC-17**. Single dispatch:

```rust
fn response_body_filter(...) {
    if ctx.body_redact.enabled {
        apply_redact_chunk(&mut ctx.body_redact, &redactor, body, eos);
        // While buffering, redact swallows chunks → *body = None.
        // On EOS (or cap), redact emits the full body in *body.
    }
    if ctx.body_mask.enabled {
        apply_body_mask_chunk(&mut ctx.body_mask, &mask, body, eos);
    }
    Ok(None)
}
```

When FR-034 buffers, `*body = None` → AC-17 sees nothing → no-op. On EOS, FR-034 emits the redacted full body → AC-17 runs over it (single-chunk + EOS).

**Order rationale:** field-name redaction happens on parsed JSON; AC-17's regex value-masking is byte-level. If AC-17 ran first, the parser might still see the redacted token as a String value and wouldn't break — but running FR-034 first reduces AC-17's scan area (mask token is short) and is the natural composition.

## Skip Conditions (decided in `response_filter`)

| Condition | Behaviour |
|-----------|-----------|
| `Content-Encoding` is anything other than `identity` / absent | skip — `tracing::debug!` once (mirror AC-17 line 362) |
| `Content-Type` not `application/json` and not `application/*+json` | skip — no log (most responses are HTML) |
| `Content-Type: text/event-stream` / `application/x-ndjson` | rejected by `is_json_content_type` → skip |
| `CompiledRedactor::is_noop()` (every family off + zero extras) | skip — zero cost |
| Any other condition | enable + drop `Content-Length` (replacement length differs) |

`Content-Length` drop happens only if AC-17 hasn't already dropped it.

## Failure Mode = Fail-Open (preserved from v1)

If redaction can't run (over cap, malformed JSON, serde error mid-walk) → forward original body and emit `tracing::warn!(reason, processed)`. Rationale unchanged from v1: FR-034 is defense-in-depth; killing legitimate responses is worse than a single leak in degraded conditions.

## Cache Interaction (verified 2026-04-28)

`crates/gateway/src/cache.rs` defines `CachedResponse` / moka instance, but **`proxy.rs` does NOT wire the cache into the request path** today (zero `cache.get` references in `proxy.rs`). Same as v1 finding. Implication for FR-034: every response is fresh, redaction unconditional when opted in. When cache eventually wires in (separate plan), it must store either pre-redaction bytes (and re-redact on hit) or post-redaction bytes — that plan owns the decision.

## Phases (3, not 4)

| # | Phase | File | Status |
|---|-------|------|--------|
| 01 | HostConfig fields + redactor filter (logic + 19 unit tests) | [phase-01-host-config-and-redactor-filter.md](./phase-01-host-config-and-redactor-filter.md) | todo |
| 02 | GatewayCtx + WafProxy wiring + integration tests + docker verify | [phase-02-gateway-wiring-and-tests.md](./phase-02-gateway-wiring-and-tests.md) | todo |
| 03 | Docs sync + commits + PR vs main | [phase-03-docs-and-ship.md](./phase-03-docs-and-ship.md) | todo |

Collapsing v1's phase-04 (ship) into v2's phase-03; the heavy lifting is in 01+02.

## Build & Test = Docker Only

Per user instruction: **no local `cargo` runs**. All build/test inside containers.

The repo ships:
- `Dockerfile` — full release build (apt deps + cargo build, then runtime image).
- `Dockerfile.prebuilt` — uses `target/release/prx-waf` from host. Not viable here (we'd need to build first).
- `docker-compose.yml` — full stack (postgres + prx-waf).

For dev iteration we use a one-shot **builder container** (no host writes outside `target/`):

```bash
podman run --rm \
  -v "$PWD":/work:Z \
  -v "$PWD/.cargo-cache":/usr/local/cargo/registry:Z \
  -v "$PWD/.cargo-target":/work/target:Z \
  -w /work \
  docker.io/rust:1.86-slim-bookworm \
  bash -c "apt-get update && apt-get install -y --no-install-recommends pkg-config libssl-dev clang cmake \
           && cargo fmt --all -- --check \
           && cargo clippy --workspace --all-targets --all-features -- -D warnings \
           && cargo test --workspace"
```

Phase 02 verifies this incantation works once and pins it. Subsequent phases re-use the cache volumes.

(If the user already has a project-standard "dev container" command, defer to that. Otherwise the above is the fallback.)

## Success Criteria

- `cargo fmt --all -- --check` (in container) clean
- `cargo clippy --workspace --all-targets --all-features -- -D warnings` (in container) clean
- `cargo build --release` (in container) green
- `cargo test --workspace` (in container) green; ≥ 19 unit tests + ≥ 6 integration tests added (no existing tests regress)
- p99 added latency on a 50 KB JSON body / 5 sensitive fields < 1.5 ms (deferred bench, not blocking)
- Branch `feat/fr-034-response-field-redaction` (already created) commits pushed; PR opened against `main`
- PR body / commit messages contain ZERO leaked content (no agent references, no prompts, no PAT)

## Risk

| Risk | Mitigation |
|------|-----------|
| Buffering breaks SSE / chunked-streaming JSON endpoints | `is_json_content_type` rejects `text/event-stream` + `application/x-ndjson` |
| Compressed responses pass through unredacted (silent leak) | `tracing::debug!` once per skipped compressed response (mirror AC-17 line 362); operator visibility |
| Replaced body size mismatch with `Content-Length` | Drop `Content-Length` in `response_filter` when redactor enables (mirror AC-17 line 360) |
| `response_body_filter` `end_of_stream` may never fire | Filter also flushes when `state.processed >= max_bytes` even without EOS |
| Composition order with AC-17 wrong | Integration test: response with both AC-17 internal-IP pattern AND a `card_number` field — assert both redacted in final body |
| Per-host cache leak when config changes | Cache key is `Arc::as_ptr(hc) as usize`; on hot-reload `Arc<HostConfig>` is replaced → new cache entry. Old entries garbage-collect when DashMap pressure forces eviction (acceptable; no GC needed for hackathon) |
| Fields like `email` / `phone_number` redacted by mistake on user-listing endpoints | All families default OFF; operator opts in per host, per family |
| Test response too large to fit cap | `redact_max_bytes` is operator-configurable; raise if needed |
| Composing `Vec<String>` per nested object during walk | Matches AC-17 hot-path overhead level; benchmarked separately if needed |

## Out of Scope (explicit)

- **Compressed body redaction.** Skip-on-non-identity is the entire compression strategy in v2. Decompress / force-identity-upstream deferred.
- **Type preservation under redaction.** Redacted slot becomes a JSON string regardless of original type. Typed clients with strict types may see schema changes — acceptable for sensitive fields.
- **Partial masking** (`****-****-****-1234`). Always full mask token.
- **JSONPath / dotted-path field rules.** Names match anywhere in the tree.
- **Global TOML config.** Per-host only (matches house style).
- **Hot reload of redactor config.** Implicit via `HostConfig` reload — when `Arc<HostConfig>` is replaced, the per-host cache entry naturally diverges.
- **FR-033** (response-body value scanning for stack traces / API keys) — separate plan. FR-034 only redacts JSON FIELDS by name; FR-033 will scan VALUES for patterns.
- **NDJSON / streaming JSON / SSE redaction.** Hard skip.
- **Cluster sync of redactor config.** Stateless — ships via `HostConfig` storage layer, no FR-034-specific sync.

## Standards & References

- OWASP API Security Top 10 (2023) — API3:2023 Broken Object Property Level Authorization
- PCI-DSS Req 3.4 — Render PAN unreadable
- HIPAA §164.514(b) — De-identification of PHI
- CWE-200 (Information Exposure)
- Research: `research/researcher-01-best-practices.md`, `research/researcher-02-pingora-streaming.md`
- Red-team: `../reports/code-review-260428-1404-GH-034-plan-redteam.md` (issues C1-C3 + M1-M8 — see "Red-Team Carry-Over" below)

## Red-Team Carry-Over (from v1, reapplied to v2)

| v1 issue | Status in v2 |
|---|---|
| C1: Wrong return type for `response_body_filter` | **N/A on main** — main's signature is `fn response_body_filter(...) -> pingora_core::Result<Option<Duration>>` (researcher-02 was correct, red-team reviewer was confused by colleague's branch having a different `request_body_filter` shape). v2 phase-02 spec uses main's actual signature verbatim. |
| C2: Cache claim unverified | **Re-verified** — main's `proxy.rs` still has zero cache wiring; same conclusion holds. |
| C3: Skip-flag polarity fragile | **Mooted** — AC-17 mirror uses `enabled: bool` defaulting `false`, only set to `true` in `response_filter` on affirmative opt-in. Same safe-by-default pattern. |
| M1: Compression silent leak | `tracing::debug!` once per skipped compressed response — same as AC-17. |
| M2: Case-folding extras | Documented; default `redact_case_insensitive=true` lower-cases extras at compile-time. |
| M3: Mask collapses types | Documented in "Out of Scope". |
| M4: EOS may never fire | Filter also flushes on `processed >= max_bytes`. |
| M5: Multi-chunk test spec vague | Phase 02 integration test spec uses 3-chunk EOS-pattern with byte-level assertions. |
| M6: `crates/gateway/tests/` doesn't exist | Still doesn't on main. v2 phase-02 creates it. |
| M7: Skip relies on `response_filter` | Same as AC-17; acceptable. |
| M8: FR-033 boundary | Documented in "Out of Scope". |

## Open Questions for User

1. **Mask token default** — `***REDACTED***` (matches v1 + logging-masker plan) or `[redacted]` (matches AC-17's `mask_token` default)? Plan ships `***REDACTED***` distinct from AC-17 because (a) FR-034 redacts SENSITIVE values, AC-17 masks INTERNAL refs — different semantic; (b) operators may want to grep server logs for "REDACTED" specifically. Override with `redact_mask_token` per host.
2. **Body cap default** — 256 KiB (per researcher-02) or 1 MiB (AC-17's `body_mask_max_bytes` default)? Plan ships **256 KiB** distinct from AC-17 because parsing JSON is more expensive than regex scanning. Override per host.
3. **Filter file size** — projected ~300 LOC. AC-17 filter is 282 LOC. If FR-034 grows beyond 350 LOC during phase-01, split into `response_json_field_redactor/{mod.rs, families.rs, walker.rs}`.
4. **Cargo dev-container command** — does the team have a standard one? Plan currently includes a generic `rust:1.86-slim-bookworm` recipe. Replace if there's a project standard.
