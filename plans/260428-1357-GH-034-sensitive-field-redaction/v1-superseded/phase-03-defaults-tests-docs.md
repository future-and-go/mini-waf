# Phase 03 — Default TOML Stanza, Tests, Docs

**Goal:** Make the feature *operationally complete*: default config visibility, end-to-end tests through Pingora, and minimal docs/changelog.

**Status:** todo
**Depends on:** Phase 01 + Phase 02

## Files Touched

| File | Change |
|------|--------|
| `configs/default.toml` | Append commented `[outbound.body_redactor]` stanza next to existing `[outbound.headers]` |
| `crates/gateway/tests/response_body_redaction.rs` | **NEW** — integration test using a Pingora-driven test backend (or stubbed Session) verifying end-to-end redaction |
| `docs/system-architecture.md` | Add a sub-section under outbound protection covering FR-034 |
| `docs/project-changelog.md` | Add an entry for FR-034 |
| `docs/project-roadmap.md` | Flip FR-034 from "missing" to "complete" |

## 1. `configs/default.toml` Stanza

Append directly after the existing `[outbound.headers]` block (line ~135 currently). Match the comment style used for FR-035:

```toml
# ── FR-034: Outbound Sensitive Field Redaction (response JSON bodies) ─────────
# Mask known-sensitive fields in JSON response bodies before forwarding to the
# client. Field-name catalogs (per family) are hard-coded in waf-engine; this
# section only decides which families are active and lets the operator extend.
# Disabled by default — opt in by setting enabled = true.
#
# Skip conditions (always-on, not configurable in v1):
#   * Content-Type not application/json or application/*+json  → pass through
#   * Any Content-Encoding present (gzip / br / deflate / zstd) → pass through
#   * text/event-stream / application/x-ndjson                  → pass through
#   * Body exceeds body_size_cap_bytes                          → pass through + warn-log
#   * Malformed JSON                                            → pass through + warn-log
#
# Standards: PCI-DSS Req 3.4, HIPAA §164.514, OWASP API3:2023, CWE-200.
#
# [outbound.body_redactor]
# enabled                = false
# redact_pci             = true   # card_number, cvv, cc_number, pin, exp_date, …
# redact_banking         = true   # bank_account, account_number, routing_number, iban, bic, swift_code
# redact_identity        = true   # ssn, tax_id, passport_number, driver_license, national_id
# redact_secrets         = true   # password, token, api_key, secret, refresh_token, private_key
# redact_pii             = false  # phone_number, email, dob, mother_maiden_name (off — high false-positive in legitimate user-listing APIs)
# redact_phi             = false  # patient_id, medical_record_number, insurance_id, health_record (HIPAA — opt-in)
# extra_fields           = []     # extra exact field names; extends every active family
# case_insensitive       = true   # match "card_number" / "Card_Number" / "CARDNUMBER" identically
# body_size_cap_bytes    = 262144 # 256 KiB; over cap → pass through + warn-log
```

Keep ALL lines commented out — same convention as `[outbound.headers]`. Operator must uncomment to opt in.

## 2. Integration Test

**State check (verified 2026-04-28):** `crates/gateway/tests/` directory **does NOT exist**. There is no integration-test precedent for the gateway crate; existing test scaffolding is engine-side (`crates/waf-engine/tests/sql_injection_acceptance.rs`). Phase 02's `response_body_filter` is the first hook outside `request_body_filter` we'll need to integration-test in this crate. (Red-team M6.)

**Decision:** create `crates/gateway/tests/` and add `response_body_redaction.rs`. New territory but small surface — one file, ~10 cases, ~250 LOC.

**Strategy choice (red-team M6):**

- **A. Pure-function test against `BodyRedactor::redact_bytes`** — already covered in Phase-01 unit tests. Insufficient for verifying chunk-stealing and the `response_filter` opt-in flow.
- **B. Hand-rolled fake `Session` + manual hook invocation** — `pingora_proxy::Session` is not constructible outside the Pingora crate easily. Likely needs `unsafe` or a thin trait abstraction we don't have today.
- **C. Spawn a real Pingora server in-test against a canned upstream** — the only way to actually verify the chain. Heavier (~50 ms per case) but stable. Pingora ships test helpers under `pingora-core/src/services/listening` we can lean on; the existing `tests/e2e-cluster.sh` already proves the binary boots clean in test mode.

**Pick C.** Build a single test fixture that:
1. Spins an `ephemeral_port`-bound Pingora gateway with `body_redactor` enabled (or disabled per-case).
2. Spins a `tiny_http`/`hyper` mock upstream that serves canned JSON (or text/html, or gzipped bytes) per case.
3. Issues a `reqwest` GET against the gateway, asserts on the response body / headers.

If fixture construction proves heavier than expected (>500 LOC scaffolding or flaky port-binding), DROP integration tests — the Phase-01 unit tests already cover the redaction logic; the Pingora-hook glue is small enough that careful code review + manual smoke test (Phase-04 PR description test plan) carries acceptable risk. Document the decision in the test file's top comment either way.

### Test Cases (≥ 8)

| # | Setup | Body in | Expected body out |
|---|-------|---------|-------------------|
| 1 | enabled=false | `{"card_number":"4111"}` | identical (no redaction) |
| 2 | enabled=true, content-type=application/json | `{"card_number":"4111","name":"alice"}` | `card_number` masked, `name` unchanged |
| 3 | enabled=true, content-type=text/html | `<p>4111</p>` | identical (skipped) |
| 4 | enabled=true, Content-Encoding: gzip | gzipped JSON with `card_number` | identical compressed bytes (skipped) |
| 5 | enabled=true, multi-chunk JSON delivered in 3 chunks (chunk1: `{"a":"x","b":`, chunk2: `"y","ssn":`, chunk3: `"1"}`) with `end_of_stream=false,false,true` | first two `response_body_filter` calls leave `*body = None` and accumulate; third call assembles full JSON, emits redacted body with `ssn` masked. Asserts: `body_redactor_done` transitions `false → false → true`; final `*body.as_ref().unwrap().len()` equals `serde_json::to_vec(redacted).len()` (NOT the sum of input chunk lengths — the mask string changes size); `name`/`a`/`b` fields preserved verbatim in final JSON |
| 6 | enabled=true, body > cap | 300 KiB JSON containing card_number | original bytes preserved (fail-open), warn-log emitted |
| 7 | enabled=true, malformed JSON | `{not json` | identical bytes (fail-open) |
| 8 | enabled=true, content-type=application/vnd.api+json | `{"data":{"attributes":{"ssn":"1"}}}` | nested `ssn` masked |
| 9 | enabled=true, content-type=text/event-stream | `data: {"card_number":"x"}\n\n` | identical (SSE skipped) |
| 10 | enabled=true, redact_pii=false | `{"email":"a@b","ssn":"1"}` | only `ssn` masked, `email` preserved |

### Performance Sanity Check (single criterion benchmark — optional)

Add `crates/waf-engine/benches/body_redactor.rs` (criterion) with one bench: 50 KB JSON, 5 sensitive fields, all families on. Target: `< 1.5 ms` per redaction on the dev machine. Mark as optional — skip if benches infrastructure is heavy.

## 3. Docs Updates

### `docs/system-architecture.md`

Find the existing FR-035 outbound section (under "Outbound Protection" or similar). Add a sibling subsection:

```markdown
#### FR-034 — Sensitive Field Redaction (Response Body)

Detect-and-mask configured sensitive fields in JSON response bodies. Implemented
in `waf-engine::outbound::body_redactor::BodyRedactor` with a per-family const
catalog (PCI, banking, identity, secrets, PII, PHI). Operators activate
families and extend with `extra_fields[]` via `[outbound.body_redactor]` in TOML.

Hook: Pingora `response_body_filter` (post-cache). Buffer cap: 256 KiB.
Skip conditions: non-JSON content-type, any Content-Encoding, oversize, malformed.
Failure mode: fail-open with `tracing::warn!`.

See: `plans/260428-1357-GH-034-sensitive-field-redaction/`.
```

### `docs/project-changelog.md`

Add a top-of-list entry:

```markdown
## Unreleased

- **FR-034 — Sensitive field redaction in response JSON bodies** (`feat/fr-034-response-field-redaction`).
  Six detection families (PCI, banking, identity, secrets, PII, PHI) hard-coded;
  toggles + `extra_fields[]` configurable via `[outbound.body_redactor]`.
  Disabled by default; PII / PHI families default off when enabled. 256 KiB body cap.
  Skips compressed and non-JSON responses (out-of-scope deferred). Pingora
  `response_body_filter` hook; cache-hits redacted same as fresh responses.
```

### `docs/project-roadmap.md`

Find the FR-034 row in the gap-analysis table (or "Outbound Protection" section). Flip status from `MISSING` → `COMPLETE` and link to the PR (placeholder, fill in Phase 04).

## Pre-Edit Impact Check (gitnexus)

Before any code edit:
```
gitnexus_impact({target: "BodyRedactor", direction: "upstream"})
gitnexus_impact({target: "GatewayCtx", direction: "upstream"})
```
After all changes:
```
gitnexus_detect_changes()
```
Confirm only expected symbols changed.

## Build Verification (gate before Phase 04)

```bash
cargo fmt --all -- --check
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo test --workspace
cargo build --release
```

ALL of the above clean. No skipped tests. No `cargo test` failures (development-rules.md forbids ignoring failures).

## Success Criteria

- ≥ 10 integration test cases pass.
- Existing test suite (incl. FR-035 tests, SQLi tests, e2e) all pass — no regressions.
- `configs/default.toml` parses with the new (commented) stanza present, and (when uncommented) loads cleanly into `OutboundConfig`.
- `docs/` updates committed alongside code.
- p99 redaction overhead measurable but inside the 1.5 ms / 50 KB body budget.

## Out of Scope (Phase 03)

- Performance tuning beyond meeting the 1.5 ms budget.
- Adding `application/yaml` / `application/xml` redaction.
- Cluster sync (no new state).
- Hot-reload of the redactor specifically (the existing config reload path covers `OutboundConfig` already; verify by inspection, no new code).
