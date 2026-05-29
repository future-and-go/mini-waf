# Red-Team Review: WAF Interop Contract v2.3 Critical Compliance Plan

**Reviewer:** code-reviewer (red-team mode)
**Date:** 2026-05-27
**Verdict:** CONDITIONAL PASS

The plan is well-structured and addresses all 6 CRITICAL contract gaps. However, 3 findings are blocking (CRITICAL) and 4 are HIGH severity. If addressed, the plan is viable.

---

## Findings Table

| ID | Severity | Finding | Phase | Recommendation |
|----|----------|---------|-------|----------------|
| RT-01 | CRITICAL | `RequestCtx` has no `peer_addr` field; JSONL `ip` will use XFF-resolved IP | P3 | Add `peer_ip: IpAddr` field to `RequestCtx` |
| RT-02 | CRITICAL | WafDecision discarded after `request_filter`; unreachable in `response_filter` | P2 | Store decision on `GatewayCtx` or populate interop fields before discard |
| RT-03 | CRITICAL | Response headers NOT injected on WAF-blocked responses (403/429/503) | P2 | Inject headers in `write_waf_decision` + `handle_challenge`, not only ResponseFilter |
| RT-04 | HIGH | `is_allowed()` rename to `is_enforcement_allowed()` breaks 10+ callers incl. http3.rs | P1 | Grep-verified: 10+ call sites. Plan mentions "update all call sites" but underestimates scope |
| RT-05 | HIGH | Default `header_blocklist` strips `x-waf-version` which collides with `X-WAF-*` prefix | P2 | Rename default blocklist entry or use exact-match exclusion |
| RT-06 | HIGH | `set_profile` scope=`all` semantic ambiguity: does it clear overrides? | P4 | Contract says "SHOULD be cleared" (line 186); plan must implement override clearing |
| RT-07 | HIGH | Engine has 11 `log_only_mode` branches; plan says 12. Missing or extra? | P1 | Grep-verified: 11 unique occurrences. Plan's "12 detection phases" count is wrong |
| RT-08 | MEDIUM | `RuleAction::Log` still maps to `WafAction::LogOnly` via `to_waf_action()` | P1 | Custom rules with `action: log` will produce deprecated variant; must update mapping |
| RT-09 | MEDIUM | `WafDecision::block()` is `const fn` -- cannot populate `rule_id: Option<String>` | P1 | `const fn` cannot call `.clone()` or construct `Some(String)`; must un-constify |
| RT-10 | MEDIUM | No `risk_score` infrastructure in engine; Phase 1 claims "populated from scorer" | P1 | No risk scorer exists in engine.rs. `risk_score` will always be 0 unless synthesized |
| RT-11 | MEDIUM | `WafAction` serde tag `"type"` may break JSONL action field | P1 | Internally-tagged enum serializes as `{"type":"block","status":403}`, not `"block"` string |
| RT-12 | LOW | H3 path (`http3.rs:242`) has independent decision handling, not covered by plan | P2 | H3 WAF path builds its own response; needs parallel header injection |
| RT-13 | LOW | Config YAML support in Phase 5 adds a dependency for questionable value | P5 | Contract says "or ./waf.toml"; skip YAML for MVP per YAGNI |

---

## Detailed Analysis

### RT-01: CRITICAL -- `peer_addr` not stored on `RequestCtx`

**Verified at:** `crates/waf-common/src/types.rs:21-54` and `crates/gateway/src/ctx_builder/request_ctx_builder.rs:70-82`

`RequestCtx` stores `client_ip: IpAddr` which is the **XFF-resolved** IP when `trust_proxy_headers=true`. The raw TCP `peer_addr.ip()` is extracted in `request_ctx_builder.rs:70` but only used as input to `extract_client_ip_from_session()`. The result (`client_ip`) may differ from `peer_addr`.

Phase 3 claims: "RequestCtx already has the socket peer_addr stored separately." **This is false.** There is no `peer_addr` or `socket_ip` field on `RequestCtx`.

Contract requirement (section 6 + section 10): `ip` field MUST be TCP peer address, NOT XFF.

**Fix:** Add `pub socket_ip: IpAddr` to `RequestCtx`, populated from `peer_addr.ip()` in `request_ctx_builder.rs:79`. Use this for the JSONL `ip` field.

### RT-02: CRITICAL -- WafDecision not stored on context

**Verified at:** `crates/gateway/src/proxy.rs:681-692`

```rust
let decision = self.engine.inspect(&mut request_ctx).await;
if write_waf_decision(session, &decision, ...).await? {
    return Ok(true);  // response already written, decision dropped
}
// decision goes out of scope if request continues to upstream
```

`GatewayCtx` (context.rs:101-140) has no field for `WafDecision`. The `response_filter` (proxy.rs:792) cannot access it. Phase 2 proposes putting interop fields on `RequestCtx`, which is stored on `GatewayCtx.request_ctx`. This works IF the fields are populated BEFORE the `request_filter` returns.

However, the plan's Step 8 says "populate interop fields in proxy.rs after WAF engine returns decision" -- the `request_ctx` at proxy.rs:681 is a **local variable** (cloned from `ctx.request_ctx`). Changes to the local won't propagate back to `ctx.request_ctx`.

**Fix:** After populating interop fields on the local `request_ctx`, write them back: `ctx.request_ctx.as_mut().unwrap().interop_action = request_ctx.interop_action.clone()`. Or better: populate directly on `ctx.request_ctx` before cloning.

### RT-03: CRITICAL -- Headers missing on WAF-generated responses

**Verified at:** `crates/gateway/src/proxy_waf_response.rs:30-84`

When WAF blocks a request, `write_waf_decision` builds and sends the response directly (line 67-69) bypassing `response_filter`. The `ResponseFilterChain` (including the new `WafObservabilityHeaderFilter`) only runs in `response_filter` (proxy.rs:817), which is a Pingora callback for **upstream responses**.

For blocked/challenged/rate-limited requests, `request_filter` returns `Ok(true)` and Pingora never calls `response_filter`. The 6 mandatory `X-WAF-*` headers will be ABSENT on all blocked responses.

Contract section 5.1: "required observability headers below on EVERY HTTP response... including block, challenge, rate_limit."

**Fix:** Inject headers directly in `write_waf_decision` and `handle_challenge`. The ResponseFilter approach only covers proxied (allowed) responses. Both paths need coverage.

### RT-04: HIGH -- `is_allowed()` rename blast radius

**Grep-verified:** 10+ non-test callers across gateway and engine:
- `proxy_waf_response.rs:37` and `:196`
- `http3.rs:242`
- `engine.rs:506,530,545,717`
- Test files: `types_decisions.rs` (4 calls), `proxy_waf_response_writer.rs` (2 calls)

The plan acknowledges this risk but underestimates it. The rename from `is_allowed()` to `is_enforcement_allowed()` touches the hot path in both the HTTP/1.1 and HTTP/3 code paths. Recommend: keep `is_allowed()` as a deprecated wrapper calling `is_enforcement_allowed()` for one release cycle.

### RT-05: HIGH -- Default blocklist strips `x-waf-version`

**Verified at:** `types.rs:463-465`

```rust
fn default_header_blocklist() -> Vec<String> {
    vec!["x-powered-by-waf".to_string(), "x-waf-version".to_string()]
}
```

The default `header_blocklist` includes `x-waf-version`. The blocklist filter iterates these names and calls `remove_header`. If the new observability filter sets `X-WAF-*` headers, and a downstream filter strips `x-waf-version` (which starts with `x-waf-`), only that specific one is affected. However, any operator who adds a wildcard pattern like `x-waf-*` to their blocklist would strip ALL contract headers.

Phase 2 proposes adding an exclusion check `if name.starts_with("x-waf-") { continue; }` in the blocklist filter. But the current filter iterates the blocklist and calls `remove_header` by exact name, NOT by prefix scan. The plan's proposed fix doesn't match the actual filter implementation.

**Fix:** The real fix is simpler: remove `"x-waf-version"` from the default blocklist (it's a legacy internal header, not an interop header). Add the prefix guard only if operators might add wildcard patterns. Document that `X-WAF-*` headers are protected.

### RT-06: HIGH -- `set_profile` scope=all override clearing

**Contract line 186:** "Any previous feature-level or policy-level log_only overrides SHOULD be cleared unless the WAF explicitly reports otherwise."

The plan's `ModeState` has `default_mode`, `feature_overrides`, and `policy_overrides`. When `set_all(mode)` is called, the plan must clear both override maps AND set `default_mode`. If it only sets `default_mode`, the `resolve()` method would still find leftover per-feature overrides.

The plan's Step 5 says `set_all(mode)` but doesn't specify override clearing behavior. This is a contract compliance gap.

### RT-07: HIGH -- Branch count mismatch

**Grep-verified:** `grep -c "log_only_mode" engine.rs` = 11 occurrences. Plan claims "12 detection phases." The mismatch could mean one branch is missed during refactoring, or one phase doesn't have a log_only branch. Either way, the implementer must use the actual grep count (11) not the plan's claim (12).

### RT-08: MEDIUM -- `RuleAction::Log` mapping

**Verified at:** `types.rs:137`

```rust
Self::Log => WafAction::LogOnly,
```

Custom rules with `action: log` currently produce `WafAction::LogOnly`. After Phase 1 deprecates `WafAction::LogOnly`, this mapping becomes a path to the deprecated variant. Must update to produce `WafAction::Allow` with `InteropMode::LogOnly` on the decision, or create a new mapping strategy.

### RT-09: MEDIUM -- `const fn` constraint

**Verified at:** `types.rs:158-162`

```rust
pub const fn block(status: u16, body: Option<String>, result: DetectionResult) -> Self {
```

Phase 1 adds `rule_id: Option<String>` to `WafDecision`. The `block()` constructor needs to extract `rule_id` from `DetectionResult` (e.g., `result.rule_id.clone()`). But `const fn` cannot call `.clone()` on `String` or access methods. Must remove `const` qualifier.

Similarly, `allow()` is `const fn` and needs to set `risk_score: 0, mode: Enforce, rule_id: None` which works for literals but blocks any future non-trivial defaults.

### RT-10: MEDIUM -- No risk_score infrastructure

**Grep-verified:** No `risk_score` field exists on `WafDecision` today. The engine has a `RiskScore` phase (Phase enum value 20) and `risk::threshold` module, but these produce a Challenge/Block decision, not a numeric score that's stored on the decision.

Phase 1 claims `risk_score` will be "populated from scorer." There is no scorer that currently produces a `u16` value. The `risk::threshold::is_allowed(score, thresholds)` function takes a `u8` score but this is the accumulated actor score, not a per-request value.

**Impact:** `X-WAF-Risk-Score` will be `0` for all requests unless the implementer also builds the plumbing to capture the cumulative risk score from the actor state and attach it to the decision. This is missing from the plan.

### RT-11: MEDIUM -- WafAction serde tag format

**Verified at:** `types.rs:93-94`

```rust
#[serde(tag = "type", rename_all = "snake_case")]
pub enum WafAction {
```

`WafAction` uses **internally-tagged** enum serialization. `WafAction::Block { status: 403, body: None }` serializes to `{"type":"block","status":403}`, not the string `"block"`.

For the JSONL audit log's `action` field, the contract expects a plain string like `"block"`. The plan proposes `as_contract_str()` for headers, but the JSONL entry struct has `pub action: String` which should be fine if populated via `as_contract_str()` rather than serde. However, this serde behavior will affect any code that serializes `WafDecision` directly (e.g., existing VictoriaLogs audit events). Verify the existing audit pipeline doesn't break.

### RT-12: LOW -- HTTP/3 path not covered

**Verified at:** `http3.rs:240-279`

The H3 code path builds its own response (`http::Response::builder()`) and sends headers independently. It does not go through `ResponseFilterChain`. The plan only discusses the Pingora HTTP/1+2 path. H3 blocked responses will lack `X-WAF-*` headers.

### RT-13: LOW -- YAML config adds unnecessary complexity

Phase 5 proposes YAML config support. The contract says `./waf.yaml` or `./waf.toml`. Supporting TOML-only and naming the file `waf.toml` satisfies the contract. YAML parsing adds a dependency and conversion complexity for no benchmark benefit.

---

## Missing Contract Items Not Addressed

1. **Section 2.7 multi-policy mode resolution:** "When a request matches multiple policies with different active modes, X-WAF-Mode SHOULD reflect the mode of the policy that produced the final reported X-WAF-Action." The plan's `ModeRegistry.resolve()` takes a single (feature, policy) pair. The engine evaluates multiple phases. Which phase's mode wins? The plan doesn't specify the resolution rule.

2. **Section 4 challenge response format:** Contract specifies JSON and HTML challenge formats the benchmarker can solve. The existing `handle_challenge` uses a custom PoW renderer. Plan doesn't verify the rendered format matches contract section 4 expectations (e.g., `challenge_token`, `difficulty`, `submit_url` fields).

3. **Section 10 loopback alias:** "All traffic arrives from 127.0.0.x loopback addresses. The WAF MUST treat different 127.0.0.x addresses as distinct clients." This is about rate-limiting and risk scoring using TCP peer_addr. Currently, `client_ip` (possibly XFF-resolved) is used for rate limiting. Must verify rate-limiter uses `socket_ip` (see RT-01).

4. **Audit log for `access_bypass` requests:** When `ctx.access_bypass = true`, the engine is skipped entirely (proxy.rs:677-679). No WafDecision is produced. These requests will have no JSONL audit entry and no `X-WAF-*` headers. Contract says headers on EVERY response.

---

## Positive Observations

- **Additive-only strategy** is sound -- preserving existing types with deprecation is the right call.
- **ArcSwap for ModeRegistry** is correct for lock-free hot-path reads. No race condition concern.
- **Dual-write audit** architecture with mpsc channel is well-designed for backpressure handling.
- **TDD approach** per phase is appropriate for a compliance-critical change.
- **Feature/policy catalog** mapping in Phase 4 is comprehensive and maps well to existing Phase enum.

---

## Unresolved Questions

1. Does the existing VictoriaLogs audit pipeline serialize `WafAction` via serde (internally-tagged)? If so, adding new variants may change the wire format for downstream log consumers.
2. What happens to `BruteForce` (Phase 23) and `RequestBodyAbuse` (Phase 24) in the feature catalog? They're missing from the Phase 4 mapping table.
3. The `reset_state` handler needs to clear rate-limit state. Is `MemoryStore` (rate limiter) accessible from `AppState`? It's not currently a field on `AppState`.
4. For blocked responses, who sets `X-WAF-Cache: BYPASS`? The cache lookup never runs when the request is blocked at request_filter time.
