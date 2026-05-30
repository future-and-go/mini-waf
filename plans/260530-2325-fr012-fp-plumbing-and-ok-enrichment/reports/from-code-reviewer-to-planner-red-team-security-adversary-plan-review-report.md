# Red-team review — FR-012 device-fp plumbing + ok enrichment

Adversary lens. Findings keyed to fraud-detection bypass / state-tamper attacks.

---

## Finding 1: Empty-FpKey filter at gateway is bypass-safe but classifier still buckets via SessionIdent::Fingerprint(FpKey)

- **Severity:** High
- **Location:** Phase 2, "Step 2.4 — wire from proxy.rs" + Phase 1 hoist
- **Flaw:** `RequestCtx.device_fp` is gated `Some` only if `!d.key.is_empty()` at proxy.rs builder. Good. BUT `SessionIdent::Fingerprint(FpKey)` keys the DashMap on the **full** `FpKey` struct (`crates/waf-engine/src/checks/tx_velocity/session_key.rs:20-22`). `FpKey` has three `Option<FingerprintValue>` fields (`crates/waf-engine/src/device_fp/types.rs:40-47`). A non-empty key with **only h2_akamai populated** collides with **every other** request carrying that same h2 hash and no JA3/JA4 (e.g. all clients behind shared CDN egress). The plan does not address per-field richness as a bucketing constraint.
- **Failure scenario:** Attacker behind a popular CDN/proxy gets the same `h2_akamai` value as 10k legitimate users. With no `SESSIONID` cookie, every cookie-less request from those users buckets into the same `SessionKey`. Attacker fires 16 withdrawals → ring fills with attacker events, ok_count = 0 → classifier signal blames the **entire bucket**, FR-025 risk score elevates innocent users. Reverse of intended: an attacker poisons reputation of victim cohort.
- **Evidence:**
  - `crates/waf-engine/src/checks/tx_velocity/session_key.rs:20-22` — `SessionIdent::Fingerprint(FpKey)` keys on whole struct
  - `crates/waf-engine/src/device_fp/types.rs:49-55` — `is_empty` only checks "all None", not "fingerprint diversity"
  - Plan phase-02 Step 2.4 quote: `.filter(|d| !d.key.is_empty())` — guard is too weak
- **Suggested fix:** Add a stronger gate: only enroll fp identity when **at least TWO** providers populated the key, OR require JA3/JA4 (TLS-bound, harder to share) and treat h2-only fingerprints as `None`. Document the bucketing collision risk explicitly in the plan.

---

## Finding 2: Race on set_outcome lets a concurrent request flip the wrong event's ok

- **Severity:** High
- **Location:** Phase 3, "set_outcome slot-matching algorithm" + plan.md Risk Assessment row 5
- **Flaw:** The plan acknowledges the race ("Concurrent requests for same session race `last_recorded_idx`") and dismisses it as multi-tab corner case. It is exploitable. `set_outcome` walks newest→oldest and flips the first event whose `role` matches. With two concurrent withdrawals from the same session (legitimate user double-clicking + attacker piggyback request riding the same cookie/fp), response A returns 200 first while response B (the actual fraudulent one) returns 200 later. Both flip the **same newest** slot to `ok=true`. The earlier event — the attacker's — is never flipped from `ok=false`.
- **Failure scenario:** Attacker triggers a withdrawal via session replay (stolen cookie). Concurrently, the legitimate user clicks "balance check" (no, wait — that's wrong role). Better scenario: legitimate user submits two withdrawals (split payment). Attacker, observing timing, fires a third withdrawal of their own during the window. ok_count reports 2/3 successful. Attacker's withdrawal goes through with `ok=false` attribution → the classifier signal under-weights the actual fraud event because the "honest" 200s mask it. ok_count is now misleading data for FR-025 weighting.
- **Evidence:**
  - Phase-03 §"set_outcome slot-matching algorithm" — walks newest→oldest, flips first match
  - `crates/waf-engine/src/checks/tx_velocity/recorder.rs:165-216` — record() append uses `entry.clone()` under shard guard; ring index not returned to caller
  - plan.md:116 quote: "if telemetry shows collisions we add per-req_id token in a follow-up"
- **Suggested fix:** `record()` must return the absolute slot index it wrote. `set_outcome` takes that index, not a role search. Pass via a small `RecordReceipt { slot_idx, generation }` token stored on `Ctx` (the gateway per-request ctx, not `RequestCtx`). Yes, this adds plumbing, but correctness > KISS when the type is "fraud signal".

---

## Finding 3: WAF-blocked requests never call on_response → events linger as ok=false and recon-leak block decisions

- **Severity:** High
- **Location:** Phase 5, "Architecture" §"KNOWN GAP" and plan.md:114 Risk Assessment row 3
- **Flaw:** Plan declares "Event stays with `ok=false` placeholder — recorded as 'did not succeed', which is correct." This is wrong from the adversary lens. Three problems:
  1. **Recon channel.** Attacker sees their own withdrawal signal payload (via FR-025 risk score change visible in latency, downstream challenge behavior, or response Server-Timing). They learn whether WAF blocked-at-gate vs upstream-rejected by whether `ok_count` ever increments — turning ok-count into an oracle for WAF gate composition.
  2. **Storage poisoning.** A single attacker who knows their requests trigger gate blocks can pre-fill the ring with 16 `ok=false` events on a victim session's `FpKey` bucket. Legitimate user's subsequent 2xx withdrawals see ok_count low because the attacker's blocked events crowd the ring.
  3. **TOCTOU on request_filter blocking.** `proxy.rs:861` gates on `upstream_contacted`, but `TxVelocityCheck::check()` already appended an event before the WAF gate's later check blocked. Phase-03's check runs during `engine.evaluate` — the recorder records BEFORE the WAF makes a decision. Look at `proxy.rs:574-580`: missing request context → fail-closed 503, but tx_velocity has already appended.
- **Failure scenario:** Attacker sends 16 deliberately malformed `/api/withdraw` requests with someone else's cookie. Each hits `request_filter` → device_fp resolved → `TxVelocityCheck::check()` records 16 events to victim's session bucket → some other gate check fires Block (SQLi, header injection, etc.) → response_filter sees `upstream_contacted=false` → no `on_response` → ring is now 16 ok=false withdrawals attributed to victim. Victim's first real withdrawal triggers `count=16, ok_count=1` → WithdrawalVelocity signal fires → victim gets risk-blocked. Attack cost: 16 requests with a cookie.
- **Evidence:**
  - `crates/gateway/src/proxy.rs:867` — `if upstream_contacted` gate confirmed
  - phase-05 Architecture quote: "requests blocked at WAF gate never see on_response. Event stays ok=false. Documented as expected behavior."
  - `crates/waf-engine/src/checks/tx_velocity/recorder.rs:165-180` — record runs unconditionally before any other check's decision
- **Suggested fix:** Either (a) move `TxVelocityCheck::check()` to record **only on commit** (after the full WAF pipeline declares Allow), or (b) `record()` returns a sentinel that callers must promote via `set_outcome` to enter classifier consideration. Untouched events with `ok=false` should NOT count toward `count` either — they're "did not reach upstream", not "denied". The current plan conflates these.

---

## Finding 4: FpKey moved to waf-common pulls Serialize/Deserialize across crate boundary — admin-UI / waf-api can now serialize internal identity material

- **Severity:** Medium
- **Location:** Phase 1, "Step 1.2 — move the types"
- **Flaw:** Phase 1 moves `FpKey` + `FingerprintValue` to `waf-common::types`. Both already derive `Serialize, Deserialize` (`crates/waf-engine/src/device_fp/types.rs:21,39`). `waf-common` is consumed by `waf-api` (admin REST). Any `RequestCtx` or `DeviceIdentity`-shaped struct that previously serialized via opt-in now becomes trivially serializable from waf-api code paths. JA3/JA4 hashes are not secret, BUT JA3 raw strings (when the FingerprintValue holds raw cipher list, not hash) are device-fingerprinting telemetry that leaks user device class to anyone with admin-API read.
- **Failure scenario:** Operator builds a "session inspector" admin endpoint. It serializes `RequestCtx` (now containing `device_fp: Option<Arc<FpKey>>`). JSON exposes per-user device fingerprints to anyone with admin-read access. Audit-trail leak; possible privacy compliance issue.
- **Evidence:**
  - `crates/waf-engine/src/device_fp/types.rs:21` — `#[derive(...Serialize, Deserialize)]` on FingerprintValue
  - `crates/waf-engine/src/device_fp/types.rs:39` — same on FpKey
  - Plan phase-01 §Requirements: "`serde` is already in `waf-common` so the existing derives keep compiling" — confirms cross-crate exposure intentional
- **Suggested fix:** Drop the `Serialize, Deserialize` derives on `FpKey` and `FingerprintValue` when they move to waf-common, OR gate them behind a `#[cfg(feature = "internal-serde")]` that admin-UI does not enable. The DashMap key only needs `Eq + Hash`; serde was for IdentityRecord persistence (Redis store) which still lives in waf-engine and can re-add the derives at its own site.

---

## Finding 5: ok_count saturating_add hides ring-overflow disagreement between count and ok_count

- **Severity:** Medium
- **Location:** Phase 4, "Step 4.3 — extend evaluate_velocity"
- **Flaw:** The plan's `evaluate_velocity` uses `count.saturating_add(1)` and `ok_count.saturating_add(1)` independently. Ring is fixed at 16 slots (`crates/waf-engine/src/checks/tx_velocity/recorder.rs:41`) so overflow is impossible — the plan acknowledges this. **However**, the ring eviction policy silently drops the **oldest** event. A successful (ok=true) old withdrawal evicted by 16 new ok=false attempts skews ok_count downward; ok_count(window) ≤ count(window) but ok_count loses memory of past success. FR-025 weight that uses `ok_count / count` as a "success rate" will read 0/16 for an account that had 100 successful withdrawals yesterday and 16 denials today. Risk scorer over-penalizes legitimate accounts under burst-attack.
- **Failure scenario:** Attacker stuffs 16 failed withdrawal attempts against victim's session. Ring is now [16x ok=false]. Real successful past withdrawals are evicted. FR-025 reads `count=16, ok_count=0` → "100% denial rate" → max risk score → victim challenged/blocked. Denial-of-service via reputation grooming.
- **Evidence:**
  - `crates/waf-engine/src/checks/tx_velocity/recorder.rs:41,66-75` — WINDOW=16, head-rotation eviction
  - Phase-04 step 4.3 code: counts loop over `in_window` only
  - phase-04 §Risk Assessment row 3 quote: "saturating arithmetic masks an overflow bug" — addresses wrong risk
- **Suggested fix:** Don't ship `ok_count / count` as a "success rate" without per-window decay independent of ring eviction. Document that `ok_count` is "successful events still in the 16-slot ring" — NOT "historical success rate". Better: add `total_ever_recorded` / `total_ever_ok` u32 counters per-actor (8 bytes added) so FR-025 can do honest rate calc.

---

## Finding 6: 30-50 RequestCtx literal estimate is off by ~3x — wide blast radius for missed fixtures

- **Severity:** Medium
- **Location:** Phase 2, "Step 2.6 — sweep test fixtures"
- **Flaw:** Plan estimates "~30-50 fixtures across waf-engine, gateway, waf-common, waf-api". Actual count is **166 RequestCtx struct-literal sites** workspace-wide (`grep -rn "RequestCtx {" crates/ --include="*.rs" | wc -l` → 166). Plan also leaves the rule "if any uses `Default::default()` add a Default impl" as a hand-wave. Compile will catch missing fields (struct update syntax is rare here, FRU rebinds require all fields), but the volume implies real review fatigue.
- **Failure scenario:** Reviewer rubber-stamps the mechanical change. A test fixture in `tests/support/` somewhere uses `RequestCtx { ..mock_ctx() }` style — Rust's FRU drops the helper's `device_fp` field if the helper predates the change. Test pass with default `None`, hiding a regression where production code sets `Some(fp)` but tests assert on `None` path semantics.
- **Evidence:**
  - `grep -rn "RequestCtx {" crates/ --include="*.rs" | wc -l` → 166
  - Phase-02 step 2.6 quote: "Expected hit count: ~30-50 fixtures"
- **Suggested fix:** Add `Default` impl to `RequestCtx` with `device_fp: None`. Then a hot-path `assert!(ctx.device_fp.is_none() == cookie_present)` (or equivalent) integration test catches the case where prod sets but test fixture doesn't. Also: re-count and update the plan's expected hit count.

---

## Finding 7: Empty-fp guard at gateway is duplicated in extract_session_key — drift risk

- **Severity:** Medium
- **Location:** Phase 2, "Step 2.4 — wire from proxy.rs" + session_key.rs existing code
- **Flaw:** Plan adds `.filter(|d| !d.key.is_empty())` at the proxy builder. `extract_session_key` already filters `if let Some(key) = fp && !key.is_empty()` (`crates/waf-engine/src/checks/tx_velocity/session_key.rs:45`). Two guards in two places that must remain in lock-step. If a future refactor relaxes the gateway guard (e.g., to enable telemetry for empty-fp requests) without updating `extract_session_key`, empty-fp bucketing returns silently.
- **Failure scenario:** Future dev removes the gateway-side `is_empty` filter to log empty-fp requests for analytics. `RequestCtx.device_fp = Some(Arc<empty>)` now flows into `extract_session_key`, which **still** returns None — good. BUT if a third consumer (e.g., a future risk scorer) reads `ctx.device_fp.as_deref()` directly without the `is_empty` check, every empty-fp request buckets under one super-key (Finding 1's failure mode but cheaper to hit).
- **Evidence:**
  - `crates/waf-engine/src/checks/tx_velocity/session_key.rs:45-52` — existing is_empty guard inside extract_session_key
  - Phase-02 step 2.4 quote: "`.filter(|d| !d.key.is_empty())` is critical"
- **Suggested fix:** Choose one guard location. Recommend: keep it at the gateway builder (single point of truth for "what enters RequestCtx") and document that `RequestCtx.device_fp = Some(_)` is **invariant: not empty**. Remove the duplicate inside `extract_session_key`. Add a debug-assert at the gateway: `debug_assert!(fp.as_ref().map_or(true, |k| !k.is_empty()))`.

---

## Finding 8: Phase-05 e2e test uses build_request_ctx that bypasses gateway's empty-fp filter

- **Severity:** Medium
- **Location:** Phase 5, "Step 5.1 — failing end-to-end test", `build_request_ctx` helper
- **Flaw:** The test helper at phase-05 line 190-221 constructs `RequestCtx` with `device_fp: None` default, and the third test `fingerprint_fallback_when_no_cookie` directly assigns `ctx.device_fp = Some(Arc::clone(&fp))` with a non-empty `FpKey { ja3: Some(...) }`. Good. **However**, no test exercises the production guard `.filter(|d| !d.key.is_empty())` at the builder. The e2e never confirms that a production-pipeline empty fp does NOT enter the recorder. Empty-fp bypass is exactly the super-key bucketing attack — it deserves an e2e assertion.
- **Failure scenario:** Future refactor in `proxy.rs:543` causes empty FpKey to be created with a stub field (e.g., `h2_akamai: Some("default")` for unrecognized clients). No test catches it. All bot traffic that previously hit `None` device_fp now hits one shared bucket. Recorder explodes with one super-actor accumulating millions of events.
- **Evidence:**
  - Phase-05 step 5.1 build_request_ctx helper does not exercise the gateway builder
  - `crates/gateway/src/proxy.rs:526-543` — device_fp_detector.process is the only producer of empty/non-empty FpKey
- **Suggested fix:** Add a fourth e2e test that calls the full RequestCtxBuilder with an empty FpKey simulated upstream of the builder and asserts `built.device_fp.is_none()`. Better: a property test that asserts `FpKey::default().is_empty() == true ⟹ RequestCtx.device_fp.is_none()`.

---

## Finding 9: Replay-flip via set_outcome — same withdrawal id re-sent flips ok back-and-forth

- **Severity:** Critical
- **Location:** Phase 3, set_outcome semantics
- **Flaw:** `set_outcome` is keyed only on `(SessionKey, EndpointRole, ok)`. It walks newest→oldest and flips the first matching slot. There is no idempotency key, no per-event ID. If the upstream supports request retry (Pingora retries, or browser retry on idle connection), `on_response` for the SAME logical request can fire twice. Worse: any code path that calls `set_outcome` (today: response_filter only; tomorrow: anything an operator wires) can flip the same event multiple times.
- **Failure scenario:** Attacker observes the upstream sometimes returns 502 then succeeds on retry. First response (502): set_outcome(role=Withdrawal, ok=false). Second response (200): set_outcome flips newest matching Withdrawal slot → that's the SAME slot → now ok=true. Classifier sees `count=1, ok_count=1` for what was actually a single failed-then-succeeded attempt. Worse: a malicious upstream (in cluster mode, compromised origin) can deliberately return multiple "responses" via H2 PUSH_PROMISE or h1 chunked-trailer manipulation — each one triggers a `response_filter`. Attacker upstream can drive ok_count up by repeated 2xx pings, then drive count up by request bursts → arbitrary ok_count manipulation.
- **Evidence:**
  - Phase-03 §"set_outcome slot-matching algorithm" — first newest match wins, no event ID
  - `crates/gateway/src/proxy.rs:867` — `engine.on_response` called per response_filter invocation, no dedup
  - `crates/waf-engine/src/checks/tx_velocity/mod.rs:49-56` — `Event` has no id/req_id field
- **Suggested fix:** Add `req_id: u32` (truncated hash of `RequestCtx.req_id`) to `Event`. `record()` returns the assigned index AND the req_id. `set_outcome(receipt, ok)` matches on both. Idempotent: re-flipping the same `(idx, req_id)` to the same `ok` is a no-op; flipping `(idx, req_id)` after eviction (req_id mismatch) is a silent skip with a `tracing::debug` line.

---

## Finding 10: ok=false default means cooldown-mark never fires for blocked-burst — attacker can spam request_filter forever

- **Severity:** High
- **Location:** Phase 3, "set_outcome" semantics + recorder.rs:191-209 (current cooldown logic)
- **Flaw:** Cooldown mark (`mark_signal`) only fires inside `set_outcome` after classifiers emit signals. With WAF-blocked requests (Finding 3) never reaching `set_outcome`, attacker's blocked floods **never advance the cooldown timer**. Each request still allocates a ring slot, still bumps `updated_ms`, still keeps the actor pinned in the DashMap (defeating `purge_expired`'s ttl-based eviction since `updated_ms` keeps fresh).
- **Failure scenario:** Attacker pins a victim's session bucket alive indefinitely by sending one tx_velocity-tracked request per `session_ttl_secs - 1`. Each request appends, bumps updated_ms, but never set_outcome → never run classifier → cooldown never starts → bucket never purged. Memory cost: one ActorTx struct per victim, indefinitely. Combined with Finding 1 (fingerprint bucketing) → attacker pins memory growth on every popular UA fingerprint.
- **Evidence:**
  - `crates/waf-engine/src/checks/tx_velocity/recorder.rs:165-216` — record() updates `updated_ms` unconditionally
  - `crates/waf-engine/src/checks/tx_velocity/recorder.rs:233-237` — `mark_signal` only called from inside record's classifier block (moves to set_outcome in phase-03)
  - `crates/waf-engine/src/checks/tx_velocity/recorder.rs:254-267` — purge_expired keys on `updated_ms`
- **Suggested fix:** Track `last_outcome_ms` separately from `updated_ms`. `purge_expired` evicts actors where `last_outcome_ms` is stale AND `updated_ms - last_outcome_ms > grace_window`, so request-only floods cannot pin actors forever. Document the eviction asymmetry in the plan.

---

## Verification trail (for adjudication)

- waf-common does NOT depend on waf-engine: `grep -n waf-engine crates/waf-common/Cargo.toml` → no match (cargo deps block lines 7-21)
- FpKey location: `crates/waf-engine/src/device_fp/types.rs:40`; FingerprintValue: line 22
- RequestCtx location: `crates/waf-common/src/types.rs:21`
- engine.on_response call site: `crates/gateway/src/proxy.rs:867-869` confirmed, gated on `upstream_contacted` (line 860, 867)
- device_fp resolution: `crates/gateway/src/proxy.rs:526-543` confirmed
- extract_session_key signature: `crates/waf-engine/src/checks/tx_velocity/session_key.rs:36` — already accepts `Option<&FpKey>`, plan claim verified
- Signal::name() arms use `..` rest pattern: `crates/waf-engine/src/device_fp/signal.rs:74-87` confirmed
- DeviceIdentity.key is `Arc<FpKey>`: `crates/waf-engine/src/device_fp/types.rs:137` confirmed
- FR-018 brute_force on_response reference: `crates/waf-engine/src/checks/brute_force.rs:125-152` confirmed
- Check trait on_response default no-op: `crates/waf-engine/src/checks/mod.rs:60` confirmed
- RequestCtx struct-literal count: 166 (plan estimated 30-50)
- Signal::WithdrawalVelocity / LimitChangeBurst consumers: all use `{ .. }` or `{ field, .. }` — phase-04 backwards-compat claim verified

## Unresolved questions

1. Should request-time `record()` be deferred until WAF Allow decision? (Finding 3) — this would change FR-012 semantics significantly; needs product owner sign-off.
2. Is `FpKey` Serialize derive actually consumed by anyone today besides Redis identity store? Audit before phase-01 lands. (Finding 4)
3. What is the maximum sustained record() rate per actor under attack? Determines whether `last_outcome_ms` is enough or per-actor rate limit is needed. (Finding 10)
