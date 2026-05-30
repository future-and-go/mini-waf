# Red-Team Plan Review — FR-012 FP Plumbing & ok Enrichment

Role: Failure-Mode Analyst / Flow Tracer.
Scope: `plans/260530-2325-fr012-fp-plumbing-and-ok-enrichment/` (plan.md + 5 phase files).
Verdict: 10 findings — 2 Critical, 5 High, 3 Medium.

---

## Finding 1: HTTP/2 multiplexing — concurrent in-flight requests share `GatewayCtx` and corrupt each other's `set_outcome` flips

- **Severity:** Critical
- **Location:** Phase 3, section "set_outcome slot-matching algorithm" + Risk Assessment row 2 ("Concurrent requests for same session race the `last withdrawal` slot")
- **Flaw:** Plan dismisses the multi-in-flight case as "documented; not blocking", but **the same session/H2 connection on Pingora gets one `GatewayCtx` per request** (Pingora allocates `Self::CTX` per stream — fine), HOWEVER multiple H2 streams hitting the SAME `SessionKey` from the same browser/app land into the same `DashMap` slot in `TxStore`. Two streams that interleave `record()` → upstream RTT → `response_filter` will compete for "newest matching role" in `set_outcome`. The algorithm in phase-03 walks newest→oldest and flips the FIRST role match. Mobile apps routinely fire `GET /api/withdraw?confirm=1` and `POST /api/withdraw` concurrently on one H2 connection.
- **Failure scenario:**
  1. Stream A: `check()` records `Event { role: Withdrawal, ts: T0, ok: false }`. Goes to slow upstream (5s).
  2. Stream B (200 ms later): `check()` records `Event { role: Withdrawal, ts: T0+200, ok: false }`. Fast upstream returns 200 in 300ms.
  3. Stream B's `on_response` runs `set_outcome(Withdrawal, true)` — walks newest→oldest, hits B's event first, flips it. Correct.
  4. Stream A's upstream returns 403 at T0+5000ms. `on_response(Withdrawal, false)` walks newest→oldest. The newest matching `role==Withdrawal` is **B's event** (already true), but algorithm only checks `role`, so it flips B back to **false**. A's event stays `false` forever.
  5. Classifier now sees `count=2 ok_count=0` instead of `count=2 ok_count=1`. Risk score over-penalises a user who had one legitimate withdrawal.
  Inverse case (A succeeds, B fails) is worse: classifier reports `ok_count=2` for what was really `ok_count=1`, under-penalising a stuffed bad transfer.
- **Evidence:**
  - `plans/260530-2325-fr012-fp-plumbing-and-ok-enrichment/phase-03-defer-classifier-eval-to-on-response.md:73-89` (algorithm).
  - `plans/260530-2325-fr012-fp-plumbing-and-ok-enrichment/phase-03-defer-classifier-eval-to-on-response.md:338` ("Race produces wrong-event flip in a corner case (multi-tab user). Documented; not blocking.").
  - `crates/waf-engine/src/checks/tx_velocity/recorder.rs:66-75` (ring `record` API has no per-event id).
- **Suggested fix:** Either (a) carry an opaque `event_token: u64` from `record()` back to the caller, stash it in `RequestCtx` (e.g. `tx_velocity_event_token`), and have `set_outcome(token, ok)` flip THAT exact slot, or (b) use `ctx.req_id` as a tiebreaker — `Event` gains a `req_id_hash: u32` field, `set_outcome` matches on `(role, req_id_hash)`. Option (a) is O(1) and KISS. Document the chosen mechanism in plan.md "Decisions" so phase-04 tests it explicitly.

---

## Finding 2: `upstream_contacted` gate is FALSE-POSITIVE — `ctx.upstream_addr` is set inside `upstream_peer` BEFORE the TCP connect

- **Severity:** Critical
- **Location:** Phase 5, section "Architecture" and "No change `crates/gateway/src/proxy.rs:867`"
- **Flaw:** Phase-5 reasons that gating `on_response` on `upstream_contacted = ctx.upstream_addr.is_some()` means "only fires after upstream returned a response". This is **wrong**. `ctx.upstream_addr` is assigned in `upstream_peer()` at `proxy.rs:478` BEFORE `HttpPeer::new` even runs — that's just the address-resolution stage. If Pingora then fails to connect (DNS resolution miss, refused TCP, TLS handshake fail, idle-timeout, ALPN mismatch with `H2Only`), `response_filter` will still fire with a Pingora-synthesized 502/504, and `upstream_contacted` is `true` even though no upstream byte was exchanged. Worse: phase-03 says "if response_filter never fires (upstream timeout never logged), the event stays attributed as 'did not succeed'" — but the gate also misclassifies "upstream attempted but failed" as "non-2xx legitimate denial".
- **Failure scenario:**
  1. User POSTs `/api/withdraw`, gateway records `Event { ok: false, role: Withdrawal }`.
  2. Upstream's TCP RST refuses the connection. Pingora calls `response_filter` with a synthesized 502.
  3. `upstream_contacted == true` (upstream_addr set), so `engine.on_response(req_ctx, 502)` runs.
  4. `set_outcome(Withdrawal, false)` flips ok → false (already false). Event indistinguishable from "upstream rejected with 4xx".
  5. Operator sees `count=3 ok_count=0` and bans a legitimate user when origin is just down.
- **Evidence:**
  - `crates/gateway/src/proxy.rs:478` — `ctx.upstream_addr = Some(upstream_addr.clone());` inside `upstream_peer` callback, before connect.
  - `crates/gateway/src/proxy.rs:860` — `let upstream_contacted = ctx.upstream_addr.is_some();`
  - `plans/.../phase-05-gateway-wiring-tests-docs.md:35-42` ("Architecture") asserts the gate is correct without verifying the semantic.
- **Suggested fix:** Add a real `ctx.upstream_response_received: bool` flag set in Pingora's `upstream_response_filter` callback (the first one that fires after we have actual bytes from origin), and gate FR-012's `on_response` on THAT, not on `upstream_addr.is_some()`. Alternatively distinguish `5xx` from `2xx/3xx/4xx` and skip FR-012 `set_outcome` for 5xx where origin is suspect.

---

## Finding 3: `tokio::spawn` inside `set_outcome` — JoinHandle dropped, panics swallowed, runtime-shutdown races

- **Severity:** High
- **Location:** Phase 3, "set_outcome slot-matching algorithm" and Step 3.3 ("Use the existing `fp_key_for_submission` helper and `tokio::spawn` for the aggregator submit.")
- **Flaw:** Plan inherits the existing `tokio::spawn(async move { aggregator.submit(...).await; })` pattern (`recorder.rs:213-215`). Three failure modes are not addressed:
  1. The `JoinHandle` is dropped immediately — if the spawned task panics, the panic surfaces only in `tracing` (if subscriber installed); silent in worst case.
  2. During runtime shutdown (SIGTERM → tokio drains), `spawn` after the runtime is partially gone returns a handle whose future may never run; the signal is **lost** with no log.
  3. `set_outcome` is called from Pingora's `response_filter`, which runs inside a tokio worker. If the response is a streaming/SSE/websocket response, `response_filter` fires once at headers, but if the worker is hot, the spawned aggregator task may be **queued behind 10k other tasks** — by the time it runs, the FpKey is stale (rare but real for high-RPS hosts).
- **Failure scenario:**
  1. Aggregator's `submit` panics due to a bad signal (e.g. `unwrap()` on a missing weight in FR-025). Panic kills the task; classifier work for THAT signal is lost. Operator never knows.
  2. Container restart: SIGTERM at T0. WAF receives a burst of 200 withdrawals between T0 and T+100ms while tokio drains. Half the `set_outcome` spawns never complete; risk store never sees those signals. After restart, the same actor's velocity counter is silently zero.
- **Evidence:**
  - `crates/waf-engine/src/checks/tx_velocity/recorder.rs:212-215` — spawn pattern.
  - Plan does not address shutdown ordering anywhere.
- **Suggested fix:** Either (a) submit synchronously when aggregator is in-memory (`NoopAggregator` / `LoggingAggregator` / in-process risk scorer all return instantly — no async needed), or (b) wrap the spawn in `tokio::spawn(async move { if let Err(e) = std::panic::AssertUnwindSafe(aggregator.submit(&fp_key, &signals)).catch_unwind().await { tracing::error!(?e, "aggregator panic"); } })` to log panics. For shutdown, document the lossy semantic explicitly in plan.md Decisions block.

---

## Finding 4: Hot-reload of `TxVelocityConfig` between `check()` and `on_response()` — role can flip, key extraction can return different ident, event becomes orphaned

- **Severity:** High
- **Location:** Phase 3, "TxVelocityCheck::on_response" implementation (Step 3.4)
- **Flaw:** `on_response` re-extracts the role and session key by re-loading `self.cfg.load()`. If an operator hot-reloads config between request entry and response (FR-012 uses `ArcSwap` precisely to support live reload), the snapshot loaded in `check()` and in `on_response()` are **different**:
  - `role` may flip: `/api/v2/withdraw` was classified `Withdrawal` at request-time; admin renames the regex to `^/api/v2/withdraw$` → response-time classify returns `EndpointRole::None`. `set_outcome` is never called. Event stays `ok=false` forever (lost).
  - `session_cookie` may change: operator switches from `SID` to `JSESSIONID`. Request used `SID=abc123` → `SessionIdent::Cookie("abc123")`. Response sees only `JSESSIONID=xyz` and falls through to fingerprint, building a DIFFERENT `SessionKey`. `set_outcome` does `actors.get_mut(WRONG_KEY)` → returns `None` → silent no-op. The original event is orphaned.
- **Failure scenario:**
  1. Operator pushes config change adding new role-rules. ArcSwap pointer flips.
  2. 50 in-flight withdrawals enter the reload window. 30 had recorded under old `session_cookie="SID"`.
  3. Responses arrive; new cfg has `session_cookie="JSESSIONID"`. All 30 lookups for `set_outcome` find no matching ident → no-op.
  4. 30 events stay `ok=false` permanently. Classifier later evaluates them on a NEW recorded event for the same actor — `ok_count` is artificially zero, false positive.
- **Evidence:**
  - `plans/.../phase-03-defer-classifier-eval-to-on-response.md:51-66` — both paths call `extract_session_key(ctx, cookie, device_fp)` independently.
  - `crates/waf-engine/src/checks/tx_velocity/recorder.rs:115-117` — `cfg: Arc<ArcSwap<TxVelocityConfig>>` is hot-reloadable.
  - No invariant in plan that the snapshot must be the same across request/response.
- **Suggested fix:** Stash the resolved `SessionKey` + `role` from `check()` into `RequestCtx` (e.g. `tx_velocity_marker: Option<(SessionKey, EndpointRole)>`) and have `on_response` use that marker directly. No re-classify, no re-extract. Bonus: solves Finding 1 if the marker includes an event token.

---

## Finding 5: Websocket / SSE / long-poll / streaming responses — `response_filter` fires at headers but request never terminates, classifier evaluation runs on incomplete state

- **Severity:** High
- **Location:** Phase 5, "Architecture" diagram and Requirements row 3 ("A request with no cookie but a populated `FpKey` records under fingerprint identity")
- **Flaw:** Pingora's `response_filter` fires at **response header arrival**, not at body completion. Withdrawal endpoints are POSTs that finish quickly, fine. But `endpoint_roles` is operator-configurable — nothing in the plan prevents an operator from regexing `^/api/stream/` to `Withdrawal`. SSE/WS responses produce 200 OK headers immediately, then stream for hours; `set_outcome(..., true)` flips ok=true the moment headers arrive, regardless of whether the operation actually completed.
- **Failure scenario:**
  1. Operator labels `/api/withdraw/confirm` as Withdrawal. Endpoint is a long-poll: returns 200 headers, then either streams `{"status":"ok"}` after a 5s confirmation OR holds the connection and closes with no body when user cancels.
  2. User starts withdrawal; gateway records `ok=false`. Headers (200) arrive; `set_outcome(true)`. User then cancels — connection dropped, no body, no transaction.
  3. Classifier counts it as a successful withdrawal. Velocity score over-counts.
- **Evidence:**
  - `crates/gateway/src/proxy.rs:851-869` — `response_filter` fires once at headers.
  - Plan does not bound endpoint_roles to "completed-response" semantics.
  - Phase-3 plan.md:53 explicitly claims "only confirmed 2xx counts" but headers ≠ confirmed.
- **Suggested fix:** Either (a) move `set_outcome` to Pingora's `logging()` hook which fires at request COMPLETION (success or drop) — same place audit logs are emitted (`proxy.rs:1179`), or (b) document and ban operator regexes that match streaming endpoints. (a) is correct semantically and matches FR-018 if it's also wrong (worth checking brute_force.rs's call site).

---

## Finding 6: `set_outcome` re-flip on retry — request-entry default `false` collides with idempotent client retries

- **Severity:** High
- **Location:** Phase 3, "Why `false` as the pending value" section
- **Flaw:** Plan defends `false` as pending-default with "conservative; matches operator intuition". But the ring is bounded at 16 slots. Consider: client retries on network drop (common for mobile withdrawals). The retry walks back through `check() → record()` and **appends a new event** rather than reusing the previous slot. `set_outcome` later flips the newest; the older retry's event stays `false` forever. Classifier sees `count=4, ok_count=1` for what is actually ONE logical withdrawal that succeeded on retry #4.
- **Failure scenario:**
  1. User taps "Withdraw $100". App sends request; flaky network drops connection mid-upload at byte 5 of 200. Gateway records event #1 (`ok=false`, no response_filter ever fires).
  2. App auto-retries 3 times before success. Gateway records events #2, #3, #4. Only #4 gets `set_outcome(true)`.
  3. Velocity classifier with threshold=3 sees `count=4`, fires `WithdrawalVelocity` signal with `ok_count=1`.
  4. Risk engine penalises legitimate user. False positive.
- **Evidence:**
  - `plans/.../phase-03-defer-classifier-eval-to-on-response.md:94-101` (KISS justification).
  - `plans/.../plan.md:53` ("only confirmed 2xx counts").
  - `crates/waf-engine/src/checks/tx_velocity/recorder.rs:66-75` — `record` is unconditional append.
- **Suggested fix:** Either (a) extend ring to track a `Pending`/`Ok`/`Failed` tristate and let classifiers discount or skip `Pending` events older than N seconds, OR (b) on `check()`, if newest event for same `(key, role)` is `Pending` and within `dedupe_window_ms` (e.g. 5s), update its `ts_ms` instead of appending. Document the retry semantic in plan.md explicitly.

---

## Finding 7: Phase-2 step 2.6 grep undercounts fixtures — every `crates/waf-api`, integration test, and CRH builder that constructs `RequestCtx` will break

- **Severity:** Medium
- **Location:** Phase 2, Step 2.6 "sweep test fixtures"
- **Flaw:** Verified by grep: workspace has **166** `RequestCtx {` literals, not "30-50". Many of these are inside `tests/` (integration), some in macros, some in helpers. Step 2.6 says "Add `device_fp: None,` field-by-field" — this assumes flat struct literals. Anywhere a literal uses `..` rest pattern combined with `Default::default()` calls a non-existent `Default` impl. Phase-1 risk row says "No `Default` impl exists; this is fine" — but the fix recommendation in Risk Assessment row 4 of phase-2 contradicts itself: "if any, add a `Default` impl on `RequestCtx`". Inconsistent guidance.
- **Failure scenario:**
  1. Devs add `device_fp: None` to every struct literal Step 2.6's grep finds.
  2. Compile breaks in `crates/waf-api/tests/...rs` (literal not on the grep glob due to `--include="*.rs"` exclusion of something), in `prx-waf/...`, in a Rhai plugin test that constructs ctx programmatically.
  3. Phase 2 commit lands with `device_fp` added in ~40 places, but ~120 sites use the `RequestCtx { req_id, …, ..base_ctx }` shorthand referencing a function helper — those compile fine WITHOUT the field, hiding the broken field.
  Actually: Rust DOES require all fields to be initialized unless `..Default::default()` is used. So compile catches it. Hidden risk: `cargo check -p X` on a single crate may pass while another crate compiles separately; only `cargo check --workspace` is total.
- **Evidence:**
  - `bash grep -rn "RequestCtx {" crates/ --include="*.rs" | wc -l` → 166.
  - `plans/.../phase-02-plumb-device-fp-into-requestctx.md:177` ("Expected hit count: ~30-50 fixtures").
  - `plans/.../phase-02-plumb-device-fp-into-requestctx.md:204` self-contradicts phase-1 risk note.
- **Suggested fix:** Update the count estimate to "~150-180 sites" so devs don't stop early. Strongly consider adding `impl Default for RequestCtx` (sets all fields to safe defaults including `device_fp: None`) — it's a one-time cost that future-proofs every subsequent field addition. The "no Default impl exists" stance is the wrong default; this plan is the second time the workspace adds a field to RequestCtx.

---

## Finding 8: Phase-1 type move — `FpKey` derives `Default`, but `waf-common` may not have `Hash`/`Eq` in scope identically; `SessionIdent::Fingerprint(FpKey)` requires Hash

- **Severity:** Medium
- **Location:** Phase 1, Step 1.2 "move the types"
- **Flaw:** `FpKey` is used as `SessionIdent::Fingerprint(FpKey)` inside `SessionKey` which is the `DashMap` key (`recorder.rs:115`). `DashMap` requires `Hash + Eq`. The current `FpKey` in `waf-engine::device_fp::types` derives these. The plan says to "paste in `FingerprintValue` + `FpKey` defs" — but doesn't enumerate the derive list. If the paste loses a derive (`PartialEq`, `Eq`, `Hash`, `Serialize`, `Deserialize`), `waf-engine` compiles but `tx_velocity` breaks. Plan's verification gate is just `cargo check --workspace` which catches it — but the failure message will be misleading ("`FpKey` does not implement `Hash`"), and a hurried implementer may "fix" it by adding `#[derive(Hash)]` without realizing the existing impl was hand-rolled or had specific bounds.
- **Failure scenario:**
  1. Dev moves the struct but drops `#[derive(Hash, Eq, PartialEq, Serialize, Deserialize)]` from the paste.
  2. `cargo check -p waf-common` passes (no Hash requirement).
  3. `cargo check -p waf-engine` fails with the misleading error.
  4. Dev adds `#[derive(Hash)]` — but `FingerprintValue` (the inner type) was using `derive_hash_xor_eq` or a custom impl. Hash semantics silently differ from pre-move.
- **Evidence:**
  - `crates/waf-engine/src/checks/tx_velocity/session_key.rs:18-22` (`SessionIdent::Fingerprint(FpKey)` requires Hash + Eq).
  - `crates/waf-engine/src/checks/tx_velocity/recorder.rs:115` (`DashMap<SessionKey, …>`).
  - Plan does not list required derives for the moved types.
- **Suggested fix:** Phase-1 Step 1.2 must explicitly state: "Copy these derives verbatim: `#[derive(Clone, Debug, Default, Eq, Hash, PartialEq, Serialize, Deserialize)]`". Add a Success Criteria check: `grep -A1 "pub struct FpKey" crates/waf-common/src/types.rs` matches the pre-move derive set.

---

## Finding 9: Phase-4 saturating-arithmetic claim is wrong — `count` can absolutely overflow when consumed by FR-025

- **Severity:** Medium
- **Location:** Phase 4, Risk Assessment row "Saturating arithmetic masks an overflow bug"
- **Flaw:** Plan says "count overflowing u32 means >4 billion events in a 16-slot ring — physically impossible". Correct for the ring snapshot. But `count` is the **filtered count of events in window** — bounded by 16 (ring size), so it's `u32::try_from(usize).unwrap_or(u32::MAX)` (existing line 46). True ceiling is `WINDOW=16`. So `saturating_add` is unreachable — fine. However, the plan also claims `ok_count <= count` "invariant" — encoded by the loop. This is true within one classifier call, but the **emitted Signal** travels to FR-025 (`risk/ingest/signal_to_contributor.rs:142`), which currently ignores the new field. If FR-025 starts using `count - ok_count` as a "denied count", it will be `<= 16`. Fine. But if a future classifier change widens the window or removes the ring cap, the invariant evaporates silently. No assertion or debug_assert encodes it.
- **Failure scenario:**
  1. Future engineer extends `WINDOW` to 256 (large session). Tests pass.
  2. A racing flip (Finding 1) sets `ok = false` on an event that was just flipped true; another flip sets it true. If the loop iterates and matches the same event twice (which the current code does NOT but a future "match-all" variant would), `ok_count` could exceed `count`. No debug_assert catches it.
- **Evidence:**
  - `plans/.../phase-04-two-signal-payload-count-ok-count.md:202`.
  - `crates/waf-engine/src/checks/tx_velocity/classifiers/withdrawal_velocity.rs:40-46`.
- **Suggested fix:** Add `debug_assert!(ok_count <= count, "ok_count invariant");` inside `evaluate_velocity` after the loop. Cheap; surfaces logic bugs in dev/test. Document the invariant as a doc-comment on the `Signal` variant.

---

## Finding 10: Phase-3 cooldown semantics shift is NOT functionally equivalent — long-RTT upstreams can fire signal AFTER the next request burst has already been recorded

- **Severity:** Medium
- **Location:** Phase 3, Risk Assessment row "Cooldown semantics shift — was 'cooldown since record', now 'cooldown since set_outcome'"
- **Flaw:** Plan claims "functionally equivalent — both fire on the same logical event boundary". False. With eval at `record()`, signal fires at T_request and `last_signal_ms = T_request`. With eval at `set_outcome()`, signal fires at T_response and `last_signal_ms = T_response = T_request + RTT`. If origin RTT is 800 ms and cooldown is 1000 ms, the cooldown window for the NEXT request runs from T_response, but the next request may have been recorded between T_request and T_response. The next event's classifier run (at its own T_response) reads `last_signal_ms` = the old response's T_response; if the new response_filter fires before the old one's set_outcome lands (because aggregator submit is spawned and may delay `mark_signal`), cooldown can fail.
- **Failure scenario:**
  1. Withdrawal A: records at T=0. Upstream slow (1.5s).
  2. Withdrawal B: records at T=200. Upstream fast (300ms). B's `set_outcome` at T=500. B's classifier sees count=2, breach → emits signal, `mark_signal(T=500)`.
  3. A's `set_outcome` at T=1500. Cooldown check: `1500 - 500 = 1000 ms`. If `signal_cooldown_ms = 1000`, this exact value compares as `< 1000` ? Strict `<` means it passes cooldown gate. Signal #2 fires — duplicate.
  4. With request-time eval, A would have evaluated at T=0 (before B), no duplicate.
- **Evidence:**
  - `crates/waf-engine/src/checks/tx_velocity/recorder.rs:191` — `now_ms.saturating_sub(last_signal_ms) < cfg.signal_cooldown_ms` (strict `<`).
  - `plans/.../phase-03-defer-classifier-eval-to-on-response.md:339`.
- **Suggested fix:** Document the new cooldown semantic precisely in the plan: "cooldown is measured from last-emitted-signal at response-time; out-of-order responses (slow followed by fast) may emit duplicate signals if RTTs straddle the cooldown window". Either accept that and bump default cooldown to `2 * p99_upstream_rtt`, or change cooldown to be evaluated at `record()` time using `last_signal_ms` while keeping classifier eval at response.

---

## Unresolved Questions

1. Is there a stable `event token` mechanism the team is willing to add to `Event` and `RequestCtx`, or is the multi-tab/H2-mux race officially accepted as a known limitation? (Finding 1)
2. Does the team agree `upstream_addr.is_some()` is an unsound proxy for "upstream actually responded with these bytes", and is FR-018 also affected? (Finding 2)
3. Logging hook (`logging()` callback) vs `response_filter` for `set_outcome` — what is the team's preference given streaming endpoints? (Finding 5)
4. Hot-reload contract: should `RequestCtx` carry an immutable snapshot of `TxVelocityConfig` that `on_response` MUST use instead of `self.cfg.load()`? (Finding 4)
5. `Default` impl on `RequestCtx` — should this plan add it now to avoid the field-sweep ritual on every future addition? (Finding 7)
