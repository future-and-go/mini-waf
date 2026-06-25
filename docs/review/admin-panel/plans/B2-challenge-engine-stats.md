# B2 — Challenge Engine: live stats, authed preview, PoW status

**G.1 rows:** 10, 11 · **Req IDs:** FR-006 (Challenge Engine: JS + PoW) ·
**Epic:** E17-challenge-lifecycle (US-1701, US-1702) · **Lane:** normal
(B2a/B2c) → high-risk (B2d challenge enforcement wiring)

> Companion: spec §B2. Follows [`ARCHITECTURE.md`](../../../ARCHITECTURE.md)
> and [`CONTEXT_RULES.md`](../../../CONTEXT_RULES.md). Read
> `docs/product/challenge-lifecycle.md`.

---

## 1. Codebase audit (current state)

**Frontend** (`web/admin-panel/src/pages/challenge-engine/index.tsx`):
- `GET`/`PUT /api/challenge/config` — real. `GET /api/challenge/stats` expects
  `ChallengeStats` (lines 43-48): `{ issued, passed, failed, replays }`.
- `POST /api/challenge/preview` is called via **bare `fetch()`** (lines
  110-114) → no `Authorization` header; body `{ branding }`, response raw HTML.
- PoW + CAPTCHA challenge-type options are `disabled:true` "Coming soon"
  (lines 243-264).

**Backend reality:**
- `get_challenge_stats` (`challenge_api.rs:133-137`) → hardcoded zeros, ignores
  state. Config get/put + `challenge_preview` (returns HTML) are real.
- **No issued/passed/failed/replay counters exist** anywhere in the gateway or
  engine hot path. The proxy has only a generic `blocked_counter`.

**Engine/gateway reality:**
- Issue path: `handle_challenge` (`proxy_waf_response.rs:187`), token issued at
  244-247, log "Challenge issued" at 317-322.
- Verify path: `handle_challenge_verify` (`proxy_waf_response.rs:71-93`),
  intercepted at `proxy.rs:627-631` (`POST /challenge/verify`). Outcomes from
  `ChallengeVerifier::verify`: `Valid{nonce}`, `Invalid`, `Replay`, `Expired`.
- **PoW is fully implemented**: `verify_pow` (`waf-engine/src/challenge/pow.rs:77`),
  `CHALLENGE_POW_BITS = 16`; JSON challenge advertises
  `"challenge_type":"proof_of_work"`.
- **Critical production gap:** `WafProxy::with_challenge_ctx` exists
  (`proxy.rs:152-154`) but **`prx-waf/src/main.rs` never calls it** →
  `challenge_ctx = None` → `WafAction::Challenge` is treated as **Allow**
  (`proxy_waf_response.rs:214-216`). So challenges are never actually issued in
  the running system. Stats would therefore always be zero even once wired.

## 2. Gap

- B2a: stats endpoint has no counters to read.
- B2c: preview call is unauthenticated (works only because the route isn't
  bearer-gated today; breaks if gated, and is inconsistent).
- B2d: PoW exists but the whole challenge action is disabled at runtime.

## 3. Assumptions (explicit)

- A-1: Counters are process-local atomics exposed via `AppState` (mirror
  `request_counter`/`blocked_counter`), not persisted across restarts.
- A-2: "passed" = verify `Valid`; "failed" = `Invalid`+`Expired`; "replays" =
  `Replay`; "issued" = each challenge response emitted. Confirm with US-1702.
- A-3: PoW is in scope to **expose** (it already works); CAPTCHA is **not** in
  FR-006 → remove/relabel rather than implement.
- A-4: Actually enabling challenge enforcement (wiring `ChallengeCtx` in
  `main.rs`) is **high-risk** (new enforcement behavior) and is a separate,
  flagged phase — stats wiring (B2a) is meaningful only once this is done, but
  the API/counters can land first and read zero safely.

## 4. Scope

**In scope:** counter struct + increments at issue/verify; `get_challenge_stats`
reads them; FE preview → shared `httpClient`; remove CAPTCHA option; enable the
PoW option in the type selector.

**Out of scope (separate stories):** implementing a new challenge algorithm
(PoW already exists); persistent/rolling stats; wiring challenge enforcement in
`main.rs` (B2d — high-risk, own story under E17).

## 5. Phased plan (independently testable & reversible)

### Phase 1 — Preview auth (FE-only, tiny)
- Replace the bare `fetch()` (`index.tsx:110-114`) with the shared
  `httpClient` POST so the bearer token is attached; keep `responseType` text.
- **Success:** Network tab shows `Authorization: Bearer …` on
  `/api/challenge/preview`; preview renders while authenticated; works if the
  route is later bearer-gated.
- **Reversible:** one-file revert.

### Phase 2 — Challenge counters (engine/gateway)
- Add `ChallengeStats { issued, passed, failed, replays }` as `AtomicU64`s on a
  shared struct in `AppState` (or on the challenge subsystem) injected into the
  gateway ctx.
- Increment `issued` at issue (`proxy_waf_response.rs:317`); map verify outcomes
  to `passed/failed/replays` in `handle_challenge_verify`.
- **Success:** unit/integration — calling the issue path increments `issued`;
  simulated `Valid`/`Replay`/`Invalid` increment the right counters.
- **Reversible:** counters are additive; removing increments restores old behavior.

### Phase 3 — `GET /api/challenge/stats` reads counters
- Rewrite handler to take `State` and read the four atomics.
- **Success:** after Phase 2 events, the endpoint returns matching non-zero
  numbers; with no events, returns zeros (no error).
- **Reversible:** revert handler body.

### Phase 4 — PoW expose / CAPTCHA removal (FE, tiny)
- Remove `disabled:true` from the `pow`/`proof_of_work` option; remove (or mark
  clearly non-roadmap) the CAPTCHA option (`index.tsx:243-264`).
- **Success:** selecting PoW saves `type: proof_of_work` via
  `PUT /api/challenge/config`; preview renders the PoW challenge HTML.
- **Reversible:** one-file revert.

### Phase 5 (separate high-risk story) — enforce challenges
- Wire `WafProxy::with_challenge_ctx(...)` in `prx-waf/src/main.rs` so
  `WafAction::Challenge` actually issues challenges.
- **Success:** an end-to-end test where a risky request receives a challenge
  response and a solved PoW retry is admitted; stats reflect it.

## 6. Edge cases & failure modes

- Stats read with enforcement disabled (Phase 5 not done) → all zeros; FE should
  show "0" calmly, and ideally a hint that challenges aren't enforced.
- Counter increment must be `Relaxed` and never panic on the hot path.
- Verify with malformed body → counts as `failed`, returns the existing error.
- Replay detection already exists; ensure it maps to `replays`, not `failed`.
- Preview HTML must not be cached with stale branding (set no-store).

## 7. Security

- Phase 1 closes an inconsistent unauthenticated call; keep all challenge admin
  routes behind `require_auth`.
- Do not expose token secrets/nonce-store internals in stats.
- PoW difficulty (`CHALLENGE_POW_BITS`) is a security parameter — surface as
  read-only in the GUI; changing it is a config concern, not a stat.

## 8. Observability

- Canonical per-request JSON log on `get_challenge_stats`.
- Keep the existing "Challenge issued" structured log; add solve-outcome logs
  (`action="challenge.verify", outcome=valid|replay|invalid|expired`).

## 9. Production-readiness gaps

- **Biggest gap:** challenge enforcement is off (`ChallengeCtx` unwired) — FR-006
  is not actually active. Stats wiring without Phase 5 yields a permanently-zero
  dashboard; this must be communicated so the GUI fix isn't mistaken for FR-006
  completion.
- Stats are process-local and reset on restart; production may want rolling/
  persisted metrics.

## 10. Harness intake

- **Lane:** normal for B2a/B2c/B2 PoW-expose; **high-risk** for Phase 5
  (enforcement behavior → story packet under E17 + possible decision).
- **Story:** update `docs/stories/epics/E17-challenge-lifecycle/` (US-1701/1702);
  use `docs/templates/story.md`.
- **Validation:** FE manual (preview auth, PoW selectable), unit/integration for
  counters, E2E for Phase 5. Record with `harness-cli story update`.
