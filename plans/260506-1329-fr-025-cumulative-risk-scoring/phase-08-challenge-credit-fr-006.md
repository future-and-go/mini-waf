---
phase: 8
title: "Challenge Credit FR-006"
status: pending
priority: P1
effort: "3d"
dependencies: [1, 7]
---

# Phase 8: Challenge Credit — FR-006 Wiring

## Overview

Close the FR-027 loop: a successful challenge (e.g. JS-PoW from FR-006) issues an HMAC-signed credit token; the next request presenting the token applies a negative contributor (`Contributor { kind: ChallengeCredit, delta: -25 }`) to the actor's `RiskState`. A failed challenge applies a positive contributor (+20). Tokens are single-use (consumed-nonce LRU) to prevent replay.

This phase implements the SCORING side of challenge credit. The actual JS-PoW page/verifier (the FR-006 ticket proper) is out of scope — this phase wires the verified-token surface so FR-006 can plug in.

## Why P8 (Last Functional Layer)

Decay alone (P5) reduces score over time, but a verified human shouldn't have to wait. Challenge credit gives the WAF a way to actively reduce score on positive proof-of-humanity. This closes FR-027 ("Allow / Challenge / Block" with the Challenge tier actually doing useful work).

Comes after Redis (P7) because credits must persist cluster-wide — single-node memory makes cluster-coherent challenge state impossible.

## Requirements

**Functional:**
- HMAC token format: `base64url(payload).base64url(hmac_sha256(key, payload))`. Payload = `{actor_id, issued_ms, nonce}`.
- HMAC secret loaded from `risk.session.hmac_secret_path`. Persisted across restarts (FR-RS-085). Generated only on first boot if absent.
- `ChallengeIssuer::issue(actor) -> token` — called by FR-006 page on successful PoW.
- `ChallengeVerifier::verify(token, request_actor) -> VerifyOutcome` — called inline by Scorer.
  - `Valid` → contributor delta=-25, single-use enforced.
  - `Invalid(reason)` → contributor delta=+20 (failed challenge); no consume.
  - `Replay` → contributor delta=+30; alerted.
  - `Expired` → contributor delta=+10 (mild penalty; expected drift).
- Consumed-nonce LRU: in-memory bounded `LruCache<Nonce, ()>` (size ~100k); cluster-shared via Redis SETNX with TTL = max(token TTL).
- Binding: token's `actor_id` MUST match the request's RiskKey owner. Mismatch → `Invalid(BindingMismatch)`.
- Token TTL: 5 minutes default.

**Non-functional:**
- Verify p99 ≤ 200µs (HMAC + LRU + Redis SETNX in-pool).
- Token size ≤ 256 bytes base64.

## Architecture

```
risk/challenge_credit/
├── mod.rs                  # public ChallengeIssuer, ChallengeVerifier, VerifyOutcome
├── token.rs                # encode/decode, HMAC sign/verify
├── nonce_store.rs          # LRU + Redis SETNX consume-once
├── secret.rs               # load/persist HMAC key from disk
└── tests/
    ├── replay.rs
    ├── binding_mismatch.rs
    └── token_lifecycle.rs
```

### Token Format

```
Payload (JSON, compact):
  {"a":"<actor_owner_id>","i":1700000000000,"n":"<128-bit-hex-nonce>","t":300}
                                                                      ^ TTL secs

Encoded:
  base64url(payload) + "." + base64url(hmac_sha256(secret, payload))
```

> Why `actor_owner_id` not full RiskKey triple? Owner_id is the canonical identity (P7); robust against IP rotation but tied to fp/session legs. Mismatch detection: verifier resolves request's owner_id and compares.

### Verify Flow

```
1. Decode token; check format         → if bad → Invalid(MalformedToken)
2. Verify HMAC                        → if bad → Invalid(BadSig)
3. Check `now - issued_ms < ttl_ms`   → if not → Expired
4. Resolve request → owner_id; compare → if not → Invalid(BindingMismatch)
5. nonce_store.try_consume(nonce)     → if false → Replay
6. → Valid; return ChallengeOutcome::Valid
```

### Consumed-Nonce Store

- In-process LRU (size 100k, ~5MB) — fast path.
- On miss, SETNX `waf:risk:cnonce:{nonce}` "1" EX `ttl_sec` to Redis. If success → consume. If fail (already set) → Replay.
- TTL = token TTL + small skew margin (10s).

## Related Code Files

**Create:**
- `crates/waf-engine/src/risk/challenge_credit/mod.rs`
- `crates/waf-engine/src/risk/challenge_credit/token.rs`
- `crates/waf-engine/src/risk/challenge_credit/nonce_store.rs`
- `crates/waf-engine/src/risk/challenge_credit/secret.rs`
- `crates/waf-engine/src/risk/challenge_credit/tests/replay.rs`
- `crates/waf-engine/src/risk/challenge_credit/tests/binding_mismatch.rs`
- `crates/waf-engine/src/risk/challenge_credit/tests/token_lifecycle.rs`
- `crates/waf-engine/benches/challenge_credit.rs`

**Modify:**
- `crates/waf-engine/src/risk/mod.rs` — `pub mod challenge_credit;`
- `crates/waf-engine/src/risk/config.rs` — `challenge:` section (ttl_sec, hmac_secret_path, lru_size).
- `crates/waf-engine/src/risk/scorer.rs` — call verifier on every request that bears the credit cookie/header; fold result as contributor.
- `crates/waf-engine/Cargo.toml` — add `hmac = "0.12"`, `sha2 = "0.10"`, `base64 = "0.22"` (verify version alignment).
- `docs/deployment-guide.md` — document HMAC secret persistence path + ops runbook for rotation.

## Implementation Steps

1. **HMAC secret bootstrap.** `secret::load_or_init(path)` — read from disk; if absent, generate 32 random bytes via `OsRng`, write 0600 perms. Never auto-rotate (Iron Rule §11).
2. **Token codec.** `token::encode(payload, secret) -> String`, `token::decode_and_verify(s, secret, now) -> Result<Payload, VerifyError>`. Use `subtle` for constant-time HMAC compare.
3. **Nonce store.** In-process LRU (`lru` crate; already in workspace? grep). Cluster-shared via Redis SETNX. `try_consume(nonce, ttl) -> bool`.
4. **Issuer.** `ChallengeIssuer::issue(owner_id, ttl_sec) -> String`. Mints fresh nonce via `OsRng`.
5. **Verifier.** `ChallengeVerifier::verify(token, request_owner_id, now) -> VerifyOutcome`. Implements full flow above.
6. **Scorer integration.** Read credit from configured cookie/header (e.g. `X-WAF-Cred`). On present: verify → fold contributor (Valid=-25, Invalid=+20, Replay=+30, Expired=+10). On absent: no-op.
7. **Tests.**
   - `token_lifecycle.rs`: issue → verify → Valid → consume → re-verify → Replay.
   - `replay.rs`: same nonce twice → Replay both nodes (cluster coherence via Redis).
   - `binding_mismatch.rs`: token issued for actor A, presented by actor B → Invalid(BindingMismatch).
   - HMAC tampering → Invalid(BadSig).
   - Expired → Expired outcome.
   - Bench: verify p99 ≤ 200µs (warm Redis pool).
8. **Compile gates + integration smoke.**

## Common Pitfalls

- **HMAC secret regenerated on restart** → all live tokens invalidate → thundering challenge herd. Persist to disk (§6 pitfall #9 brainstorm).
- **Nonce LRU but no Redis fallback** → cluster-wide replay possible (attacker rotates between nodes). Redis SETNX is the source of truth; LRU is fast-path.
- **Constant-time compare missed** → timing attack on HMAC. Use `subtle::ConstantTimeEq`.
- **Token decoded as `String` vs `&[u8]` allocs** — use `Bytes` or `&[u8]` until final decode.
- **Verifier panics on malformed input** — must return `Invalid(MalformedToken)`, never panic.

## Success Criteria

- [ ] HMAC secret persisted across restart (file present, 0600 perms).
- [ ] Issue → verify → Valid → consume → Replay flow green.
- [ ] Binding mismatch detected.
- [ ] Verify p99 ≤ 200µs.
- [ ] Cluster-coherent replay detection (instance A consumes → instance B sees Replay).
- [ ] No panics on malformed input (fuzzed via `cargo-fuzz` if available).
- [ ] No `.unwrap()` introduced.
- [ ] Constant-time HMAC compare verified.

## Risk Assessment

| Risk | Severity | Mitigation |
|------|----------|------------|
| Secret leak via logs | High | Never log token, secret, payload — only outcome enum |
| Token replay across nodes | High | Redis SETNX is source of truth; LRU is cache only |
| Secret rotation loses live tokens | Medium | Document: rotate during low-traffic window; old tokens invalidate |
| Clock drift triggers Expired storm | Medium | Token TTL + 10s skew; alert on Expired rate spike |
| Fuzz finds parser panic | Medium | `cargo-fuzz` token decoder; gate merge |

## Verify

```bash
cargo test -p waf-engine risk::challenge_credit
cargo bench -p waf-engine --bench challenge_credit
# Smoke: issue token, verify, replay
HMAC_SECRET_FILE=/tmp/waf-hmac.key cargo run -p prx-waf  # auto-mints if absent
```
