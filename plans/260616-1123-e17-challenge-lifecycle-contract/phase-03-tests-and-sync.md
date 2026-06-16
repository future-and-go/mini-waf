# Phase 03 — Tests + story/docs sync

Stories: US-1701, US-1702.

## Overview

- Priority: high
- Status: done
- Prove the contract behavior, keep existing suites green, sync stories/docs.

## Requirements

- Unit (waf-engine):
  - HTML render contains `challenge` + Format B form + hidden `challenge_token`.
  - Real-issuer token (contains `.`) renders without error.
  - PoW verify: a known `(token, nonce)` with ≥16 leading zero bits → Valid;
    insufficient → Invalid. (Reuse/extend existing `pow.rs` tests.)
- Integration:
  - issue → `verify_pow` accepts a solved nonce; `verifier.verify` consumes the
    token once (second use → Replay). Extend `challenge_flow.rs` only if a gap.
- Gateway:
  - `/challenge/verify` happy path returns 200 + `__waf_cc` Set-Cookie; bad nonce
    → non-200. Inline unit where the proxy test seam allows; otherwise document
    coverage via the engine-level verify test + manual note.
- Keep `cargo test` (workspace) + `cargo clippy` green.

## Implementation steps

1. Add/extend unit tests in `crates/waf-engine/src/challenge/` for render +
   token-charset.
2. Confirm `pow.rs` covers the 16-bit accept/reject; add a case if missing.
3. Run `cargo test -p waf-engine -p gateway` and `cargo clippy --workspace`.
4. Spawn `tester` subagent to run the full suite; fix to green.
5. Spawn `code-reviewer` subagent (acceptance criteria + touchpoints context).
6. `/ck:project-management` sync-back: update phase statuses + `plan.md`.
7. Update story statuses to `done` via `scripts/bin/harness-cli story update`.
8. `docs-manager` if docs warrant; offer commit via `git-manager`; `/ck:journal`.

## Todo

- [x] Renderer/template unit tests
- [x] PoW 16-bit accept/reject unit test
- [x] `/challenge/verify` endpoint test (where seam allows)
- [x] Full `cargo test` + clippy green
- [x] tester + code-reviewer subagents
- [x] story status → done, docs sync, journal

## Success criteria

- US-1701 + US-1702 acceptance criteria demonstrably pass.
- No regression across the workspace.
