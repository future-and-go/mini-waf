# Code Review — FR-009 Phase 1 (Tier Gate Wiring)

**Target:** `crates/gateway/src/cache.rs`
**Reviewer:** code-reviewer
**Date:** 2026-05-02

## Scope
Phase 1 defensive signature change + bypass logic + tests. Per task brief: not flagging "unused param / no callers" — wiring is Phase 2/3.

## Security Correctness — CRITICAL bypass

**Holds.** Bypass paths audited:

1. `put()` line 144 — gate 1 fires before any `inner.insert`. Correct. Stat counter incremented. Returns `false`.
2. `get()` line 107 — symmetric short-circuit before `inner.get`. Stat counter incremented. Returns `None`.
3. No alternate insertion path exists in this file (`purge_*`, `flush` only remove). 
4. `inner` field is `pub(self)` (default). External callers cannot bypass tier gate to reach `Cache<...>` directly.
5. Reclassification race (Medium→Critical mid-flight): `get()` re-checks tier on every lookup → no stale serve. Test `critical_tier_bypasses_get_even_for_existing_key` validates.

**No holes.** Audit invariant intact.

## TTL Cap Math — `apply_policy_cap` / `apply_policy_default`

Matches plan semantics:

| Variant + upstream | Plan expectation | Code result |
|---|---|---|
| Aggressive(300) + max-age=10000 | cap to 300 | `min(10000, 300, 3600) = 300` ✓ |
| Aggressive(300) + silent | default 300 | `apply_policy_default → 300` ✓ |
| ShortTtl(120) + max-age=30 | unchanged 30 | `min(30, 120, 3600) = 30` ✓ |
| ShortTtl(120) + max-age=600 | cap to 120 | `min(600, 120, 3600) = 120` ✓ |
| Default(N) + max-age=K | only bound by `max_ttl` | `min(K, hard_max, hard_max) = min(K, hard_max)` ✓ |
| Default(N) + silent | use N | `apply_policy_default → N` ✓ |
| NoCache | bypassed before reaching cap fn | defensive zero/fallback ✓ |

`u64::from(*ttl_seconds)` widens `u32` → no overflow. `Duration::from_secs(0)` is valid (entry stored with max_age=0; honestly low risk — moka's `time_to_live` would still expire it via the global `max_ttl`, and CachePolicy::NoCache is bypassed earlier so this branch is unreachable in practice). Acceptable.

One minor: `apply_policy_cap` for `Default { .. }` does not cap by the policy's own `ttl_seconds` — only by `hard_max`. The plan says "Default → use as default if upstream silent" (no explicit ceiling). Code matches plan. Operators may be surprised that `Default { ttl_seconds: 60 }` lets upstream `max-age=3600` cache for 3600s. Worth a doc-comment but not a bug.

## Set-Cookie Bypass

`name.eq_ignore_ascii_case("set-cookie")` — case-insensitive ✓. Iterates all headers ✓. Runs after CRITICAL gate but before status/Cache-Control checks, so Set-Cookie + 500 still bypasses (correct order — security gate before semantic gate). 

One observation: HTTP allows multiple `Set-Cookie` headers (one per cookie); `.any()` correctly catches any occurrence. Empty value `("Set-Cookie", "")` would also bypass — fine, defensive.

## Stat Counter Semantics — `bypassed_critical`

**Name is misleading.** Counter increments on:
- CRITICAL tier `put` / `get` (true CRITICAL bypass)
- `CachePolicy::NoCache` `put` regardless of tier (NOT a CRITICAL bypass — could be a LOW-tier route configured `NoCache`)

The doc comment on the field (line 38) acknowledges this ("by tier or `NoCache` policy"), but the metric name on the dashboard / audit log will overcount CRITICAL events. For audit defensibility (FR-009 AC-1 says "must increment on every CRITICAL touch"), a dashboard query for "CRITICAL bypasses" using this counter will be inflated by NoCache hits.

**Recommendation (non-blocking):** either rename to `bypassed_policy` / `bypassed_non_cacheable`, or split into two counters (`bypassed_critical_tier`, `bypassed_no_cache_policy`). Plan code-sketch lumps them, so this is a forward-looking concern — flag for Phase 2/3 dashboard wiring. Not a Phase-1 blocker.

Also: `Set-Cookie` bypass does NOT increment the counter (test `set_cookie_response_bypasses_cache` asserts this explicitly). That's a deliberate semantic choice — Set-Cookie is auth-flow protection, not a tier/policy bypass. Reasonable but worth documenting alongside the rename.

## Seven Iron Rules

- ✓ No `.unwrap()` in production paths. Tests use `.expect("present")` — allowed by rules.
- ✓ No `todo!()` / `unimplemented!()`.
- ✓ No dead code (intentional pre-wiring excepted per scope).
- ✓ Explicit error handling — `parse::<u64>()` uses `if let Ok` (line 277), no unwrap.
- ✓ No panics.
- ✓ `parking_lot` not used here (no Mutex needed; atomics + moka).
- ✓ No SQL, no secret logging.

## Edge Cases

| Case | Behavior | Notes |
|---|---|---|
| `max-age=` (empty) | Falls through to `Default` | OK — `parse::<u64>` on `""` errors, loop continues, returns `Default`. |
| `max-age=-1` | Falls through to `Default` | `u64::parse` rejects negatives. |
| `max-age=99999999999999999999` | Falls through to `Default` | Parse overflow → ignored. Good. |
| `Cache-Control: no-store, max-age=600` | `NoStore` (bypass) | `contains("no-store")` checked first ✓ |
| `Cache-Control: public, max-age=60` | `MaxAge(60)` | `split(',')` + `trim()` works ✓ |
| status 199 / 300 | Not cached | `(200..300)` excludes both ✓ |
| status 200 with body=Bytes::new() | Cached | OK, intentional. |
| Empty headers vec | No Set-Cookie match → proceeds | ✓ |
| Whitespace `max-age = 60` | Treated as `Default` | `strip_prefix("max-age=")` requires no space. RFC 7234 grammar permits OWS around `=` (`token "=" OWS token`). **Minor parser gap** — real-world `Cache-Control` headers very rarely have spaces around `=`, but a strict reading of RFC allows it. Low impact, flag as informational. |
| Header name `cache-control` (lowercased by upstream) | Caller responsibility — `cache_control: Option<&str>` is the value, not the header name. ✓ |
| `no-cachexyz` (substring false-match) | Treated as `NoCache` | `contains("no-cache")` will match `no-cache-extension` directives. RFC reserves `no-cache` token; a directive like `no-cachefoo` is non-standard but `contains` would mis-flag it as `NoCache` → bypass. **Fail-safe direction** (over-bypass is safer than under-bypass for a security cache). Acceptable. |
| `private-foo` substring | Same fail-safe | Acceptable. |
| u64 underflow | Not possible — only `min` and `from(u32)`. ✓ |

## Informational (non-blocking)

1. Counter naming: `bypassed_critical` will mislead audit dashboards once `NoCache` traffic flows. Suggest split or rename in Phase 2.
2. Cache-Control parser: `contains` substring matching could over-match non-standard directive names. Fail-safe direction so accept; revisit if false-bypass volume becomes operational pain.
3. `apply_policy_cap` for `CachePolicy::Default` does not cap by `ttl_seconds` — operator-visible, doc the asymmetry between `Default` (no cap) and `Aggressive` (caps).
4. Tests do not assert that `get()` for a Critical tier still increments `bypassed_critical` when key is absent — current code does increment (line 108 fires before lookup). Worth one-line test: cold-cache CRITICAL `get` → counter == 1.
5. No test for `Cache-Control: no-store` returning false. Existing test coverage solid but this directive isn't directly exercised.

## Positive

- Bypass order documented in doc-comment (lines 124–130) — matches implementation.
- Symmetric `get()` gate (defends against hot-reload reclassification) is the right call for an audit invariant.
- Atomic counters (`Relaxed` ordering — fine for stats).
- Test names are precise and behavior-focused.
- `cargo fmt`-clean style; no clippy concerns visible.

## Unresolved Questions

- Should `bypassed_critical` be renamed/split before Phase 2 dashboard wiring? (My recommendation: yes, before metrics emit publicly.)
- Should `Cache-Control: max-age` parser tolerate OWS around `=` per RFC 7234? (Pragmatic answer: no; real upstreams don't emit it.)

## Score & Status

**Score: 9.5 / 10**

Security invariant holds. TTL math correct. Tests cover the AC-1 invariant and both reclassification directions. Only flagged concern (counter naming) is a forward-looking observability nit, not a correctness bug.

**Status: DONE**
