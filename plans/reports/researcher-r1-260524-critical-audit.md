# R1 — Critical Audit Verification (260524)

Branch: main @ 61a75e6b
Method: read issue body → grep/read referenced code on main → verdict
Audit date: 2026-05-20. No commits between audit and HEAD touched the referenced files
(`git log --since=2026-05-20 -- crates/waf-cluster/ crates/waf-engine/src/plugins/
crates/waf-engine/src/checks/ssrf_scanners.rs crates/waf-common/src/url_validator.rs` → empty).

---

## #70 — VALID

**Evidence:**
- `crates/waf-cluster/src/lib.rs:148` — `token: String::new(),` (worker sends empty token).
- `crates/waf-cluster/src/transport/server.rs:203-278` — `JoinRequest` handler reads
  `req.token` nowhere. Acceptance happens unconditionally: `Some(ClusterMessage::JoinResponse(JoinResponse { accepted: true, ... }))` at line 269-270.
- `grep -rn 'validate_token' crates/` → only `crypto/token.rs:39` def + 5 hits all inside
  `#[cfg(test)]` block (lines 89,91,98,107,112,113). Zero callers in production code.

**Reasoning:** Token feature complete (gen + validate impl), CLI emits tokens, but the
server-side handler skips validation. Auth reduces to mTLS via `WebPkiClientVerifier`
(`server.rs:80`). Anyone holding a node cert signed by cluster CA can join with empty/garbage token.

**OPEN_GAP:** None adjacent — the entire feature is dead-wired. Note: `JoinResponse`
optionally ships encrypted CA key (line 209-222) — once an unauthenticated joiner is admitted,
they may receive the encrypted CA blob (still passphrase-locked, but expands attack surface).

---

## #75 — VALID

**Evidence:** `crates/waf-cluster/src/election/mod.rs:244-247`:
```
if role == NodeRole::Main {
    tokio::time::sleep(Duration::from_millis(100)).await;
    continue;
}
```

**Reasoning:** Main branch of the election loop is a no-op sleep. No peer-liveness or quorum check.
`demote_to_worker` is only called on losing a vote round (line 328) — never from the Main path.
A partitioned Main holds `NodeRole::Main` indefinitely; majority partition elects a second Main → dual-Main on heal.

**OPEN_GAP:** `health/mod.rs:117-123` evicts dead peers from the partitioned Main's view.
Once Main's peer list is empty it actively believes it owns the cluster — there is no `is_majority`
gate guarding writes (sync/rules.rs flow not throttled by quorum). Confirms split-brain divergence
path the audit cites.

---

## #76 — VALID

**Evidence:** `crates/waf-cluster/src/election/mod.rs:262-272`:
```
let total_nodes = node_state.total_nodes().await;
if total_nodes <= 1 {
    info!(... "Single-node cluster — claiming Main role without election");
    node_state.promote_to_main().await;
    continue;
}
```

**Reasoning:** Promotion gated only by current `total_nodes() <= 1`. No `ever_had_peers` /
bootstrap-only flag. `grep -rn ever_had_peers crates/waf-cluster/` → 0 results.
Combined with `health/mod.rs:117-123` peer eviction, a partitioned worker that evicts all
peers reaches `total_nodes==1` and self-promotes to Main → split-brain on heal.

**OPEN_GAP:** Configuration role (`NodeRole::Main` vs `Worker` from config.toml) is not consulted
here — a worker can promote itself. Even adding `ever_had_peers` would not help unless the
config-declared initial role is respected.

---

## #77 — VALID

**Evidence:** Primary entry for webhook URL validation = `crates/waf-common/src/url_validator.rs`,
function `is_private_or_reserved` (lines 175-211).

For `http://[::169.254.169.254]/`, `Url::parse` yields `Host::Ipv6` with segments
`[0,0,0,0,0,0,0xa9fe,0xa9fe]`. Walking lines 191-210:
- `v6.is_loopback()` false (not `::1`).
- `v6.is_unspecified()` false (not `::`).
- `v6.is_multicast()` false.
- `seg[0] & 0xfe00 == 0xfc00` → 0, false (not fc00::/7).
- `seg[0] & 0xffc0 == 0xfe80` → 0, false (not fe80::/10).
- IPv4-mapped check at line 202-203 requires `seg[5] == 0xffff` → false (seg[5] = 0).
- `2001:db8` / `64:ff9b` prefixes false.

Returns `false` → URL accepted → webhook fetches AWS IMDS.

`ssrf_scanners.rs:118-150` (the file the audit cites) handles `is_private_ip` for the
engine-level check and has the same gap: `to_ipv4_mapped()` returns None for IPv4-compatible
form, then fc00/fe80 segment checks fail (see line 139-148 — no IPv4-compatible fallback).

`check_forbidden_hostname` (line 144-171) only runs in the `Host::Domain` arm (line 113), so
IP literal `[::169.254.169.254]` skips the hardcoded string blocklist for `169.254.169.254`.

**Reasoning:** Audit claim reproduces. No IPv4-compatible (RFC 4291 §2.5.5.1) special case.

**OPEN_GAP:** Same flaw affects all v4 metadata IPs encoded as `::a.b.c.d`:
`[::100.100.100.200]` (Alibaba), `[::169.254.169.254]` (AWS/Azure), `[::127.0.0.1]` (loopback
— `Ipv6Addr::is_loopback` per Rust std only matches `::1`, NOT `::127.0.0.1`; verified by re-reading
the check at line 192). The bypass surface is wider than the issue title suggests.

---

## #78 — VALID

**Evidence:**
- `crates/waf-engine/src/plugins/manager.rs:27` — `const MAX_MEMORY_BYTES: u64 = 64 * 1024 * 1024;`
- `crates/waf-engine/src/plugins/manager.rs:93-97` — `Config::new()` sets only `consume_fuel(true)`
  and `max_wasm_stack(512 * 1024)`. No `cfg.max_memory_size(..)` or similar.
- `crates/waf-engine/src/plugins/manager.rs:131-132` — `let mut store = Store::new(&self.engine, ());
  store.set_fuel(FUEL_PER_CALL)?;` No `store.limiter(..)` call anywhere in the file.
- `grep -rn 'store.limiter\|set_limiter\|impl ResourceLimiter\|wasmtime::ResourceLimiter' crates/`
  → zero results across whole workspace.
- Line 142 `if bytes.len() < MAX_MEMORY_BYTES as usize` is a host-side guard against overlong
  context strings — does NOT cap WASM linear memory.

**Reasoning:** Fuel meters instructions, not allocations. Plugin declaring `(memory 65536)`
(4 GiB) triggers OOM at instantiation (`linker.instantiate` line 135) before any fuel is spent.
`MAX_MEMORY_BYTES` is documentation noise.

**OPEN_GAP:** `wasm_bytes` is also unbounded at the manager level (`load`, line 229) — a 2 GiB
WASM module would also blow up memory before compile. Pairs with #71 as the issue notes.

---

## Summary table

| Issue | Verdict | Action |
|-------|---------|--------|
| #70 | VALID | keep open — wire `validate_token()` in server.rs JoinRequest handler |
| #75 | VALID | keep open — add quorum check in `role == Main` branch of election loop |
| #76 | VALID | keep open — gate single-node bootstrap on initial config role + `ever_had_peers` |
| #77 | VALID | keep open — add IPv4-compatible IPv6 fallback in both `url_validator.rs` and `ssrf_scanners.rs` |
| #78 | VALID | keep open — attach `Store::limiter()` with `ResourceLimiter::memory_growing` cap |

All 5 critical audit findings reproduce against `61a75e6b`. No fix commits landed since 2026-05-20 for the referenced files.

## Unresolved questions

- None for verification. Out-of-scope but worth flagging to lead: #77 OPEN_GAP shows
  `[::127.0.0.1]` also bypasses (loopback check only covers `::1`); may warrant a follow-up issue
  if not already filed by R4.
