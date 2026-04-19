# Security Scan Report

**Project:** prx-waf (mini-waf) v0.2.0
**Scanned:** 2026-04-17 22:04 Asia/Saigon
**Scope:** Rust workspace (7 crates, ~26.2K LOC) + Vue 3 admin UI
**Tools:** Grep patterns, npm audit, manual verification

## Summary

| Category | Critical | High | Medium | Low |
|----------|:-:|:-:|:-:|:-:|
| Secrets | 0 | 0 | 0 | 2 |
| Dependencies (npm) | 0 | 1 | 4 | 0 |
| Dependencies (cargo) | — | — | — | — (tooling not installed) |
| Code patterns | 0 | 0 | 1 | 1 |
| Env exposure | 0 | 0 | 1 | 0 |

**Overall posture: STRONG.** Mature codebase with explicit safety discipline (Seven Iron Rules in CLAUDE.md, clippy deny-unwrap/panic/todo enforced, parameterized SQL throughout, no `unsafe` blocks, no shell execution). v0.2.0 already hardened against SSRF, DNS rebinding, login rate-limit, regex init panics.

---

## Findings

### HIGH

**H1 — [DEP/UI] picomatch ReDoS (GHSA-c2c7-rcm5-vvqj)**
- Package: `picomatch` transitive via `vite`/`tinyglobby`
- Severity: CVSS 7.5 (CWE-1333 ReDoS via extglob quantifiers)
- Affected range: `<2.3.2` and `>=4.0.0 <4.0.4`
- Location: `web/admin-ui/node_modules/picomatch`, `web/admin-ui/node_modules/tinyglobby/node_modules/picomatch`
- Impact: Dev-only (vite build/dev tooling). Not reachable from production runtime.
- Fix: Major-version vite bump (6.x → 8.0.8). Run `npm audit fix --force` in `web/admin-ui/`.

### MEDIUM

**M1 — [DEP/UI] axios SSRF & Cloud Metadata Exfiltration**
- Package: `axios@1.6.0` (direct dep of admin UI)
- Advisories: GHSA-3p68-rc4w-qgx5 (NO_PROXY bypass → SSRF), GHSA-fvcv-3m26-pcqx (header injection → metadata exfil)
- CVSS: 4.8 each
- Impact: Low — axios is browser-side (runs in admin's browser, talks only to same-origin WAF API via configured base). SSRF vectors rely on attacker control of URL; all UI calls are hard-coded paths. Still worth patching.
- Fix: bump to `axios@^1.15.0` (non-breaking). Edit `web/admin-ui/package.json`.

**M2 — [DEP/UI] vite path traversal in `.map` handling**
- Package: `vite` (direct)
- Advisory: GHSA-4w7w-66w2-5vf9 (CWE-22 path traversal, CWE-200 info disclosure)
- Affected: `<=6.4.1`
- Impact: Dev-only. Allows crafted requests to dev server to read files outside project root. Not production runtime.
- Fix: bump to `vite@8.0.8` (major). Same upgrade as H1.

**M3 — [DEP/UI] esbuild dev-server CORS bypass**
- Package: `esbuild` (transitive)
- Advisory: GHSA-67mh-4wv8-2f99
- Affected: `<=0.24.2`
- Impact: Dev-only. Browser requests to esbuild dev server can cross-origin read responses.
- Fix: vite@8 bump pulls newer esbuild.

**M4 — [DEP/UI] follow-redirects auth header leak**
- Package: `follow-redirects` (transitive via axios)
- Advisory: GHSA-r4q5-vmmm-2653 (CWE-200)
- Affected: `<=1.15.11`
- Impact: Custom Authorization headers leaked on cross-domain redirects. Low risk since UI talks to fixed backend, but bundled code path exists.
- Fix: resolved by upgrading axios (bundled).

**M5 — [CODE] `.unwrap()` / `.expect()` usage — tests only, no production risk**
- 209 raw matches across 32 files. **All sampled occurrences are inside `#[cfg(test)]` blocks or test-only modules** (gateway/src/lb.rs test harness, ssl.rs tests, blocklist.rs tests, rules.rs tests, auth.rs tests, security.rs tests, waf-cluster/tests/*).
- Workspace lints `deny(clippy::unwrap_used, clippy::panic)` enforce absence in production code.
- Seven Iron Rules (CLAUDE.md) verified intact.
- **No action required** — recorded for audit trail.

**M6 — [CONFIG] `.gitignore` missing `.env` patterns**
- `.gitignore` currently lists `target/`, `node_modules/`, `*.xdb`, etc., but has **no `.env` rule**.
- No `.env` files are currently git-tracked (`git ls-files` confirms), so no leak.
- Risk: future contributor adding a local `.env` would accidentally commit credentials.
- Fix: append to `.gitignore`:
  ```
  .env
  .env.*
  !.env.example
  ```

### LOW

**L1 — [SECRET] Default admin credentials `admin / admin123` documented in plaintext**
- Present in README.md:66,94, CLAUDE.md:27, docs/cluster-guide.md:88, docs/deployment-guide.md:28,82, docker-compose.cluster.yml:18, tests/e2e-cluster.sh:147.
- Not a real secret — seed fixture for first login. README line 66 states "change immediately."
- Verify the `seed-admin` CLI enforces password change on first login or at least warns. If not, add a forced-change flag.

**L2 — [SECRET] `AKIAIOSFODNN7EXAMPLE` in source**
- File: `crates/waf-engine/src/checks/sensitive.rs:32`
- This is the canonical AWS docs example string, used here as a **detection pattern** in the WAF's data-leak checker. Not a real credential. False positive.

**L3 — [CODE] `-----BEGIN PRIVATE KEY-----` in source**
- Files: `crates/waf-cluster/src/crypto/{token,store}.rs`, `crates/waf-engine/src/checks/sensitive.rs`
- All occurrences are in rustdoc comments (format descriptions) or detection patterns, not literal keys. False positive.

### INFORMATIONAL — Defenses observed

- **No `unsafe` blocks** in any workspace crate (`unsafe fn/impl/{` grep clean).
- **No shell execution** — zero `std::process::Command::new` calls.
- **No insecure TLS** — no `danger_accept_invalid_certs`, no `NoCertificateVerification`, no `rejectUnauthorized: false`.
- **No SQL string-building** — zero `format!("... SELECT/INSERT/UPDATE/DELETE ...")` matches; 107 sqlx calls in `waf-storage/src/repo.rs` all use parameterized bind.
- **No XSS sinks in UI** — no `v-html`, `innerHTML`, `dangerouslySetInnerHTML`, `document.write`, `eval()`, or `new Function()` in `web/admin-ui/**`.
- **No hardcoded real credentials, API keys, or private keys.**
- **Argon2** password hashing + **JWT with refresh** + **login rate-limit** already in place (waf-api).
- **AES-256-GCM** at-rest encryption for cluster CA key (waf-cluster/src/crypto/store.rs).
- **Ed25519** signature verification on community blocklist delta sync (hardened in commit 822eb7f).
- **Fail-closed** community init, bounded reporter, streaming body limit (commit cc8f17e).
- **XFF CIDR validation**, **cluster peer fencing**, **rule deletion sync** (v0.2.0).

---

## Dependency Audit Tooling Gap

- `cargo-audit` not installed locally.
- `cargo-deny` not installed locally.
- `.github/workflows/sec-audit.yml` runs both weekly in CI (per scout report), so production pipeline is covered.
- `deny.toml` documents 7 intentional CVE ignores:
  - `RUSTSEC-2024-0437` — protobuf DoS via pingora 0.8.0 (upstream blocker)
  - Wasmtime CVEs (mostly resolved by v0.2.0 bump to 43.0.0)
  - `daemonize`, `derivative`, `paste` — pingora transitive, unmaintained

**Recommendation:** Install `cargo-audit` + `cargo-deny` locally for pre-push validation:
```
cargo install cargo-audit cargo-deny
```

---

## Recommendations (priority order)

1. **`npm audit fix --force`** in `web/admin-ui/` — resolves picomatch HIGH + vite/esbuild/axios/follow-redirects MEDIUM in one shot (major vite bump).
2. **Patch `.gitignore`** — add `.env*` patterns to prevent future secret leaks.
3. **Seed-admin flow audit** — confirm first-login password change is enforced (or add a `--force-password-change` flag + startup warning when default hash detected).
4. **Install `cargo-audit`/`cargo-deny` locally** for dev parity with CI.
5. **Consider rotating default admin password hash at build time** — embed a random password printed once on first `seed-admin`, store hash only.

---

## Unresolved Questions

- Does `seed-admin` enforce password change on first login? Code path not inspected in this scan.
- Is the admin UI served only on the internal management port (16827) or also exposed publicly in some deployments? If public, the default credentials risk rating rises.
- Are the WASM plugin sandbox limits (wasmtime 43) configured with memory/CPU/epoch bounds, or left at permissive defaults?
