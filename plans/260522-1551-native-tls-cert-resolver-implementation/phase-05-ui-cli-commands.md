---
phase: 5
title: "UI Request via ACME + CLI cert commands"
status: pending
priority: P2
effort: "2d"
dependencies: [4]
---

# Phase 05: UI + CLI commands

## Overview

Frontend: UI page Certificates đã có (`web/admin-panel/src/pages/certificates/index.tsx`); thêm button "Request via ACME", action "Renew now", cột "Expires in" với badge warning/danger, ACME error display. Backend: CLI 6 commands `prx-waf cert {list,issue,upload,renew,delete,show}` mapping vào API endpoints. Status endpoint `GET /api/certificates/{id}/status`.

## Requirements

### Functional UI
- Button "Request via ACME" modal: select host_code (dropdown từ `/api/hosts`) + input domain + checkbox "Use staging" + submit
- Modal submit → `POST /api/certificates/acme/issue` → polling status mỗi 3s
- Per-row action "Renew now" → `POST /api/certificates/{id}/renew`
- Per-row action "Reload" → `POST /api/certificates/{id}/reload`
- Column "Expires in" — show "N days" với badge:
  - >30 days: muted gray
  - 14-30 days: yellow warning
  - 7-14 days: orange
  - <7 days: red danger
- Cột "Last error" — hiển thị ACME error message nếu có
- Toast notification trên success/error

### Functional CLI
```
prx-waf cert list [--status active|pending|error|expired]
prx-waf cert issue --host-code <code> --domain <fqdn> [--staging]
prx-waf cert upload --host-code <code> --domain <fqdn> --cert <path> --key <path>
prx-waf cert renew <cert-id>
prx-waf cert delete <cert-id>
prx-waf cert show <cert-id>
prx-waf cert reload <cert-id>
```

### Functional API
- `GET /api/certificates/{id}/status` → JSON `{id, domain, status, not_after, days_until_expiry, last_renewal_at, last_error, auto_renew}`
- Existing `GET /api/certificates` extend response với `days_until_expiry` computed field

### Non-functional
- UI form validation: domain regex (RFC 1123 subset), host_code không empty
- CLI commands fail-fast khi config missing
- CLI bypass HTTP API, gọi trực tiếp DB + SslManager (giống `prx-waf rules list`)

## Architecture

### CLI subcommand mới (`crates/prx-waf/src/main.rs`)

```rust
#[derive(Subcommand, Debug)]
enum Commands {
    // ... existing
    #[command(subcommand)]
    Cert(CertCommands),
}

#[derive(Subcommand, Debug)]
enum CertCommands {
    List { #[arg(long)] status: Option<String> },
    Issue { #[arg(long)] host_code: String, #[arg(long)] domain: String, #[arg(long)] staging: bool },
    Upload { #[arg(long)] host_code: String, #[arg(long)] domain: String, #[arg(long)] cert: PathBuf, #[arg(long)] key: PathBuf },
    Renew { cert_id: String },
    Delete { cert_id: String },
    Show { cert_id: String },
    Reload { cert_id: String },
}

async fn run_cert_cmd(cmd: CertCommands, config: &AppConfig) -> Result<()> {
    // Connect DB, instantiate SslManager, dispatch
}
```

### UI changes

```tsx
// web/admin-panel/src/pages/certificates/index.tsx
+ <Button onClick={() => setRequestModalOpen(true)}>Request via ACME</Button>

// Modal component (new file)
// web/admin-panel/src/pages/certificates/RequestAcmeModal.tsx

// Row actions component
// web/admin-panel/src/pages/certificates/RowActions.tsx — Renew + Reload + Delete

// Expiry badge component
// web/admin-panel/src/pages/certificates/ExpiryBadge.tsx
```

## Related Code Files

### Create
- `crates/prx-waf/src/cli/cert_commands.rs` — CLI handler
- `web/admin-panel/src/pages/certificates/request-acme-modal.tsx`
- `web/admin-panel/src/pages/certificates/row-actions.tsx`
- `web/admin-panel/src/pages/certificates/expiry-badge.tsx`

### Modify
- `crates/prx-waf/src/main.rs` — register `Cert` subcommand
- `crates/waf-api/src/handlers.rs` — `GET /api/certificates/{id}/status` + extend list response
- `web/admin-panel/src/pages/certificates/index.tsx` — wire modal + actions

## Implementation Steps

1. Add `CertCommands` enum + `run_cert_cmd` dispatcher.
2. Implement CLI handlers: connect DB, instantiate SslManager (no-listener path), invoke methods.
3. Implement API `GET /api/certificates/{id}/status` with `days_until_expiry` computed.
4. Build `RequestAcmeModal` component — form + validation + submit + polling.
5. Build `RowActions` — Renew/Reload/Delete buttons với confirm dialog.
6. Build `ExpiryBadge` — color-coded by days remaining.
7. Wire vào main Certificates page.
8. Add toast notification.
9. Manual UI smoke test trên VM Singapore: issue staging cert qua UI button, see badge change.

## Success Criteria

- [ ] CLI 7 commands work: list, issue, upload, renew, delete, show, reload
- [ ] UI button "Request via ACME" trigger LE staging issue end-to-end
- [ ] UI badge color đúng theo days_until_expiry
- [ ] UI hiển thị last_error khi ACME fail
- [ ] `GET /api/certificates/{id}/status` JSON đúng schema
- [ ] CLI fail-fast khi config missing
- [ ] Frontend build clean, no warnings

## Risk Assessment

| Risk | Severity | Mitigation |
|---|---|---|
| CLI bypass API → 2 path same logic (drift) | Low | Share code qua SslManager methods; CLI/API là thin wrapper |
| UI long-polling overload server | Low | Poll 3s interval, max 60s; stop on terminal state |
| Form validation client/server drift | Low | Domain regex shared (export TS từ Rust qua schema if applicable; phase 05 chỉ dup const) |
| `prx-waf cert issue` lock domain conflict với background renewal | Low | Per-domain Mutex từ phase 03 cover cả 2 path |
| Toast notification missing trên slow network | Low | Optimistic UI update + error rollback |

## Verification gates

- `cargo build -p prx-waf` xanh
- `prx-waf cert list` work end-to-end
- `cd web/admin-panel && npm run build` clean
- Manual UI smoke

## References

- Existing UI: `web/admin-panel/src/pages/certificates/index.tsx`
- Existing API handlers: `crates/waf-api/src/handlers.rs:553-602`
- Existing CLI pattern: `Commands::Rules` trong main.rs
