**Task**: Fix two production bugs in `crates/waf-api/src/handlers.rs` and `crates/waf-api/src/server.rs`.

**Bug 1 — Missing PATCH endpoint for sensitive-patterns toggle:**
The new admin panel (`web/admin-panel/src/pages/sensitive-patterns/index.tsx`) calls `PATCH /api/sensitive-patterns/{id}` with body `{ enabled: bool }` to toggle a pattern, and also `PATCH /api/sensitive-patterns/{id}` with full form body to update a pattern. The backend only has `DELETE /api/sensitive-patterns/{id}` — no PATCH.

Add to `crates/waf-api/src/server.rs`:
```rust
.route("/api/sensitive-patterns/{id}", delete(delete_sensitive_pattern).patch(patch_sensitive_pattern))
```

Add to `crates/waf-api/src/handlers.rs` the `patch_sensitive_pattern` handler:
- Accept `Json<serde_json::Value>` body
- If body contains only `{ "enabled": bool }` → toggle enabled field in DB via `state.db.toggle_sensitive_pattern(id, enabled).await`
- Otherwise → full update via `state.db.update_sensitive_pattern(id, ...)` (add these DB methods if missing)
- Return `{ "success": true, "data": { "id": id } }`
- Broadcast DB event on success

Add to `crates/waf-storage/src/repo.rs`:
```rust
pub async fn toggle_sensitive_pattern(&self, id: uuid::Uuid, enabled: bool) -> Result<bool, StorageError>
pub async fn update_sensitive_pattern(&self, id: uuid::Uuid, pattern: Option<&str>, pattern_type: Option<&str>, ...) -> Result<Option<SensitivePattern>, StorageError>
```

**Bug 2 — Plugins response shape mismatch:**
`GET /api/plugins` in `crates/waf-api/src/plugins.rs` returns `{ "plugins": [...] }`. The new `PluginsPage` expects `{ "data": [...] }` or a raw array. 

Fix the `list_plugins` handler to return:
```json
{ "success": true, "data": [...], "total": N }
```
where each plugin item includes: `id, name, version, author, description, enabled, file_size, created_at, load_error`.

**Bug 3 — Tunnels response shape mismatch:**
`GET /api/tunnels` returns `{ "tunnels": [...] }`. The new `TunnelsPage` expects `{ "data": [...] }` (or raw array). Also, the `CreateTunnel` DB model has no `protocol` field but the FE sends it.

Fix `list_tunnels` in `crates/waf-api/src/tunnels.rs` to return `{ "success": true, "data": [...], "total": N }`.

Add `protocol` field (VARCHAR 3, default 'tcp') to the tunnels table migration:
```sql
ALTER TABLE tunnels ADD COLUMN IF NOT EXISTS protocol VARCHAR(3) NOT NULL DEFAULT 'tcp';
```
Add `protocol: Option<String>` to `CreateTunnel` struct in `crates/waf-storage/src/models.rs`.
Update `create_tunnel` handler to accept and persist the `protocol` field from the request body.
Update `list_tunnels` response to include `protocol`.

**Acceptance:**
- `PATCH /api/sensitive-patterns/{uuid}` with `{"enabled":false}` returns 200
- `GET /api/plugins` returns `{"success":true,"data":[...],"total":N}`
- `GET /api/tunnels` returns `{"success":true,"data":[...],"total":N}` with `protocol` field
- `cargo check --workspace` passes