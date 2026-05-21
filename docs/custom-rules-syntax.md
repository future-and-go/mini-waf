# Custom Rules Engine — Schema Reference (FR-003)

Schema for the **DB/API-driven custom rules engine** in
`crates/waf-engine/src/rules/engine.rs`. These rules are evaluated per-request
against `RequestCtx` and stored as rows in PostgreSQL (`custom_rules` table).

> Distinct from the file-based YAML rules under `rules/*` (registry / OWASP CRS
> format). For that format, see [`../rules/README.md`](../rules/README.md).

---

## Wire Format

A rule is a JSON object (DB column `conditions` is `jsonb`):

```json
{
  "id": "uuid",
  "host_code": "myapp",
  "name": "Block bad sessions on admin",
  "priority": 100,
  "enabled": true,
  "condition_op": "and",
  "conditions": [],
  "match_tree": { "and": [ /* … */ ] },
  "action": "block",
  "action_status": 403,
  "action_msg": null,
  "script": null,
  "risk_delta": null,
  "risk_action": null
}
```

| Field           | Type            | Notes |
|-----------------|-----------------|-------|
| `host_code`     | string          | Per-host scope; `*` for global |
| `priority`      | int             | Lower wins (sorted ascending) |
| `condition_op`  | `and`\|`or`     | Used only for legacy flat `conditions` |
| `conditions`    | `Condition[]`   | Legacy flat shape (still supported) |
| `match_tree`    | `ConditionNode` | **New (FR-003).** Takes precedence when present |
| `action`        | `block`\|`allow`\|`log`\|`challenge` | |
| `action_status` | int             | HTTP status code returned on block (default `403`) |
| `action_msg`    | string?         | Custom response body / message |
| `script`        | string?         | Rhai expression — overrides `conditions`/`match_tree` when set |
| `risk_delta`    | int?            | FR-025: risk score contribution when rule matches (typically 1–100) |
| `risk_action`   | string?         | FR-025: `"block"` forces immediate block via risk override |

---

## Condition Leaf

```json
{ "field": "<field>", "operator": "<op>", "value": "<v>" }
```

### Fields

| Field             | Source |
|-------------------|--------|
| `ip`              | `ctx.client_ip` |
| `path`            | URI path |
| `query`           | Query string |
| `method`          | HTTP method |
| `body`            | UTF-8 lossy of `body_preview` |
| `host`            | Host header |
| `user_agent`      | `User-Agent` header |
| `content_type`    | `Content-Type` header |
| `content_length`  | numeric |
| `header`          | **Newtype:** `{"header":"x-foo"}` — names lowercased |
| `cookie`          | Bare `"cookie"` → full `Cookie:` header (legacy). Newtype `{"cookie":"session"}` → single cookie value by name (FR-003 AC-6). Names case-sensitive (RFC 6265). `{"cookie":null}` is explicit legacy form. |
| `geo_country`, `geo_iso`, `geo_province`, `geo_city`, `geo_isp` | populated when GeoIP enabled |

### Operators

| Operator       | Value type | Notes |
|----------------|-----------|-------|
| `eq` / `ne`    | string    | Case-insensitive (ASCII) |
| `contains` / `not_contains` | string | Case-sensitive substring |
| `starts_with` / `ends_with` | string | |
| `regex`        | string    | Rust `regex` crate; compile failure → rule skipped + warn log |
| `wildcard`     | string    | **(FR-003 AC-3)** Glob via `globset`; see below |
| `in_list` / `not_in_list` | string[] | Pre-compiled to `AHashSet` (de-duped) |
| `cidr_match`   | string    | `IpNet` parse; matches `ctx.client_ip` |
| `gt` / `lt` / `gte` / `lte` | int | Field parsed as `i64` |

#### Specialised Operators (Registry / OWASP Compatibility)

These operators exist for registry-format YAML compatibility. They bypass the
condition matcher and run their own multi-field scan with URL-decode protection.

| Operator        | Purpose |
|-----------------|---------|
| `pm_from_file`  | Pattern matching from external phrase file |
| `detect_sqli`   | SQL injection detection via libinjection |
| `detect_xss`    | XSS detection via libinjection |
| `contains_any`  | Substring matching against multiple values |

**Constraints:** Specialised operators cannot be used inside `match_tree` nodes —
they are dispatched via `specialised_op` at the rule level. Attempting to compile
one into a condition tree produces a warn log and the rule is skipped.

### Wildcard / Glob Semantics

- `*` matches one path segment — does **not** cross `/` (`literal_separator(true)`).
- `**` matches across separators.
- Bare `**` is **rejected** at compile time (matches everything — footgun).
- Empty pattern is **rejected**.

Examples:

| Pattern             | Matches              | Misses                     |
|---------------------|----------------------|----------------------------|
| `/api/*/admin`      | `/api/v1/admin`      | `/api/v1/v2/admin`, `/api/admin` |
| `/static/**`        | `/static/a/b.css`    | `/public/a.css`            |
| `*.php`             | `index.php`          | `path/index.php`           |

---

## Nested AND/OR/Not Tree (FR-003 AC-8)

Replace the flat `conditions[]` with `match_tree` for arbitrary boolean logic.
Wire format uses **key-presence disambiguation**:

```jsonc
// And branch
{ "and": [ <node>, <node>, ... ] }

// Or branch
{ "or":  [ <node>, <node>, ... ] }

// Not branch (single child)
{ "not": <node> }

// Leaf (bare condition)
{ "field": "...", "operator": "...", "value": "..." }
```

### Limits (defensive caps — see `engine.rs`)

- `MAX_TREE_DEPTH = 16`
- `MAX_TREE_LEAVES = 256`
- Trees exceeding either are **rejected at compile**; rule skipped with warn log.

### Example: `(ip in CIDR OR cookie session=bad) AND path matches /api/*/admin`

```json
{
  "match_tree": {
    "and": [
      { "or": [
        { "field": "ip", "operator": "cidr_match", "value": "10.0.0.0/8" },
        { "field": {"cookie": "session"}, "operator": "eq", "value": "bad" }
      ]},
      { "field": "path", "operator": "wildcard", "value": "/api/*/admin" }
    ]
  }
}
```

---

## Eval Order

### Priority & Scope

Rules are sorted **ascending** by `priority` (lower number = evaluated first).
Default priority: `100` via API, `0` via YAML files.

1. **Host-specific rules** are evaluated first (sorted by priority within the host bucket).
2. **Global rules** (`host_code: "*"`) are evaluated second (also sorted by priority).
3. Host-specific rules **always** take precedence over global rules regardless of
   priority value — priority only determines order *within* each group.

### Per-Rule Evaluation Hierarchy

For each rule (priority ascending):

1. If `specialised_op` is set → dispatch to specialised check (multi-field URL-decode scan).
2. If `script` is set → evaluate Rhai expression (legacy escape hatch).
3. Else if pre-compiled `match_tree` present → evaluate `CompiledNode` (preferred fast path).
4. Else if `conditions` is non-empty → legacy flat eval with `condition_op`.
5. Else if `pattern` is set → regex match against `pattern_field` (registry fallback).

### Match Semantics

- **First blocking detection** is saved as the `DetectionResult` (rule id/name/action).
- **All matching rules** contribute `risk_delta` to the cumulative `RuleVerdict`
  (FR-025 risk scoring). A priority-200 rule still contributes its delta even if
  a priority-10 rule already matched.
- Rules targeting `response_body` are **skipped** during request-phase evaluation;
  they run separately in the response phase.

## Risk Scoring (FR-025)

Custom rules integrate with the cumulative risk scoring system. When a rule
matches, it can contribute a risk score delta instead of (or in addition to)
a blocking action.

| Field         | Type   | Default | Notes |
|---------------|--------|---------|-------|
| `risk_delta`  | i16?   | `null`  | Points added to cumulative risk score (typically 1–100) |
| `risk_action` | string? | `null` | `"block"` sets `override_block = true`, forcing immediate block |

**How it works:**

1. Engine evaluates **all** matching rules (not just the first).
2. Each match with a `risk_delta` pushes a `RiskDelta { rule_id, delta }` into the verdict.
3. If any match has `risk_action: "block"`, the verdict's `override_block` flag is set.
4. The risk scorer aggregates deltas to determine the final action.

**Example:** A `log` rule with `risk_delta: 20` won't block on its own, but
three such rules matching the same request accumulate 60 risk points, which
may trigger the scorer's threshold.

> **Note:** `risk_delta` and `risk_action` are stored in the database schema
> but are not yet exposed in the `CreateCustomRule` / `UpdateCustomRule` API
> request types. They can be set via direct DB manipulation or YAML file loading.

---

## Rhai Scripts

Rules with `script` set evaluate a Rhai expression instead of `conditions`
or `match_tree`. Scripts must return `bool`; errors are logged and treated as
`false` (fail-safe).

### Available Variables

| Variable         | Type   | Source |
|------------------|--------|--------|
| `ip`             | string | `ctx.client_ip` |
| `path`           | string | URI path |
| `method`         | string | HTTP method |
| `query`          | string | Query string |
| `host`           | string | Host header |
| `user_agent`     | string | `User-Agent` header |
| `referer`        | string | `Referer` header |
| `content_type`   | string | `Content-Type` header |
| `content_length` | int    | Content length (i64) |
| `cookie`         | string | Full `Cookie:` header |

### Sandbox Limits

| Limit              | Value   |
|--------------------|---------|
| Max operations     | 100,000 |
| Max call levels    | 16      |
| Max expr depths    | 64 / 32 |

Scripts exceeding these limits fail silently (warn log).

### Example

```json
{
  "script": "path.contains(\"/admin\") && ip.starts_with(\"192.168.\")"
}
```

---

## Response Body Evaluation

Rules targeting `response_body` are evaluated **separately** in the response
phase via `check_response_body(host_code, body_text)`. They are skipped during
request-phase evaluation.

**Current support:**
- Only pre-compiled `pattern` regex against `pattern_field: "response_body"`
- Condition trees, Rhai scripts, and specialised operators are **not yet wired**
  for response phase (Phase 2)

**Evaluation order:** Host-specific response-body rules first, then global (`"*"`).
First match returns a `DetectionResult`.

---

## Compilation & Hot-Reload

- All matchers are pre-compiled at insert time (regex, glob, CIDR, list sets).
- Compile failures **skip the rule** and emit `warn!(rule_id, error)` — they do
  not abort the load.
- `from_db_rule()` auto-detects the `conditions` JSON shape:
  - Object with `match_tree` key → tree mode.
  - Anything else → legacy `Vec<Condition>` (back-compat, no migration needed).

## Migration Notes

- **No DB migration required.** Existing flat-array rules continue to evaluate
  unchanged; they are wrapped as `And([Leaf,...])` (or `Or` per `condition_op`)
  inside the compiled tree.
- New rules opting into nested logic write `{"match_tree": ...}` to the
  `conditions` column.
- Cookie rules using bare `"field": "cookie"` keep whole-header semantics; switch
  to `{"cookie":"name"}` to match a single cookie value.

## File-Based Loading

In addition to DB/API-driven rules, the engine loads `CustomRule`s from YAML
files in `rules/custom/*.yaml` at startup and watches the directory for
hot-reload. See `crates/waf-engine/src/rules/custom_file_loader.rs`.

### Discriminator

Each YAML document MUST carry the top-level key `kind: custom_rule_v1`.
Documents without `kind` are skipped silently — this lets registry-format
YAML (e.g. `example.yaml`) coexist in the same directory. A `kind:` value
starting with `custom_rule_` but not equal to `custom_rule_v1` is rejected
(forward-compat guard).

### Wire Format

```yaml
kind: custom_rule_v1            # REQUIRED discriminator
id: my-rule-001                 # REQUIRED unique id
host_code: "*"                  # default "*" (global)
name: "Block wildcard admin paths"
priority: 100                   # default 0
enabled: true                   # default true
condition_op: and               # default and; used only when match_tree absent
conditions: []                  # legacy flat shape (still supported)
match_tree:                     # nested form (preferred); takes precedence
  and:
    - { field: "ip", operator: "cidr_match", value: "10.0.0.0/8" }
    - { field: "path", operator: "wildcard", value: "/api/*/admin" }
action: block                   # default block
action_status: 403              # default 403
action_msg: "Forbidden"
script: null                    # optional Rhai expression
risk_delta: null                # FR-025: risk score contribution (i16)
risk_action: null               # FR-025: "block" for override
```

A file may contain a single document or a multi-document YAML stream
(`---` separators). Both are supported.

### Defaults

| Field           | Default      |
|-----------------|--------------|
| `host_code`     | `"*"`        |
| `priority`      | `0`          |
| `enabled`       | `true`       |
| `condition_op`  | `and`        |
| `action`        | `block`      |
| `action_status` | `403`        |
| `risk_delta`    | `null`       |
| `risk_action`   | `null`       |

### Hot-Reload

The watcher debounces filesystem events for 500ms then atomically clears
all file-loaded rules and re-parses every `*.yaml` in `rules/custom/`.
DB-loaded rules are not touched. Subdirectories (e.g.
`rules/custom/fr003-samples/`) are NOT scanned, so they are safe for
JSON or other reference material.

### Conflict Semantics

File rules and DB rules coexist; both are evaluated and ordered by
`priority` (lower wins). On startup, file load runs after DB load on
`reload_rules`, so a file rule with the same `id` as a DB rule is added
as an additional entry — operators should avoid duplicating ids across
sources. File rules are read-only on disk and not editable through the
admin UI.

### Failure Mode

A malformed file produces a single `warn!` log line and is skipped; other
files continue to load. The service does not crash on bad YAML.

## Samples

- File-loaded YAML: [`../rules/custom/fr003-sample-*.yaml`](../rules/custom/)
  (loaded automatically at startup).
- API/DB import JSON: [`../rules/custom/fr003-samples/`](../rules/custom/fr003-samples/)
  (import via admin UI or `POST /api/custom-rules`).
