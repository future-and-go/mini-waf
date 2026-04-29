# FR-003 Custom Rules — Samples

JSON samples for the **DB/API-driven custom rules engine**
(`crates/waf-engine/src/rules/engine.rs`).

> These are **not** loaded by the file-based YAML registry loader.
> They demonstrate the wire format for the `custom_rules` table and the admin
> API. Import via the admin UI or `POST /api/custom-rules`.
>
> For file-loaded equivalents (auto-loaded at startup with hot-reload), see the
> `fr003-sample-*.yaml` files in the parent directory `rules/custom/`. Those
> carry the `kind: custom_rule_v1` discriminator and live in-memory only.

| File | AC | Demonstrates |
|------|----|--------------|
| `sample-wildcard-admin.json` | AC-3 | `wildcard` operator, segment-bounded `*` |
| `sample-cookie-session.json` | AC-6 | `cookie`-by-name newtype field |
| `sample-nested-blacklist.json` | AC-8 | Nested `match_tree` with `and` / `or` / `not` |

Full schema reference: [`docs/custom-rules-syntax.md`](../../../docs/custom-rules-syntax.md).
