# Custom Rules

This directory is for your site-specific WAF rules.

## When to Write Custom Rules

- Application-specific paths and endpoints
- Business logic protection
- Proprietary API formats
- Tenant-specific blocklists

## Rule Schema

```yaml
version: "1.0"
description: "Short description of the ruleset"
rules:
  - id: "CUSTOM-CATEGORY-NNN"   # Unique string ID (REQUIRED)
    name: "Human readable description"  # Short name (REQUIRED)
    category: "your-category"   # Free-form category tag (REQUIRED)
    severity: "critical"        # critical | high | medium | low (REQUIRED)
    paranoia: 1                 # 1-4 paranoia level (optional, default 1)
    field: "all"                # See Field reference below (REQUIRED)
    operator: "regex"           # See Operator reference below (REQUIRED)
    value: "pattern"            # Pattern or value (REQUIRED)
    action: "block"             # block | log | pass (REQUIRED)
    tags: ["custom", "tag"]     # Optional string array
    reference: "https://..."    # Optional CVE/reference URL
```

## Field Reference

| Field | Description |
|-------|-------------|
| `path` | Request URI path |
| `query` | Query string arguments |
| `body` | Request body |
| `headers` | All request headers |
| `user_agent` | User-Agent header only |
| `cookies` | Request cookies |
| `method` | HTTP method |
| `content_type` | Content-Type header |
| `content_length` | Content-Length value (numeric) |
| `path_length` | URI path length (numeric) |
| `query_arg_count` | Number of query parameters (numeric) |
| `all` | All of the above |

## Operator Reference

| Operator | Description |
|----------|-------------|
| `regex` | Match against regular expression |
| `contains` | String contains value |
| `not_in` | Value not in list |
| `gt` | Greater than (numeric) |
| `lt` | Less than (numeric) |
| `detect_sqli` | SQL injection detection via libinjection |
| `detect_xss` | XSS detection via libinjection |
| `pm_from_file` | Phrase match from external list file |
| `pm` | Phrase match from inline value |

## Naming Convention

Use the `CUSTOM-` prefix for all custom rule IDs to avoid conflicts with
built-in rule sets:

```
CUSTOM-<CATEGORY>-<NNN>

Examples:
  CUSTOM-API-001
  CUSTOM-APP-001
  CUSTOM-BOT-001
```

## Paranoia Levels

| Level | Meaning |
|-------|---------|
| 1 | Default – high confidence, low false positive rate |
| 2 | Moderate – increased protection, minor false positive risk |
| 3 | High – aggressive detection, requires tuning |
| 4 | Maximum – extreme detection, expect false positives |

## Validation

Run before deploying:

```bash
python tools/validate.py rules/custom/
```

## Example

See [example.yaml](example.yaml) for a complete working example.

## License

Custom rules you write are yours. The example rules in this directory
are provided under Apache License 2.0.
