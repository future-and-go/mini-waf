# prx-waf Rules

Rule definitions for the prx-waf Web Application Firewall engine.
Rules are written in a simple YAML format and cover the full spectrum
of common web attacks — from OWASP CRS-derived detections to targeted
CVE virtual patches and custom application-level controls.

---

## Table of Contents

1. [Overview](#overview)
2. [Quick Start](#quick-start)
3. [Directory Layout](#directory-layout)
4. [Paranoia Levels](#paranoia-levels)
5. [Rule Format Specification](#rule-format-specification)
6. [Writing Custom Rules](#writing-custom-rules)
7. [Updating Rules](#updating-rules)
8. [Validation](#validation)
9. [Statistics](#statistics)
10. [Licensing](#licensing)
11. [Contributing](#contributing)

---

## Overview

prx-waf uses a declarative, YAML-based rule format. Each rule describes:

- **What to inspect** — request field (path, query, body, headers, …)
- **How to match** — operator (regex, contains, detect_sqli, …)
- **What to match** — pattern or value
- **What to do** — action (block, log, allow)

Rules are grouped into files by category and loaded by the WAF engine at
startup. The engine evaluates each incoming request against all enabled
rules in paranoia-level order.

---

## Quick Start

```bash
# Validate all rules before loading
python tools/validate.py rules/

# Sync OWASP CRS to latest release
python tools/sync.py --source owasp-crs --output rules/owasp-crs/ --tag v4.10.0

# Add a custom rule
cp rules/custom/example.yaml rules/custom/myapp.yaml
# Edit myapp.yaml, then validate
python tools/validate.py rules/custom/myapp.yaml
```

---

## Directory Layout

```
rules/
├── README.md                  ← You are here
├── sync-config.yaml           ← Upstream source configuration
│
├── owasp-crs/                 ← OWASP ModSecurity Core Rule Set (converted)
│   ├── README.md
│   ├── sqli.yaml              ← SQL injection (CRS 942xxx)
│   ├── xss.yaml               ← Cross-site scripting (CRS 941xxx)
│   ├── rce.yaml               ← Remote code execution (CRS 932xxx)
│   ├── lfi.yaml               ← Local file inclusion (CRS 930xxx)
│   ├── rfi.yaml               ← Remote file inclusion (CRS 931xxx)
│   ├── php-injection.yaml     ← PHP injection (CRS 933xxx)
│   ├── java-injection.yaml    ← Java/EL injection (CRS 944xxx)
│   ├── generic-attack.yaml    ← Node.js, SSI, HTTP splitting (CRS 934xxx)
│   ├── scanner-detection.yaml ← Security scanner UA detection (CRS 913xxx)
│   ├── protocol-enforcement.yaml  ← HTTP protocol compliance (CRS 920xxx)
│   ├── protocol-attack.yaml   ← Request smuggling, CRLF (CRS 921xxx)
│   ├── multipart-attack.yaml  ← Multipart bypass (CRS 922xxx)
│   ├── method-enforcement.yaml    ← HTTP method allowlist (CRS 911xxx)
│   ├── session-fixation.yaml  ← Session fixation (CRS 943xxx)
│   ├── web-shells.yaml        ← Web shell detection (CRS 955xxx)
│   ├── response-*.yaml        ← Response inspection (CRS 950-956xxx)
│   └── data/                  ← Phrase-match wordlists (.data files)
│       ├── scanners-user-agents.data
│       ├── lfi-os-files.data
│       ├── sql-errors.data
│       └── ...                ← 20+ wordlist files
│
├── modsecurity/               ← ModSecurity community-inspired rules
│   ├── README.md
│   ├── ip-reputation.yaml     ← Bot/scanner/proxy detection
│   ├── dos-protection.yaml    ← DoS and abnormal request detection
│   ├── data-leakage.yaml      ← PII and credential leak detection
│   └── response-checks.yaml   ← Response inspection
│
├── cve-patches/               ← Targeted CVE virtual patches
│   ├── README.md
│   ├── 2021-log4shell.yaml    ← CVE-2021-44228, CVE-2021-45046
│   ├── 2022-spring4shell.yaml ← CVE-2022-22965, CVE-2022-22963
│   ├── 2022-text4shell.yaml   ← CVE-2022-42889
│   ├── 2023-moveit.yaml       ← CVE-2023-34362, CVE-2023-36934
│   ├── 2024-xz-backdoor.yaml  ← CVE-2024-3094
│   ├── 2024-recent.yaml       ← 2024 high-profile CVEs
│   └── 2025-recent.yaml       ← 2025 high-profile CVEs
│
├── advanced/                  ← Advanced attack detection
│   ├── README.md
│   ├── ssrf.yaml              ← Server-Side Request Forgery
│   ├── xxe.yaml               ← XML External Entity injection
│   ├── ssti.yaml              ← Server-Side Template Injection
│   ├── deserialization.yaml   ← Insecure deserialization
│   ├── prototype-pollution.yaml ← JavaScript prototype pollution
│   └── webshell-upload.yaml   ← Webshell upload attempts
│
├── bot-detection/             ← Bot and crawler detection
│   ├── README.md
│   ├── crawlers.yaml          ← Known web crawlers and scrapers
│   ├── scraping.yaml          ← Automated scraping behavior
│   └── credential-stuffing.yaml ← Credential stuffing detection
│
├── geoip/                     ← Geographic IP blocking rules
│   ├── README.md
│   └── country-blocklist.yaml ← Block requests by country code
│
├── owasp-api/                 ← OWASP API Security Top 10 rules
│   ├── README.md
│   ├── broken-auth.yaml       ← API1: Broken Object Level Authorization
│   ├── data-exposure.yaml     ← API3: Excessive Data Exposure
│   ├── injection.yaml         ← API8: Injection
│   ├── mass-assignment.yaml   ← API6: Mass Assignment
│   └── rate-abuse.yaml        ← API4: Lack of Resources & Rate Limiting
│
├── custom/                    ← Site-specific / application rules
│   ├── README.md
│   └── example.yaml           ← Annotated example rules
│
└── tools/                     ← Maintenance utilities
    ├── modsec2yaml.py         ← Convert ModSecurity .conf → prx-waf YAML
    ├── sync.py                ← Sync rules from upstream sources
    ├── validate.py            ← Validate YAML rule files
    └── requirements.txt       ← Python dependencies
```

---

## Paranoia Levels

Each rule declares a `paranoia` level (1–4) indicating how aggressively
it matches. Higher paranoia levels catch more attacks but increase the
risk of false positives (blocking legitimate traffic).

| Level | Name        | Description                                                   | False Positive Risk |
|-------|-------------|---------------------------------------------------------------|---------------------|
| 1     | Default     | High-confidence rules, production-safe for most applications  | Very low            |
| 2     | Recommended | Broader coverage, minor FP risk on unusual (but valid) input  | Low                 |
| 3     | Aggressive  | Extensive heuristics; requires tuning for your application    | Moderate            |
| 4     | Maximum     | Everything, including speculative patterns; research/lab use  | High                |

**Recommended approach:**
1. Start with paranoia level 1 in production.
2. Monitor logs for false positives.
3. Once stable, enable level 2 rules.
4. Only enable levels 3/4 in environments where you can tune exclusions.

The WAF engine loads rules up to and including the configured paranoia
level. Rules without a `paranoia` field default to level 1.

---

## Rule Format Specification

Every rule file is a YAML document with this top-level structure:

```yaml
version: "1.0"                          # Schema version (string, required)
description: "Short description"        # Human-readable label (string, required)
source: "OWASP CRS v4.25.0"            # Origin of the rules (string, optional)
license: "Apache-2.0"                   # SPDX license identifier (string, optional)

rules:
  - <rule>
  - <rule>
  ...
```

### Rule Schema

```yaml
- id: "CRS-942100"              # Unique string ID across ALL rule files (REQUIRED)
                                # Format: <PREFIX>-<CATEGORY>-<NNN> or <PREFIX>-<NNN>
                                # Examples: CRS-942100, MODSEC-IP-001, CVE-2021-LOG4J-001,
                                #           CUSTOM-API-001

  name: "Rule description"      # Short human-readable name (REQUIRED)
                                # Max ~120 chars; describe what the rule detects.

  category: "sqli"              # Category tag (REQUIRED)
                                # Free-form string; used for filtering and reporting.
                                # Common values: sqli, xss, rce, lfi, rfi, php-injection,
                                # java-injection, scanner, protocol, session-fixation,
                                # data-leakage, dos, access-control, custom

  severity: "critical"          # Severity level (REQUIRED)
                                # One of: critical | high | medium | low | info | notice |
                                #         warning | error | unknown

  paranoia: 1                   # Paranoia level 1-4 (integer, OPTIONAL, default: 1)
                                # Controls how eagerly the rule is activated.

  field: "all"                  # Which part of the request to inspect (REQUIRED)
                                # See Field Reference below.

  operator: "regex"             # How to match the value (REQUIRED)
                                # See Operator Reference below.

  value: "(?i)select.+from"     # Pattern or threshold to match against (REQUIRED)
                                # For regex: a PCRE-compatible regular expression.
                                # For numeric operators: a number string.
                                # For detect_sqli / detect_xss: "true" or "".
                                # For pm_from_file: filename in owasp-crs/data/.

  action: "block"               # What to do when the rule matches (REQUIRED)
                                # One of: block | log | allow | deny | redirect | drop
                                # Most rules use block (active protection) or
                                # log (monitoring / tuning mode).

  tags:                         # List of string tags (OPTIONAL)
    - "owasp-crs"               # Used for filtering, reporting, and WAF dashboards.
    - "sqli"
    - "attack-sqli"

  crs_id: 942100                # Original CRS numeric ID (integer, OPTIONAL)
                                # Only present on CRS-converted rules.

  reference: "https://..."      # Link to CVE, OWASP article, or rule rationale (OPTIONAL)
```

### Field Reference

| Field              | Inspects                                           |
|--------------------|----------------------------------------------------|
| `path`             | Request URI path (without query string)            |
| `query`            | Query string (all parameters, decoded)             |
| `body`             | Request body (decoded)                             |
| `headers`          | All request headers (name: value pairs)            |
| `user_agent`       | User-Agent header only                             |
| `cookies`          | Request cookies                                    |
| `method`           | HTTP method (GET, POST, PUT, …)                    |
| `content_type`     | Content-Type header                                |
| `content_length`   | Content-Length value (numeric comparison)          |
| `path_length`      | Length of the URI path (numeric comparison)        |
| `query_arg_count`  | Number of query parameters (numeric comparison)    |
| `all`              | All of the above fields combined                   |

### Operator Reference

| Operator        | Description                                                         |
|-----------------|---------------------------------------------------------------------|
| `regex`         | Match field against a PCRE-compatible regular expression            |
| `contains`      | Field contains the literal string in `value`                        |
| `not_in`        | Field value is NOT in the comma-separated list in `value`           |
| `gt`            | Field value (numeric) is greater than `value`                       |
| `lt`            | Field value (numeric) is less than `value`                          |
| `ge`            | Field value (numeric) is greater than or equal to `value`           |
| `le`            | Field value (numeric) is less than or equal to `value`              |
| `equals`        | Field value exactly equals `value` (case-sensitive)                 |
| `detect_sqli`   | SQL injection detection via libinjection (value: `"true"` or `""`)  |
| `detect_xss`    | XSS detection via libinjection (value: `"true"` or `""`)            |
| `pm_from_file`  | Phrase-match against a wordlist file in `owasp-crs/data/`           |
| `pm`            | Phrase-match against an inline list (value: comma-separated)        |

### Action Reference

| Action     | Description                                              |
|------------|----------------------------------------------------------|
| `block`    | Reject the request with a 403 Forbidden response         |
| `log`      | Allow the request but log the match (monitoring mode)    |
| `allow`    | Explicitly allow the request (overrides other rules)     |
| `deny`     | Alias for `block`                                        |
| `redirect` | Redirect the request (engine-specific configuration)     |
| `drop`     | Silently drop the connection                             |

---

## Writing Custom Rules

1. **Create a new YAML file** in `rules/custom/`:
   ```bash
   cp rules/custom/example.yaml rules/custom/myapp.yaml
   ```

2. **Choose unique IDs** using the `CUSTOM-` prefix:
   ```
   CUSTOM-API-001
   CUSTOM-APP-001
   CUSTOM-BOT-001
   ```

3. **Write your rule** following the schema above. See `rules/custom/example.yaml`
   for fully annotated working examples.

4. **Validate** before deploying:
   ```bash
   python tools/validate.py rules/custom/myapp.yaml
   ```

### Example: Block a Specific Path

```yaml
version: "1.0"
description: "Myapp custom rules"
rules:
  - id: "CUSTOM-APP-001"
    name: "Block Access to Internal Admin API"
    category: "access-control"
    severity: "high"
    paranoia: 1
    field: "path"
    operator: "regex"
    value: "(?i)^/internal/"
    action: "block"
    tags: ["custom", "access-control"]
```

### Example: Log Suspicious User-Agent

```yaml
  - id: "CUSTOM-BOT-001"
    name: "Log Suspicious Automated Tool User-Agents"
    category: "scanner"
    severity: "medium"
    paranoia: 2
    field: "user_agent"
    operator: "regex"
    value: "(?i)(masscan|zgrab|python-requests/|go-http-client)"
    action: "log"
    tags: ["custom", "bot", "scanner"]
```

### Tips for Good Rules

- **Start with `action: log`** — monitor before blocking to avoid false positives.
- **Be specific with anchors** — use `^` and `$` in regexes to prevent partial matches.
- **Use non-capturing groups** — `(?:...)` instead of `(...)` for clarity.
- **Add comments** — YAML comments (`#`) are your future self's best friend.
- **Test your regex** — use `python3 -c "import re; re.compile('your_pattern')"`.
- **Set an appropriate paranoia level** — if a rule might match legitimate traffic,
  set paranoia to 2 or 3 rather than blocking at paranoia 1.

---

## Updating Rules

Rules are synced from upstream sources using `tools/sync.py`.

### Install dependencies

```bash
pip install -r tools/requirements.txt
```

### Check for updates

```bash
python tools/sync.py --check
```

### Sync OWASP CRS to a specific release tag

```bash
python tools/sync.py \
  --source owasp-crs \
  --output rules/owasp-crs/ \
  --tag v4.10.0
```

### Sync to the latest main branch

```bash
python tools/sync.py \
  --source owasp-crs \
  --output rules/owasp-crs/
```

### Preview changes without writing files

```bash
python tools/sync.py \
  --source owasp-crs \
  --output rules/owasp-crs/ \
  --dry-run
```

### Configuration

`sync-config.yaml` (in this directory) defines upstream sources and defaults.
You can override any config value via CLI flags. Supported flags:

| Flag          | Description                                  |
|---------------|----------------------------------------------|
| `--source`    | Source name (e.g. `owasp-crs`)               |
| `--output`    | Output directory                             |
| `--tag`       | Git tag to checkout (e.g. `v4.10.0`)         |
| `--branch`    | Git branch (default: `main`)                 |
| `--dry-run`   | Preview changes without writing              |
| `--check`     | Only report if updates are available         |
| `--config`    | Path to alternate config file                |
| `--temp-dir`  | Temp directory for cloning (default: `/tmp/prx-waf-sync/`) |

---

## Validation

Run `tools/validate.py` to check rule files for correctness before deploying.

### Validate all rule directories

```bash
python tools/validate.py rules/
```

### Validate a specific directory

```bash
python tools/validate.py rules/custom/
python tools/validate.py rules/owasp-crs/
python tools/validate.py rules/cve-patches/
```

### Validate a single file

```bash
python tools/validate.py rules/custom/myapp.yaml
```

### What the validator checks

- Required fields are present (`id`, `name`, `severity`, `field`, `operator`, `value`, `action`)
- No duplicate rule IDs across all loaded files
- Severity values are valid
- Paranoia levels are in range 1–4
- Action values are recognized
- Regexes compile correctly (PCRE-only patterns are flagged as warnings)
- Numeric operators are not used with string values

### Sample output

```
======================================================================
  prx-waf YAML Rule Validator
======================================================================

  ✓ owasp-crs/sqli.yaml                    87 rules
  ✓ owasp-crs/xss.yaml                     41 rules
  ✓ custom/myapp.yaml                       3 rules

----------------------------------------------------------------------
  Files:    3
  Rules:    131
  Errors:   0
  Warnings: 0
----------------------------------------------------------------------
  ✓ All files valid!
```

---

## Statistics

Current rule inventory (as of the last sync):

| Source       | Files | Rules | Description                        |
|--------------|-------|-------|------------------------------------|
| OWASP CRS    | 24    | 274   | OWASP ModSecurity Core Rule Set v4 |
| ModSecurity  | 4     | 46    | ModSecurity community rules        |
| CVE Patches  | 7     | 43    | Targeted CVE virtual patches       |
| Advanced     | 6     | 77    | SSRF, XXE, SSTI, deserialization, prototype pollution, webshell upload |
| Bot Detection| 3     | 42    | Crawlers, scraping, credential stuffing |
| GeoIP        | 1     | 2     | Geographic IP blocking             |
| OWASP API    | 5     | 64    | OWASP API Security Top 10          |
| Custom       | 1     | 8     | Example / template rules           |
| **Total**    | **51**| **556**| |

---

## Licensing

| Component              | License      | Copyright                          |
|------------------------|--------------|------------------------------------|
| OWASP CRS rules        | Apache-2.0   | OWASP CRS project contributors     |
| ModSecurity rules      | Apache-2.0   | prx-waf project                    |
| CVE patch rules        | Apache-2.0   | prx-waf project                    |
| Custom example rules   | Apache-2.0   | prx-waf project                    |
| Tooling (tools/*.py)   | Apache-2.0   | prx-waf project                    |

OWASP CRS is distributed under the Apache License, Version 2.0.
See: https://github.com/coreruleset/coreruleset/blob/main/LICENSE

prx-waf rules and tooling are distributed under the Apache License,
Version 2.0. See the LICENSE file in the repository root.

---

## Contributing

Contributions are welcome. Please follow these guidelines:

### Adding or modifying rules

1. **Pick the right directory:**
   - `owasp-crs/` — do not edit directly; re-run `sync.py` to regenerate.
   - `modsecurity/` — hand-crafted rules for threat categories not in CRS.
   - `cve-patches/` — one file per CVE year-group; add new CVEs to the current year file.
   - `custom/` — application-specific overrides.

2. **Use the correct ID namespace:**

   | Directory      | ID Prefix                        |
   |----------------|----------------------------------|
   | `owasp-crs/`   | `CRS-<crs_number>`               |
   | `modsecurity/` | `MODSEC-<CATEGORY>-<NNN>`        |
   | `cve-patches/` | `CVE-<YEAR>-<SHORT>-<NNN>`       |
   | `custom/`      | `CUSTOM-<CATEGORY>-<NNN>`        |

3. **Validate before submitting:**
   ```bash
   python tools/validate.py rules/
   ```

4. **Do not introduce false positives** — test new rules against real traffic
   logs with `action: log` before switching to `action: block`.

5. **Document your rule** — use inline YAML comments (`#`) to explain
   the threat, the pattern rationale, and any known limitations.

6. **Reference sources** — include a `reference:` URL linking to the
   relevant CVE, OWASP article, or research paper.

### Submitting changes

- Open a pull request with a clear description of what the rule detects.
- Include before/after output from `validate.py`.
- For CVE patches, include a link to the NVD entry.

### Reporting false positives

If a rule incorrectly blocks legitimate traffic:
1. Identify the rule ID from the WAF log.
2. Open an issue with the rule ID, the blocked request (sanitized), and the
   application context.
3. Consider raising the rule's `paranoia` level as an interim mitigation
   while a fix is prepared.
