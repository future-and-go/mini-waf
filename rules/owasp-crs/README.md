# OWASP Core Rule Set (CRS)

Converted from OWASP CRS v4.25.0-dev.

Source: https://github.com/coreruleset/coreruleset
License: Apache License 2.0
Converted: 2025

## Rule Files

| File | CRS Range | Category | Description |
|------|-----------|----------|-------------|
| `method-enforcement.yaml` | 911xxx | Protocol | HTTP method allowlist |
| `scanner-detection.yaml` | 913xxx | Scanner | Security scanner UA detection |
| `protocol-enforcement.yaml` | 920xxx | Protocol | HTTP protocol compliance |
| `protocol-attack.yaml` | 921xxx | Protocol | HTTP request smuggling, CRLF |
| `multipart-attack.yaml` | 922xxx | Protocol | Multipart boundary attacks |
| `lfi.yaml` | 930xxx | LFI | Local file inclusion / path traversal |
| `rfi.yaml` | 931xxx | RFI | Remote file inclusion |
| `rce.yaml` | 932xxx | RCE | Remote code execution (shell) |
| `php-injection.yaml` | 933xxx | PHP | PHP injection attacks |
| `generic-attack.yaml` | 934xxx | Generic | Node.js, SSI, HTTP splitting |
| `xss.yaml` | 941xxx | XSS | Cross-site scripting |
| `sqli.yaml` | 942xxx | SQLi | SQL injection |
| `session-fixation.yaml` | 943xxx | Session | Session fixation |
| `java-injection.yaml` | 944xxx | Java | Java deserialization, EL injection |
| `response-data-leakage.yaml` | 950xxx | Response | Generic data leakage |
| `response-sql-errors.yaml` | 951xxx | Response | SQL error disclosure |
| `response-java-errors.yaml` | 952xxx | Response | Java error disclosure |
| `response-php-errors.yaml` | 953xxx | Response | PHP error disclosure |
| `response-iis-errors.yaml` | 954xxx | Response | IIS error disclosure |
| `response-web-shells.yaml` | 955xxx | Response | Web shell detection |
| `response-ruby-errors.yaml` | 956xxx | Response | Ruby error disclosure |

## Data Files

The `data/` directory contains wordlists used by `pm_from_file` rules:

| File | Used By | Contents |
|------|---------|----------|
| `scanners-user-agents.data` | 913100 | Known scanner User-Agents |
| `lfi-os-files.data` | 930120 | OS-specific file paths |
| `restricted-files.data` | 930130 | Restricted file extensions |
| `restricted-upload.data` | 933110 | Dangerous upload extensions |
| `unix-shell.data` | 932100 | Unix shell commands |
| `unix-shell-builtins.data` | 932150 | Unix shell builtins |
| `unix-shell-aliases.data` | 932160 | Unix shell aliases |
| `windows-powershell-commands.data` | 932200 | PowerShell commands |
| `php-function-names-933150.data` | 933150 | Dangerous PHP functions |
| `php-errors.data` | 953100 | PHP error strings |
| `php-variables.data` | 933120 | PHP superglobal variables |
| `sql-errors.data` | 951100 | SQL error strings |
| `java-classes.data` | 944110 | Dangerous Java classes |
| `asp-dotnet-errors.data` | 954110 | ASP.NET error strings |
| `iis-errors.data` | 954120 | IIS error strings |
| `ruby-errors.data` | 956100 | Ruby error strings |
| `web-shells-php.data` | 955100 | PHP web shell patterns |
| `web-shells-asp.data` | 955110 | ASP web shell patterns |
| `ssrf.data` | 934100 | SSRF target patterns |
| `ssrf-no-scheme.data` | 934110 | SSRF no-scheme patterns |
| `ai-critical-artifacts.data` | 934150 | AI/ML sensitive artifacts |

## Paranoia Levels

| Level | Description | False Positive Risk |
|-------|-------------|---------------------|
| 1 | Default | Very low |
| 2 | Recommended | Low |
| 3 | Aggressive | Moderate |
| 4 | Maximum | High |

Start with paranoia level 1 in production, increase gradually with tuning.

## Updating

To pull the latest CRS and re-convert:

```bash
python tools/sync.py \
  --source owasp-crs \
  --output rules/owasp-crs/ \
  --tag v4.10.0
```

Or use a local clone:

```bash
python tools/sync.py \
  --source owasp-crs \
  --output rules/owasp-crs/ \
  --local /tmp/owasp-crs
```

## License

OWASP CRS is distributed under Apache License 2.0.
Copyright (c) 2006-2020 Trustwave and contributors.
Copyright (c) 2021-2026 CRS project.
