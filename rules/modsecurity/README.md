# ModSecurity Community Rules

Hand-crafted prx-waf rules inspired by ModSecurity community best practices.
These rules cover threat categories not fully addressed by OWASP CRS.

## Rule Sets

| File | Description | Rules |
|------|-------------|-------|
| `ip-reputation.yaml` | Malicious bot/scanner/proxy detection | 10 |
| `dos-protection.yaml` | DoS and rate-limiting indicators | 12 |
| `data-leakage.yaml` | PII and credential leak detection | 12 |
| `response-checks.yaml` | Response inspection (web shells, error disclosure) | 12 |

## Coverage

- **IP Reputation**: Blocks known scanners (Nikto, SQLMap, Nmap, Metasploit),
  headless browsers, and spoofed X-Forwarded-For headers.

- **DoS Protection**: Detects oversized requests, abnormal argument counts,
  HTTP TRACE/DEBUG methods, XML bomb patterns.

- **Data Leakage**: Detects credit card numbers, SSNs, AWS keys, private SSH keys,
  database connection strings, JWT tokens, and Git tokens in responses.

- **Response Checks**: Detects PHP/ASP web shells, directory listings, `.env`
  file exposure, verbose stack traces, and Spring Boot actuator leaks.

## Source

Written by prx-waf project. Apache License 2.0.

## Updating

These rules are maintained manually. To add rules:

1. Copy the rule schema from `rules/custom/README.md`
2. Use IDs in the `MODSEC-<CATEGORY>-NNN` namespace
3. Run `python tools/validate.py rules/modsecurity/`

## Paranoia Levels

Rules in this directory use paranoia levels 1 (essential) and 2 (recommended).
Level 3+ rules are logged only, not blocked.
