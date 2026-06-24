#!/usr/bin/env bash
#
# One-click local/demo deploy of prx-waf with ALL single-node features on.
#
#   ./scripts/deploy.sh            build + bring the stack up, gate on health
#   ./scripts/deploy.sh --no-build reuse existing target/release/waf + dist/
#   ./scripts/deploy.sh --down     tear the stack down
#
# Builds the release binary + admin panel on the host, generates secrets into
# .env, then runs docker-compose.yml + docker-compose.deploy.yml. The WAF `run`
# command auto-migrates and auto-creates the admin user — no manual steps.

set -euo pipefail

# ── Resolve repo root (script lives in <root>/scripts) ───────────────────────
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"
cd "${ROOT_DIR}"

COMPOSE_FILES=(-f docker-compose.yml -f docker-compose.deploy.yml)
HEALTH_URL="https://localhost:16827/health"
PROXY_URL="http://localhost:16880"
JUICE_HOST="juice.local"

NO_BUILD=0
DO_DOWN=0
for arg in "$@"; do
  case "$arg" in
    --no-build) NO_BUILD=1 ;;
    --down)     DO_DOWN=1 ;;
    -h|--help)
      sed -n '2,12p' "${BASH_SOURCE[0]}" | sed 's/^# \{0,1\}//'
      exit 0 ;;
    *) echo "unknown flag: $arg (see --help)" >&2; exit 2 ;;
  esac
done

log()  { printf '\033[1;34m▶ %s\033[0m\n' "$*"; }
warn() { printf '\033[1;33m! %s\033[0m\n' "$*" >&2; }
die()  { printf '\033[1;31m✗ %s\033[0m\n' "$*" >&2; exit 1; }

dc() { docker compose "${COMPOSE_FILES[@]}" "$@"; }

# ── --down: tear down and exit ───────────────────────────────────────────────
if [[ "${DO_DOWN}" == 1 ]]; then
  log "Tearing down the stack…"
  dc down
  log "Stack down."
  exit 0
fi

# ── 1. Preflight ─────────────────────────────────────────────────────────────
preflight() {
  log "Preflight checks"
  [[ -f Cargo.toml && -f docker-compose.yml ]] || die "run from the repo root (Cargo.toml + docker-compose.yml not found)"
  command -v docker >/dev/null 2>&1 || die "docker not found"
  docker compose version >/dev/null 2>&1 || die "docker compose v2 not found (legacy docker-compose is unsupported)"
  if [[ "${NO_BUILD}" == 0 ]]; then
    command -v cargo >/dev/null 2>&1 || die "cargo not found (or pass --no-build)"
    command -v npm   >/dev/null 2>&1 || die "npm not found (or pass --no-build)"
  fi
}

# ── 2. Build artifacts (prebuilt-image inputs) ───────────────────────────────
build_artifacts() {
  if [[ "${NO_BUILD}" == 1 ]]; then
    log "Skipping build (--no-build)"
    [[ -x target/release/waf ]] || die "--no-build set but target/release/waf is missing"
    [[ -d web/admin-panel/dist ]] || die "--no-build set but web/admin-panel/dist is missing"
  else
    log "Building admin panel (npm ci && npm run build)…"
    ( cd web/admin-panel && npm ci && npm run build )

    log "Building release binary (cargo build --release --features gateway/valkey)…"
    cargo build --release --features gateway/valkey
  fi
  # Dockerfile.prebuilt COPYs data/ — ensure it exists even when empty.
  mkdir -p data
}

# ── 3. Secrets / .env ────────────────────────────────────────────────────────
set_env_var() {  # set_env_var KEY VALUE — update in place or append
  local key="$1" val="$2"
  if grep -qE "^${key}=" .env; then
    # Use a temp file to stay portable across GNU/BSD sed.
    grep -vE "^${key}=" .env > .env.tmp
    printf '%s=%s\n' "$key" "$val" >> .env.tmp
    mv .env.tmp .env
  else
    printf '%s=%s\n' "$key" "$val" >> .env
  fi
}

gen_secret() {
  if command -v openssl >/dev/null 2>&1; then
    openssl rand -hex 32
  else
    head -c 32 /dev/urandom | od -An -tx1 | tr -d ' \n'
  fi
}

ensure_env() {
  log "Ensuring .env secrets"
  [[ -f .env ]] || cp .env.example .env
  # Generate a strong JWT_SECRET only if absent/empty — never clobber an existing one.
  local cur
  cur="$( (grep -E '^JWT_SECRET=' .env || true) | head -1 | cut -d= -f2-)"
  if [[ -z "${cur}" ]]; then
    log "Generating JWT_SECRET"
    set_env_var JWT_SECRET "$(gen_secret)"
  else
    log "Keeping existing JWT_SECRET"
  fi
}

# ── 4. Compose up ────────────────────────────────────────────────────────────
compose_up() {
  log "Bringing the stack up (docker compose up -d --build)…"
  dc up -d --build
}

# ── 5. Health gate ───────────────────────────────────────────────────────────
health_gate() {
  log "Waiting for the WAF to report healthy (${HEALTH_URL})…"
  local deadline=$(( SECONDS + 90 )) body=""
  while (( SECONDS < deadline )); do
    if body="$(curl -ksf "${HEALTH_URL}" 2>/dev/null)"; then
      if printf '%s' "$body" | grep -q '"status":"ok"'; then
        log "Healthy: ${body}"
        return 0
      fi
    fi
    sleep 3
  done
  warn "Health gate timed out after 90s. Last response: ${body:-<none>}"
  warn "Recent prx-waf logs:"
  dc logs --tail=50 prx-waf >&2 || true
  die "stack did not become healthy"
}

# ── 6. Smoke test (non-fatal) ────────────────────────────────────────────────
smoke_test() {
  log "Smoke test through the proxy (Host: ${JUICE_HOST})"
  local code
  # Juice Shop may still be warming up; retry the benign request briefly.
  local i
  for i in 1 2 3 4 5 6; do
    code="$(curl -s -o /dev/null -w '%{http_code}' -H "Host: ${JUICE_HOST}" "${PROXY_URL}/" || true)"
    [[ "${code}" =~ ^[23] ]] && break
    sleep 5
  done
  if [[ "${code}" =~ ^[23] ]]; then
    log "Benign request proxied (HTTP ${code})"
  else
    warn "Benign request returned HTTP ${code:-000} — Juice Shop may not be ready yet (non-fatal)"
  fi

  # SQLi probe — OWASP CRS should block with 403.
  code="$(curl -s -o /dev/null -w '%{http_code}' -H "Host: ${JUICE_HOST}" \
    "${PROXY_URL}/rest/products/search?q=1%27%20OR%20%271%27%3D%271" || true)"
  if [[ "${code}" == "403" ]]; then
    log "SQLi probe BLOCKED (HTTP 403) ✓"
  else
    warn "SQLi probe returned HTTP ${code:-000} (expected 403) — check rules/host routing"
  fi
}

# ── 7. Access info ───────────────────────────────────────────────────────────
print_access() {
  local admin_pw
  admin_pw="$( (grep -E '^ADMIN_PASSWORD=' .env || true) | head -1 | cut -d= -f2-)"
  [[ -n "${admin_pw}" ]] || admin_pw="(random — see: docker compose ${COMPOSE_FILES[*]} logs prx-waf | grep -A2 'ADMIN USER')"
  cat <<EOF

────────────────────────────────────────────────────────────────────
 prx-waf is up — all single-node features enabled
────────────────────────────────────────────────────────────────────
 Admin panel / API : https://localhost:16827/ui/   (self-signed TLS)
 HTTP proxy        : http://localhost:16880
 HTTPS proxy       : https://localhost:16843        (+ HTTP/3 on 443/udp)
 Health            : https://localhost:16827/health

 Admin login       : admin / ${admin_pw}
                     ⚠ change this immediately for anything but local demo

 Test target (Juice Shop) through the WAF:
   curl -s http://localhost:16880/ -H 'Host: juice.local'
   curl -s -o /dev/null -w '%{http_code}\\n' -H 'Host: juice.local' \\
     'http://localhost:16880/rest/products/search?q=1%27%20OR%20%271%27%3D%271'   # → 403

 Tear down: ./scripts/deploy.sh --down
────────────────────────────────────────────────────────────────────
EOF
}

main() {
  preflight
  build_artifacts
  ensure_env
  compose_up
  health_gate
  smoke_test
  print_access
}

main
