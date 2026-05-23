#!/usr/bin/env bash
#
# Idempotent installer for the GitHub Actions self-hosted runner that handles
# `release.yaml`'s deploy job on the RHEL 9 EC2 box.
#
# What it does:
#   1. Creates a dedicated `gh-runner` system user (home /opt/gh-runner).
#   2. Downloads the latest actions/runner release for linux-x64.
#   3. Registers it against the given repo with the requested labels.
#   4. Installs the runner as a systemd service (runs as gh-runner, not root).
#   5. Installs /usr/local/sbin/prx-waf-deploy (the deploy entrypoint the
#      workflow's deploy job calls via sudo).
#   6. Installs /etc/sudoers.d/prx-waf-deploy giving gh-runner password-less
#      sudo for ONLY the deploy script and `systemctl status prx-waf` /
#      `journalctl -u prx-waf`.
#   7. Adds gh-runner to the systemd-journal group so the workflow can read
#      logs on failure without sudo.
#
# Usage (run as a user with sudo, e.g. ssm-user on the EC2):
#   ./ec2-install-gh-runner.sh <repo-url> <registration-token> [labels]
#
#   repo-url            Full https URL of the repo,
#                       e.g. https://github.com/future-and-go/mini-waf
#   registration-token  Token from
#                       Settings -> Actions -> Runners -> New self-hosted runner
#                       (TTL ~1h). The value printed after `--token` in the
#                       UI's `./config.sh` example.
#   labels              Comma-separated extra labels (default: prx-waf-ec2).
#                       The runner always also reports the built-in labels:
#                       self-hosted, Linux, X64.
#
# Re-running is safe — every step is guarded.

set -euo pipefail

REPO_URL=${1:?"Usage: $0 <repo-url> <registration-token> [labels]"}
REG_TOKEN=${2:?"Usage: $0 <repo-url> <registration-token> [labels]"}
LABELS=${3:-prx-waf-ec2}
RUNNER_NAME=${RUNNER_NAME:-prx-waf-ec2}
RUNNER_DIR=/opt/gh-runner

log() { printf '\n\033[1;36m==> %s\033[0m\n' "$*"; }

# ── 1. Required system packages (rsync used by the deploy script; libicu by
#       the runner's dotnet host; tar/curl already present from base install)
log "Installing runner OS prerequisites"
sudo dnf -y install libicu rsync tar curl jq

# ── 2. gh-runner system user
if ! id gh-runner &>/dev/null; then
  log "Creating gh-runner user"
  sudo useradd -m -d "$RUNNER_DIR" -s /bin/bash gh-runner
else
  log "gh-runner user already exists"
fi
sudo usermod -aG systemd-journal gh-runner

# ── 3. Download the latest actions runner tarball (cached by version on disk)
log "Resolving latest actions/runner release"
RUNNER_VERSION=$(curl -fsSL https://api.github.com/repos/actions/runner/releases/latest \
                 | jq -r .tag_name | sed 's/^v//')
RUNNER_TAR="actions-runner-linux-x64-${RUNNER_VERSION}.tar.gz"
RUNNER_URL="https://github.com/actions/runner/releases/download/v${RUNNER_VERSION}/${RUNNER_TAR}"
log "Runner version: ${RUNNER_VERSION}"

if [ ! -f "${RUNNER_DIR}/.runner" ]; then
  log "Downloading + extracting runner"
  sudo -u gh-runner bash -c "
    cd '$RUNNER_DIR'
    curl -fsSL -o '$RUNNER_TAR' '$RUNNER_URL'
    tar xzf '$RUNNER_TAR'
    rm -f '$RUNNER_TAR'
  "

  log "Registering runner with $REPO_URL (labels: $LABELS)"
  sudo -u gh-runner bash -c "
    cd '$RUNNER_DIR'
    ./config.sh --unattended \
      --url '$REPO_URL' \
      --token '$REG_TOKEN' \
      --name '$RUNNER_NAME' \
      --labels '$LABELS' \
      --work _work \
      --replace
  "
else
  log "Runner already registered (.runner exists) — skipping config"
fi

# ── 4. Install as systemd service (uses the runner's bundled installer)
SVC_UNIT=$(sudo ls /etc/systemd/system/ | grep -E '^actions\.runner\..*\.service$' | head -1 || true)
if [ -z "$SVC_UNIT" ]; then
  log "Installing systemd service"
  sudo bash -c "cd '$RUNNER_DIR' && ./svc.sh install gh-runner"
  SVC_UNIT=$(sudo ls /etc/systemd/system/ | grep -E '^actions\.runner\..*\.service$' | head -1)
else
  log "Systemd service already installed: $SVC_UNIT"
fi
sudo systemctl enable --now "$SVC_UNIT"

# ── 5. Drop the deploy entrypoint script
log "Installing /usr/local/sbin/prx-waf-deploy"
sudo tee /usr/local/sbin/prx-waf-deploy >/dev/null <<'DEPLOY_EOF'
#!/usr/bin/env bash
#
# prx-waf-deploy <unpacked-dir> [version]
#
# Invoked by the release.yaml deploy job via sudo. Atomic-ish install of a new
# prx-waf binary + rule/config tree, with first-run DB migrate + admin seed.
#
# Layout expected at $UNPACKED:
#   prx-waf             ← release binary
#   rules/              ← OWASP CRS + custom rules
#   configs/            ← default.toml + companion YAMLs (rate-limit, cache, …)
#   migrations/         ← sqlx migrations (optional — binary also embeds them)
#   prx-waf.service     ← systemd unit (only re-installed when content changes)

set -euo pipefail

UNPACKED=${1:?"usage: prx-waf-deploy <unpacked-dir> [version]"}
VERSION=${2:-unknown}

[ -d "$UNPACKED" ]           || { echo "$UNPACKED is not a directory" >&2; exit 1; }
[ -x "$UNPACKED/prx-waf" ]   || { echo "$UNPACKED/prx-waf missing or not executable" >&2; exit 1; }

ENVFILE=/etc/prx-waf/env
CONF=/etc/prx-waf/config.toml
UNIT_SRC="$UNPACKED/prx-waf.service"
UNIT_DST=/etc/systemd/system/prx-waf.service
MARKER=/var/lib/prx-waf/.bootstrapped

echo "==> Deploying prx-waf $VERSION"

# 1. Render /etc/prx-waf/config.toml from the shipped default.toml,
#    substituting the [storage].database_url line with the value baked into
#    /etc/prx-waf/env at provisioning time. Keeps secrets out of the repo.
[ -f "$ENVFILE" ] || { echo "$ENVFILE missing — was the EC2 set up by prx-waf-install.sh?" >&2; exit 1; }
# shellcheck disable=SC1090
. <(grep -E '^(DATABASE_URL|JWT_SECRET|CACHE_BACKEND)=' "$ENVFILE")
: "${DATABASE_URL:?DATABASE_URL missing in $ENVFILE}"

TMPCONF=$(mktemp)
trap 'rm -f "$TMPCONF"' EXIT
cp "$UNPACKED/configs/default.toml" "$TMPCONF"
# Render the shipped Docker-Compose defaults for a bare-metal host:
#   - database_url:          inject value from /etc/prx-waf/env
#   - [panel] config_path:   force absolute under /opt/prx-waf so the
#                            running user can write the file (default config
#                            resolves relative to the config file's parent
#                            directory, which is /etc/prx-waf — read-only).
#   - [cache.valkey] seeds:  swap the Compose hostname "valkey:6379" for the
#                            local Valkey instance installed alongside prx-waf.
sed -i "s|^database_url *=.*|database_url = \"${DATABASE_URL//|/\\|}\"|" "$TMPCONF"
sed -i "s|^config_path *=.*waf-panel.toml.*|config_path = \"/opt/prx-waf/waf-panel.toml\"|" "$TMPCONF"
sed -i 's|seeds *= *\["valkey:6379"\]|seeds = ["127.0.0.1:6379"]|' "$TMPCONF"
install -o prx-waf -g prx-waf -m 0640 "$TMPCONF" "$CONF"

# 2. Sync rules + non-default-toml configs into the working dir
rsync -a --delete "$UNPACKED/rules/" /opt/prx-waf/rules/
rsync -a --delete --exclude='default.toml' "$UNPACKED/configs/" /opt/prx-waf/configs/
chown -R prx-waf:prx-waf /opt/prx-waf/rules /opt/prx-waf/configs

# 3. Install binary (atomic via temp + rename), add CAP_NET_BIND_SERVICE
install -m 0755 "$UNPACKED/prx-waf" /usr/local/bin/prx-waf.new
setcap 'cap_net_bind_service=+ep' /usr/local/bin/prx-waf.new
mv -f /usr/local/bin/prx-waf.new /usr/local/bin/prx-waf

# 4. Refresh the systemd unit only when its contents differ
if [ -f "$UNIT_SRC" ]; then
  if ! cmp -s "$UNIT_SRC" "$UNIT_DST"; then
    install -m 0644 "$UNIT_SRC" "$UNIT_DST"
    systemctl daemon-reload
  fi
fi

# 5. First-run bootstrap: migrate + seed-admin
if [ ! -f "$MARKER" ]; then
  echo "==> First deploy: running migrate + seed-admin"
  sudo -u prx-waf /usr/local/bin/prx-waf -c "$CONF" migrate
  sudo -u prx-waf /usr/local/bin/prx-waf -c "$CONF" seed-admin || \
    echo "(seed-admin may have already run — continuing)"
  install -o prx-waf -g prx-waf -m 0644 /dev/null "$MARKER"
fi

# 6. Restart and report
systemctl restart prx-waf
sleep 1
systemctl is-active prx-waf
DEPLOY_EOF
sudo chmod 0755 /usr/local/sbin/prx-waf-deploy

# ── 6. Sudoers fragment (validate before installing)
log "Installing sudoers fragment"
TMPSUDO=$(mktemp)
cat >"$TMPSUDO" <<'SUDO_EOF'
# gh-runner deploy permissions (managed by ec2-install-gh-runner.sh)
gh-runner ALL=(root) NOPASSWD: /usr/local/sbin/prx-waf-deploy *
gh-runner ALL=(root) NOPASSWD: /bin/systemctl status prx-waf
gh-runner ALL=(root) NOPASSWD: /bin/systemctl is-active prx-waf
gh-runner ALL=(root) NOPASSWD: /bin/systemctl restart prx-waf
Defaults!/usr/local/sbin/prx-waf-deploy !requiretty
SUDO_EOF
sudo install -m 0440 -o root -g root "$TMPSUDO" /etc/sudoers.d/prx-waf-deploy
rm -f "$TMPSUDO"
sudo visudo -cf /etc/sudoers.d/prx-waf-deploy

# ── 7. Status
log "Done"
sudo systemctl status "$SVC_UNIT" --no-pager | head -15 || true
echo
echo "Verify the runner is online at:"
echo "  ${REPO_URL%/}/settings/actions/runners"
