#!/usr/bin/env bash
# On-node deploy step driven by .github/workflows/deploy-cluster.yml.
#
# The workflow renders __URL__ (S3 presigned binary URL) and __SHA__
# (commit SHA) before sending the script to SSM Run Command. The body
# runs as the SSM agent (root) on each cluster node.

set -euo pipefail

TMP=$(mktemp)
trap 'rm -f "$TMP"' EXIT

curl -fSL --max-time 120 --retry 2 --retry-delay 3 "__URL__" -o "$TMP"
chmod +x "$TMP"

# Install at /opt/mini-waf/bin/mini-waf — the path the systemd unit executes.
install -o miniwaf -g miniwaf -m 0755 "$TMP" /opt/mini-waf/bin/mini-waf.new
mv -f /opt/mini-waf/bin/mini-waf.new /opt/mini-waf/bin/mini-waf

# Admin API TLS is on by default (auto self-signed). Auto mode persists the cert
# under /var/lib/prx-waf/admin-tls; the non-root service user can't create that
# path itself, so pre-create it owned by the service user. Without this the admin
# API fails to bootstrap TLS and never binds 9527.
mkdir -p /var/lib/prx-waf/admin-tls
chown miniwaf:miniwaf /var/lib/prx-waf/admin-tls
chmod 0700 /var/lib/prx-waf/admin-tls

systemctl restart mini-waf
sleep 6
systemctl is-active mini-waf

# Admin API serves HTTPS (self-signed) once TLS bootstraps, so probe over TLS
# and skip cert verification for the loopback self-signed cert.
for i in 1 2 3 4 5; do
  if curl -fsSk --max-time 5 https://127.0.0.1:9527/health >/dev/null; then
    break
  fi
  if [ "$i" = 5 ]; then
    echo "post-deploy /health failed after 5 tries" >&2
    journalctl -u mini-waf -n 80 --no-pager >&2 || true
    exit 1
  fi
  sleep 2
done

echo "deploy OK: __SHA__"
