#!/usr/bin/env bash
# On-node deploy step for the external (non-AWS) cluster worker, driven over
# SSH by .github/workflows/deploy-cluster.yml. The external worker cannot be
# reached via SSM, so the workflow pipes this script to `ssh ... bash -s`.
#
# The workflow renders __URL__ (S3 presigned binary URL) and __SHA__ (commit
# SHA) before sending the script. It runs as root on the worker.
#
# NOTE: the binary is installed at /opt/mini-waf/bin/mini-waf — the path the
# systemd unit actually executes on this node.

set -euo pipefail

TMP=$(mktemp)
trap 'rm -f "$TMP"' EXIT

curl -fSL --max-time 180 --retry 3 --retry-delay 3 "__URL__" -o "$TMP"
chmod +x "$TMP"

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

# Bounded health gate (~30s). --connect-timeout caps a half-open socket while
# the process is still binding 9527, so no single probe can stall. Admin API
# serves HTTPS (self-signed) so probe over TLS with -k. Exit on the first
# success so the remote shell returns promptly and the SSH session closes.
for _ in $(seq 1 15); do
  if curl -fsSk --connect-timeout 3 --max-time 5 https://127.0.0.1:9527/health >/dev/null 2>&1; then
    echo "external worker deploy OK: __SHA__"
    exit 0
  fi
  sleep 2
done

echo "post-deploy /health failed after ~30s" >&2
journalctl -u mini-waf -n 80 --no-pager >&2 || true
exit 1
