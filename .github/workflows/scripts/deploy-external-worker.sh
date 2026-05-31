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

# Admin API TLS now defaults on (auto self-signed). The auto cert dir falls back
# to /var/lib/prx-waf/admin-tls, which this non-root (miniwaf) service can't
# create — the admin API then fails to start and the health check below times
# out. The cluster admin API is HTTP on loopback/internal by design, so pin TLS
# off when the node config hasn't set [api.tls] explicitly.
CFG=/opt/mini-waf/configs/prod.toml
if [ -f "$CFG" ] && ! grep -q '^\[api\.tls\]' "$CFG"; then
  printf '\n[api.tls]\nenabled = false\n' >>"$CFG"
fi

systemctl restart mini-waf

# Bounded health gate (~30s). --connect-timeout caps a half-open socket while
# the process is still binding 9527, so no single probe can stall. Exit on the
# first success so the remote shell returns promptly and the SSH session closes.
for _ in $(seq 1 15); do
  if curl -fsS --connect-timeout 3 --max-time 5 http://127.0.0.1:9527/health >/dev/null 2>&1; then
    echo "external worker deploy OK: __SHA__"
    exit 0
  fi
  sleep 2
done

echo "post-deploy /health failed after ~30s" >&2
journalctl -u mini-waf -n 80 --no-pager >&2 || true
exit 1
