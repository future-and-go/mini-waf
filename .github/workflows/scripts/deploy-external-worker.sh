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

systemctl restart mini-waf

for i in 1 2 3 4 5; do
  if curl -fsS --max-time 5 http://127.0.0.1:9527/health >/dev/null; then
    break
  fi
  if [ "$i" = 5 ]; then
    echo "post-deploy /health failed after 5 tries" >&2
    journalctl -u mini-waf -n 80 --no-pager >&2 || true
    exit 1
  fi
  sleep 2
done

echo "external worker deploy OK: __SHA__"
