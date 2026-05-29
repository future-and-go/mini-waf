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

install -o miniwaf -g miniwaf -m 0755 "$TMP" /opt/mini-waf/bin/prx-waf.new
mv -f /opt/mini-waf/bin/prx-waf.new /opt/mini-waf/bin/prx-waf

systemctl restart mini-waf
sleep 6
systemctl is-active mini-waf

if ! curl -fsS --max-time 5 http://127.0.0.1:9527/healthz \
  && ! curl -fsS --max-time 5 http://127.0.0.1:9527/api/health; then
  echo "post-deploy healthz failed" >&2
  journalctl -u mini-waf -n 80 --no-pager >&2 || true
  exit 1
fi

echo "deploy OK: __SHA__"
