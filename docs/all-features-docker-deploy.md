# All-Features Docker Deploy (single node, local/demo)

One command brings up `prx-waf` on a single host via Docker with **every
single-node feature enabled**, self-signed TLS, and the bundled OWASP Juice
Shop as a live test target behind the WAF.

> Local/demo only. TLS is self-signed, CORS and the admin IP allowlist are
> open, and secrets live in a generated `.env`. Do **not** expose this to the
> public internet as-is.

## One command

```bash
./scripts/deploy.sh
```

That script: preflight-checks tooling → builds the admin panel (`npm`) and the
release binary (`cargo build --release --features gateway/valkey`) → generates
`.env` secrets → `docker compose -f docker-compose.yml -f docker-compose.deploy.yml up -d --build`
→ waits for `/health` → runs a benign + SQLi smoke probe → prints access info.
The WAF `run` command auto-migrates the database and auto-creates the admin
user, so there are no manual migrate/seed steps.

Flags: `--no-build` (reuse an existing `target/release/waf` + panel `dist/`),
`--down` (tear the stack down).

## Access

| Surface | URL |
| --- | --- |
| Admin panel / API | `https://localhost:16827/ui/` (self-signed) |
| Health | `https://localhost:16827/health` |
| HTTP proxy | `http://localhost:16880` |
| HTTPS proxy | `https://localhost:16843` (+ HTTP/3 on `443/udp`) |

Admin login: `admin` / value of `ADMIN_PASSWORD` in `.env` (defaults to
`admin123`). **Change it for anything but a local demo.** If `ADMIN_PASSWORD`
is blank, the WAF generates a random password and prints it once to the
container log (`docker compose ... logs prx-waf | grep -A2 'ADMIN USER'`).

## Verify it enforces

The Juice Shop host is routed as `juice.local` with OWASP CRS on.

```bash
# Benign request → proxied
curl -s -o /dev/null -w '%{http_code}\n' -H 'Host: juice.local' http://localhost:16880/

# SQLi probe → blocked (403)
curl -s -o /dev/null -w '%{http_code}\n' -H 'Host: juice.local' \
  'http://localhost:16880/rest/products/search?q=1%27%20OR%20%271%27%3D%271'

# The block is recorded (after admin login → JWT):
curl -ksf https://localhost:16827/api/security-events
```

Other live-feature checks:

| Feature | Check |
| --- | --- |
| Config loaded | `docker compose ... logs prx-waf \| grep full-features` |
| Valkey cache | `docker compose ... logs prx-waf \| grep -i valkey` (standalone, not memory fallback) |
| HTTP/3 | `443/udp` published; `curl -ksI --http3 https://localhost:16843/` if your curl has HTTP/3 |
| Outbound strip | proxied response headers carry no `X-Powered-By` / server fingerprint |
| Audit sink | `docker compose ... exec prx-waf ls -la waf_audit.log` (JSONL) |

> `/health` reports `"status":"ok"` (HTTP 200) with `database` / `waf_engine` /
> `cache` components. It does not surface the cache backend name — use the logs
> for the Valkey-vs-memory check.

## Prebuilt binary & glibc

The deploy builds the release binary on the host, then copies it into the image
(`Dockerfile.prebuilt`). A dynamically-linked binary needs a runtime glibc
**≥ the build host's** glibc. The deploy override therefore bases the image on
`debian:trixie-slim` (glibc 2.41) via the `BASE_IMAGE` build arg, which covers
current build hosts; the Dockerfile's default base stays `debian:bookworm-slim`
for other consumers (cluster, e2e, CI). If you build on an even newer host and
hit `version 'GLIBC_x.y' not found`, bump `BASE_IMAGE` in
`docker-compose.deploy.yml` to a base with a newer glibc.

## Toggle features

`configs/full-features.toml` is the single source of truth — every feature is a
labelled section. Flip `enabled = false` (or remove the section) to disable one,
then re-run `./scripts/deploy.sh` (or `docker compose ... restart prx-waf`).
The companion `configs/full-features-panel.toml` holds enforce-mode, risk bands,
honeypots, and auto-block.

`configs/default.toml` is the conservative baseline and is left untouched.

## Excluded features (need a different topology / external setup)

| Feature | Why excluded | How to enable later |
| --- | --- | --- |
| Cluster HA (3-node) | Multi-host topology | Uncomment `[cluster]` in the config + use `docker-compose.cluster.yml` |
| Community threat-intel | Needs `prx-waf community enroll` + external server | Enroll, then set `[community] enabled = true` |
| CrowdSec | Needs an external CrowdSec LAPI | Set `[crowdsec] enabled = true` + `lapi_url` / `api_key` |
| ACME / Let's Encrypt | Needs a real public domain | Use real cert paths in `[proxy]` / `[http3]` |
| GeoIP auto-update | Needs outbound network + DB download | `prx-waf geoip download`, then `[geoip.auto_update] enabled = true` |
| Benchmark interop control | Test harness control plane | Set `[interop] enabled = true` (off by default here) |
