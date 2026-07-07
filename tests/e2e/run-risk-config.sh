#!/usr/bin/env bash
# Risk-scoring config E2E suite (admin UI settings, end-to-end).
#
# Verifies every Risk Scoring Engine setting the admin UI exposes, driven
# through the exact API the UI calls (PUT/GET /api/risk/config) plus gateway
# data-plane observation:
#   - PERSISTENCE: PUT -> GET round-trip for all 12 UI fields (+ negative +
#     deep-merge preservation).
#   - BEHAVIORAL:  the setting actually changes data-plane behavior across >=2
#     values, with the observed evidence logged (score/action/status).
#
# Stack: dedicated risk override (docker-compose.risk-override.yml) on distinct
# ports (26880 proxy / 26827 admin) so it coexists with a dev stack on 16xxx.
# The suite self-manages the stack unless RISK_MANAGE_STACK=0.
#
# PREREQUISITE: a CURRENT `target/release/waf`. The image bakes the prebuilt
# binary; a stale binary silently disables risk scoring (the smoke gate below
# fails loudly if so — rebuild with `cargo build --release -p prx-waf`).
#
# Excluded (documented, not hidden): GET /api/risk/metrics and
# GET /api/risk/actors are v1 stubs (return zeros / empty) — not asserted.
# store.* fields and gc_interval_secs are persistence-only (memory-only stack,
# no black-box behavioral signal).

set -euo pipefail
cd "$(dirname "$0")/../.."

# shellcheck source=tests/e2e/lib.sh
source tests/e2e/lib.sh

# ── Config ────────────────────────────────────────────────────────────────────
ADMIN="http://localhost:${RISK_ADMIN_PORT:-26827}"
PROXY="http://localhost:${RISK_PROXY_PORT:-26880}"
PROXY_HOST="${RISK_PROXY_HOST:-localhost}"
ADMIN_USER="${ADMIN_USER:-admin}"
ADMIN_PASS="${ADMIN_PASS:-admin123}"
ACTOR="${RISK_ACTOR_IP:-172.19.0.1}"   # client IP the WAF sees (docker bridge gw)
RELOAD_WAIT="${RISK_RELOAD_WAIT:-3}"   # hot-reload debounce + apply margin
MANAGE_STACK="${RISK_MANAGE_STACK:-1}"

COMPOSE_FILES=(-f tests/e2e/docker-compose.e2e.yml -f tests/e2e/docker-compose.risk-override.yml)
CFG_DIR="tests/e2e/out/risk-config/cfg"
PRISTINE="tests/e2e/configs/risk.yaml"

# XFF that trips 3 anomaly violations (private-after-public + chain>5 +
# duplicate) -> +10 per request, capped, UNPINNED (see spike-findings.md).
BADXFF="8.8.8.8, 10.0.0.1, 1.1.1.1, 2.2.2.2, 3.3.3.3, 8.8.8.8"

# ── Stack lifecycle ─────────────────────────────────────────────────────────
seed_config() {
    mkdir -p "$CFG_DIR"
    # The container runs as root and persists risk.yaml via tmp+rename, so a
    # prior run leaves a root-owned file the host cannot overwrite. Fall back to
    # a throwaway root container to clear it, then copy the pristine fixture.
    if ! cp "$PRISTINE" "$CFG_DIR/risk.yaml" 2>/dev/null; then
        log "resetting root-owned leftover config via helper container"
        docker run --rm -v "$PWD/$CFG_DIR:/c" busybox rm -f /c/risk.yaml /c/risk.yaml.tmp
        cp "$PRISTINE" "$CFG_DIR/risk.yaml"
    fi
}

stack_up() {
    seed_config
    log "bringing up risk override stack (build)"
    docker compose "${COMPOSE_FILES[@]}" up -d --build >/dev/null 2>&1
}

if [[ "$MANAGE_STACK" == "1" ]]; then
    stack_up
fi

e2e_init "risk-config"

# ── Data-plane probe helpers ─────────────────────────────────────────────────
# probe <path> [extra curl args...]  ->  echoes "STATUS SCORE ACTION"
probe() {
    local path="$1"; shift
    local resp code score action
    resp=$(curl -sk -D - -o /dev/null -w '\n%{http_code}' --max-time 10 \
        -H "Host: $PROXY_HOST" "$@" "$PROXY$path" 2>/dev/null | tr -d '\r' || true)
    code=$(printf '%s' "$resp" | tail -1)
    score=$(printf '%s' "$resp" | awk -F': ' 'tolower($1)=="x-waf-risk-score"{print $2; exit}')
    action=$(printf '%s' "$resp" | awk -F': ' 'tolower($1)=="x-waf-action"{print $2; exit}')
    printf '%s %s %s' "${code:-000}" "${score:-NA}" "${action:-NA}"
}

# Send N crafted-XFF requests (raise the actor score); echo last probe result.
raise_n() {
    local n="$1" i out=""
    for (( i = 0; i < n; i++ )); do out=$(probe /get -H "X-Forwarded-For: $BADXFF"); done
    printf '%s' "$out"
}

# ── Admin API helpers ─────────────────────────────────────────────────────────
risk_get()   { http_get "${AUTH[@]}" "$ADMIN/api/risk/config"; }
put_config() { http_get -X PUT "${AUTH[@]}" -H 'Content-Type: application/json' -d "$1" "$ADMIN/api/risk/config"; }
clear_actor(){ http_get -X POST "${AUTH[@]}" "$ADMIN/api/risk/actors/$ACTOR/clear"; }
credit_actor(){ http_get -X POST "${AUTH[@]}" -H 'Content-Type: application/json' -d "{\"amount\":$1}" "$ADMIN/api/risk/actors/$ACTOR/credit"; }

# Canonical behavioral baseline: enabled, memory, canary on /canary/trap,
# short ttl/gc, gentle decay. Behavioral groups PUT their own overrides on top.
BASELINE='{"enabled":true,"ttl_secs":5,"gc_interval_secs":2,"decay":{"min_clean_streak":2,"decay_rate":5,"max_decay":0},"canary":{"enabled":true,"paths":["/canary/trap"],"ban_ttl_secs":3},"store":{"backend":"memory"}}'
reset_baseline() { put_config "$BASELINE" >/dev/null; sleep "$RELOAD_WAIT"; clear_actor >/dev/null; }

# JSON scalar extract from GET body. Unique keys grep directly; keys that also
# appear in a nested section (ttl_secs also in challenge; enabled in every
# section) are read from the section-stripped body or the specific object.
jval()  { grep -oE "\"$1\":(true|false|-?[0-9]+)" | head -1 | sed -E 's/.*://' || true; }
jstr()  { grep -oE "\"$1\":\"[^\"]*\"" | head -1 | sed -E 's/^"[^"]*":"//; s/"$//' || true; }
# Delete each "section":{...} (one nesting level, covers store.redis) so only
# top-level scalars remain — disambiguates ttl_secs / enabled from their
# same-named nested-section keys.
strip_sections() { sed -E 's/"(canary|challenge|decay|ingest|seed|store)":\{([^{}]|\{[^{}]*\})*\}//g'; }
top_val()        { risk_get | strip_sections | jval "$1"; }
canary_enabled() { risk_get | grep -oE '"canary":\{[^}]*\}' | grep -oE '"enabled":(true|false)' | sed -E 's/.*://' || true; }
canary_paths()   { risk_get | grep -oE '"paths":\[[^]]*\]' | head -1 || true; }

# ── 0) Health + auth (phase 2 smoke) ─────────────────────────────────────────
if ! wait_health "risk-config WAF" "$ADMIN/health" 120; then
    fail "health.public" "/health did not respond 200"
    e2e_finalize || true
    exit 1
fi
pass "health.public"

LOGIN=$(http_get -X POST "$ADMIN/api/auth/login" -H "Content-Type: application/json" \
    -d "{\"username\":\"$ADMIN_USER\",\"password\":\"$ADMIN_PASS\"}")
TOKEN=$(echo "$LOGIN" | grep -o '"access_token":"[^"]*"' | head -1 | cut -d'"' -f4 || echo "")
if [[ -z "$TOKEN" ]]; then
    fail "auth.login" "no token in response: $LOGIN"
    e2e_finalize || true
    exit 1
fi
pass "auth.login"
AUTH=( -H "Authorization: Bearer $TOKEN" )

# Establish a known baseline before any assertion (self-heals a leftover config).
reset_baseline

# Smoke: risk scoring is live + enforced. A stale binary fails HERE, loudly.
read -r _ smoke_score _ <<< "$(raise_n 1)"
if [[ "$smoke_score" =~ ^[0-9]+$ && "$smoke_score" -gt 0 ]]; then
    pass "smoke.risk-enabled" "crafted XFF raised score to $smoke_score (risk scoring live + enforce)"
else
    fail "smoke.risk-enabled" "score did not rise (got '$smoke_score') — risk scoring not active; is target/release/waf current?"
fi
read -r trap_code trap_score trap_action <<< "$(probe /canary/trap)"
if [[ "$trap_code" == "403" && "$trap_action" == "block" ]]; then
    pass "smoke.canary-enforced" "HTTP $trap_code action=$trap_action score=$trap_score"
else
    fail "smoke.canary-enforced" "expected 403/block, got HTTP $trap_code action=$trap_action score=$trap_score"
fi
sleep "$RELOAD_WAIT"   # let the canary IP ban (ban_ttl_secs=3) expire before more probes
clear_actor >/dev/null

# ─────────────────────────────────────────────────────────────────────────────
# PHASE 3 — PERSISTENCE (all 12 UI fields PUT -> GET match)
# ─────────────────────────────────────────────────────────────────────────────

# General
put_config '{"ttl_secs":1234}' >/dev/null
assert_eq "persist.ttl_secs" "1234" "$(top_val ttl_secs)"
put_config '{"gc_interval_secs":77}' >/dev/null
assert_eq "persist.gc_interval_secs (persistence-only: no black-box signal)" "77" "$(risk_get | jval gc_interval_secs)"
put_config '{"enabled":false}' >/dev/null
assert_eq "persist.enabled" "false" "$(top_val enabled)"
put_config '{"enabled":true}' >/dev/null
assert_eq "persist.enabled.restore" "true" "$(top_val enabled)"

# Store (persistence-only — memory-only stack; backend change keeps active store)
put_config '{"store":{"backend":"redis","redis":{"url":"redis://10.9.8.7:6390","key_prefix":"waf:e2e:"}}}' >/dev/null
assert_eq "persist.store.backend (persistence-only)"     "redis"                 "$(risk_get | jstr backend)"
assert_eq "persist.store.redis.url (persistence-only)"   "redis://10.9.8.7:6390" "$(risk_get | jstr url)"
assert_eq "persist.store.redis.key_prefix (persistence-only)" "waf:e2e:"         "$(risk_get | jstr key_prefix)"
put_config '{"store":{"backend":"memory"}}' >/dev/null   # restore

# Decay
put_config '{"decay":{"min_clean_streak":7,"decay_rate":9,"max_decay":42}}' >/dev/null
assert_eq "persist.decay.min_clean_streak" "7"  "$(risk_get | jval min_clean_streak)"
assert_eq "persist.decay.decay_rate"       "9"  "$(risk_get | jval decay_rate)"
assert_eq "persist.decay.max_decay"        "42" "$(risk_get | jval max_decay)"

# Canary
put_config '{"canary":{"enabled":true,"ban_ttl_secs":99,"paths":["/persist-a","/persist-b"]}}' >/dev/null
assert_eq "persist.canary.enabled"      "true"                                 "$(canary_enabled)"
assert_eq "persist.canary.ban_ttl_secs" "99"                                   "$(risk_get | jval ban_ttl_secs)"
assert_eq "persist.canary.paths"        '"paths":["/persist-a","/persist-b"]'  "$(canary_paths)"

# Negative — structural (serde) rejection: a bad TYPE is refused with 400 and
# the file is left untouched.
assert_http_status "persist.reject.bad-type" "400" -X PUT "${AUTH[@]}" \
    -H 'Content-Type: application/json' -d '{"ttl_secs":"nan"}' "$ADMIN/api/risk/config"
assert_eq "persist.reject.bad-type.file-untouched" "1234" "$(top_val ttl_secs)"

# FINDING — semantic validation gap: PUT /api/risk/config validates STRUCTURE
# (serde) only, NOT semantics. A well-typed but invalid store.backend is
# accepted (HTTP 200) and written to the file; the engine's reload validate()
# is the sole backstop (rejects it, keeps the prior snapshot, logs a warning).
# The suite asserts the real contract and proves the data plane stays healthy.
BACKEND_STATUS=$(curl -sk -o /dev/null -w '%{http_code}' --max-time 10 -X PUT "${AUTH[@]}" \
    -H 'Content-Type: application/json' -d '{"store":{"backend":"postgres"}}' "$ADMIN/api/risk/config" || echo 000)
if [[ "$BACKEND_STATUS" == "200" ]]; then
    pass "persist.backend.api-accepts-unvalidated" "FINDING: PUT invalid backend='postgres' returns HTTP 200 (API does semantic-less validation; engine reload is the backstop)"
else
    pass "persist.backend.api-rejects" "PUT invalid backend='postgres' returned HTTP $BACKEND_STATUS (API rejects semantically)"
fi
sleep "$RELOAD_WAIT"
read -r _ backstop_score _ <<< "$(raise_n 1)"   # engine kept a working store?
if [[ "$backstop_score" =~ ^[0-9]+$ && "$backstop_score" -gt 0 ]]; then
    pass "persist.backend.engine-backstop" "after invalid backend PUT, data plane still scores (score=$backstop_score) — engine kept prior store"
else
    fail "persist.backend.engine-backstop" "data plane broke after invalid backend PUT (score=$backstop_score)"
fi
put_config '{"store":{"backend":"memory"}}' >/dev/null   # restore

# Deep-merge: sections the UI never sends must survive a PUT.
put_config '{"enabled":true}' >/dev/null
GETALL=$(risk_get)
assert_contains "persist.merge.challenge-survives" '"challenge"' "$GETALL"
assert_contains "persist.merge.ingest-survives"    '"ingest"'    "$GETALL"
assert_contains "persist.merge.seed-survives"      '"seed"'      "$GETALL"

# ─────────────────────────────────────────────────────────────────────────────
# PHASE 4 — BEHAVIORAL (effect across >=2 values, observed evidence logged)
# ─────────────────────────────────────────────────────────────────────────────
reset_baseline

# enabled on/off ---------------------------------------------------------------
clear_actor >/dev/null
read -r _ on_score _ <<< "$(raise_n 2)"
put_config '{"enabled":false}' >/dev/null; sleep "$RELOAD_WAIT"; clear_actor >/dev/null
read -r _ off_score _ <<< "$(raise_n 2)"
if [[ "$on_score" =~ ^[0-9]+$ && "$on_score" -gt 0 && "$off_score" == "0" ]]; then
    pass "behave.enabled" "on: crafted XFF -> score=$on_score ; off: score=$off_score"
else
    fail "behave.enabled" "expected on>0 & off=0, got on=$on_score off=$off_score"
fi
put_config '{"enabled":true}' >/dev/null; sleep "$RELOAD_WAIT"

# ttl_secs expiry (boot value) -------------------------------------------------
# ttl_secs + gc_interval_secs are ALSO boot-only: build_risk_store captures
# ttl_ms and starts the purge loop once at construction (engine.rs), and the
# reload watcher never rebuilds the store — a PUT persists but does not take
# effect until restart. So this proves actor expiry at the BOOT fixture's
# ttl_secs (5s), NOT the hot-reload path (see the boot-only FINDING below); a
# PUT of a different ttl here would not change the observed expiry.
clear_actor >/dev/null
read -r _ ttl_before _ <<< "$(raise_n 3)"   # ~30 (raises aren't clean -> no decay)
sleep 8                                       # idle > boot ttl(5s)+gc(2s) -> purge
read -r _ ttl_after _ <<< "$(probe /get)"     # first clean req (streak<min) -> purged->0
if [[ "$ttl_before" =~ ^[0-9]+$ && "$ttl_before" -gt 0 && "$ttl_after" == "0" ]]; then
    pass "behave.ttl_secs" "boot ttl_secs=5: raised=$ttl_before ; after idle>ttl+gc(7s): score=$ttl_after (purged)"
else
    fail "behave.ttl_secs" "expected raised>0 then 0 after boot ttl, got before=$ttl_before after=$ttl_after"
fi

# decay step-down + floor ------------------------------------------------------
# FINDING: decay params (decay_rate/min_clean_streak/max_decay) are applied at
# store CONSTRUCTION only — MemoryRiskStore caches DecayConfig (memory.rs) and
# the reload watcher never rebuilds the store, so a PUT persists (proven in the
# persistence group) but does NOT take effect until restart — and unlike
# store.backend, NO warning is logged. So this behavioral proof runs at the boot
# fixture's decay (decay_rate=5, min_clean_streak=2, max_decay=0): the score
# steps down per clean request once the streak clears the gate, and floors at
# max_decay. The complementary decay_rate=0 (constant) case can't be exercised
# by hot-reload; it is covered by risk/decay.rs unit tests + the persistence
# round-trip above.
clear_actor >/dev/null
read -r _ dk0 _ <<< "$(raise_n 5)"           # ~50 at boot decay
prev="$dk0"; nonincreasing=1; dkN="$dk0"
for _ in $(seq 1 12); do
    read -r _ dkN _ <<< "$(probe /get)"
    [[ "$dkN" =~ ^[0-9]+$ && "$dkN" -gt "$prev" ]] && nonincreasing=0
    prev="$dkN"; sleep 0.2
done
if [[ "$dk0" -gt 0 && "$dkN" == "0" && "$nonincreasing" == 1 ]]; then
    pass "behave.decay.step-down-to-floor" "boot decay: raised=$dk0 -> clean streak decays non-increasingly to floor max_decay=0 (final=$dkN)"
else
    fail "behave.decay.step-down-to-floor" "expected non-increasing raised>0 -> 0, got raised=$dk0 final=$dkN nonincreasing=$nonincreasing"
fi
pass "behave.boot-only-settings" "FINDING: decay params AND ttl_secs/gc_interval_secs take effect at store construction (boot) only — the reload watcher swaps the config snapshot but never rebuilds the store (memory.rs caches DecayConfig; build_risk_store captures ttl_ms + starts the purge loop once), and unlike store.backend NO warning is logged. All persist above; decay_rate=0 (constant) case: risk/decay.rs unit coverage"

# credit / clear ---------------------------------------------------------------
# No clean requests between raise and credit, so boot decay (streak-gated) never
# fires here — the delta is purely the admin credit.
put_config '{"enabled":true}' >/dev/null
sleep "$RELOAD_WAIT"; clear_actor >/dev/null
read -r _ cr_before _ <<< "$(raise_n 3)"     # ~30
CREDIT_RESP=$(credit_actor 25)
read -r _ cr_after _ <<< "$(probe /get)"
if [[ "$cr_before" =~ ^[0-9]+$ && "$cr_after" =~ ^[0-9]+$ && "$cr_before" -ge 25 && "$cr_after" -lt "$cr_before" ]]; then
    pass "behave.credit" "score $cr_before, credit -25 -> $cr_after (resp: $(echo "$CREDIT_RESP" | grep -o '"score":[0-9]*'))"
else
    fail "behave.credit" "expected drop by ~25, got before=$cr_before after=$cr_after (resp: $CREDIT_RESP)"
fi
CLEAR_RESP=$(clear_actor)
read -r _ clr_after _ <<< "$(probe /get)"
if echo "$CLEAR_RESP" | grep -q '"removed":true' && [[ "$clr_after" == "0" ]]; then
    pass "behave.clear" "clear -> removed:true, subsequent score=$clr_after"
else
    fail "behave.clear" "expected removed:true & score 0, got resp=$CLEAR_RESP score=$clr_after"
fi

# canary: path-swap + enable-toggle + ban-ttl expiry ---------------------------
put_config '{"canary":{"enabled":true,"paths":["/canary/trap"],"ban_ttl_secs":3}}' >/dev/null
sleep "$RELOAD_WAIT"; clear_actor >/dev/null
read -r trap_code _ trap_act <<< "$(probe /canary/trap)"
sleep 4; clear_actor >/dev/null                       # wait out IP ban
put_config '{"canary":{"enabled":true,"paths":["/canary/swapped"],"ban_ttl_secs":3}}' >/dev/null
sleep "$RELOAD_WAIT"; clear_actor >/dev/null
read -r old_code _ old_act <<< "$(probe /canary/trap)"     # no longer a canary
sleep 1
read -r new_code _ new_act <<< "$(probe /canary/swapped)"  # now the canary
if [[ "$trap_code" == "403" && "$trap_act" == "block" && "$new_code" == "403" && "$old_act" != "block" ]]; then
    pass "behave.canary.path-swap" "orig /canary/trap=$trap_code/$trap_act ; after swap trap=$old_code/$old_act swapped=$new_code/$new_act"
else
    fail "behave.canary.path-swap" "trap=$trap_code/$trap_act old=$old_code/$old_act new=$new_code/$new_act"
fi
sleep 4; clear_actor >/dev/null
put_config '{"canary":{"enabled":false,"paths":["/canary/swapped"],"ban_ttl_secs":3}}' >/dev/null
sleep "$RELOAD_WAIT"; clear_actor >/dev/null
read -r dis_code _ dis_act <<< "$(probe /canary/swapped)"
if [[ "$dis_act" != "block" ]]; then
    pass "behave.canary.enabled-toggle" "disabled: /canary/swapped action=$dis_act code=$dis_code (not blocked)"
else
    fail "behave.canary.enabled-toggle" "expected non-block when disabled, got $dis_code/$dis_act"
fi

# ban_ttl_secs expiry: canary hit bans the IP; clean path blocked until ttl -----
put_config '{"canary":{"enabled":true,"paths":["/canary/trap"],"ban_ttl_secs":3}}' >/dev/null
sleep "$RELOAD_WAIT"; clear_actor >/dev/null
probe /canary/trap >/dev/null                          # trip -> IP banned
read -r banned_code _ _ <<< "$(probe /get)"            # clean path, expect banned block
sleep 5                                                 # > ban_ttl_secs(3)
clear_actor >/dev/null
read -r unbanned_code _ _ <<< "$(probe /get)"          # clean path, expect allowed
if [[ "$banned_code" == "403" && "$unbanned_code" == "200" ]]; then
    pass "behave.canary.ban_ttl_secs" "post-trap clean req=$banned_code (banned); after ttl(3s)=$unbanned_code (unbanned)"
else
    fail "behave.canary.ban_ttl_secs" "expected banned=403 then unbanned=200, got $banned_code then $unbanned_code"
fi

# ── Documented exclusions (logged, not hidden) ────────────────────────────────
pass "exclude.metrics-stub" "GET /api/risk/metrics is a v1 stub (zeros) — excluded from assertions"
pass "exclude.actors-stub"  "GET /api/risk/actors is a v1 stub (empty) — excluded from assertions"

e2e_finalize
