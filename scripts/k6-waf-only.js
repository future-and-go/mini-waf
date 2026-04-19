// =============================================================================
// k6 WAF-only benchmark — A/B comparison: through-WAF vs direct upstream
// =============================================================================
// Goal: measure the *pure* overhead of mini-waf (rules, logging, proxy) by
// comparing latency/throughput against an identical upstream accessed
// directly. The upstream is a tiny nginx that returns canned responses, so
// it is never the bottleneck — any difference between paths is attributable
// to the WAF.
//
// PREREQUISITES
//   * mini-waf running, host route: localhost:80 → static-upstream:80
//   * static-upstream container reachable on host port 18080 (bypass path)
//   * Run scripts/setup-waf-only.sh first (see README at top of this file)
//
// USAGE
//   # 30s smoke
//   PROFILE=smoke k6 run scripts/k6-waf-only.js
//
//   # default: ramp 100 -> 5000 RPS for 5 min, both paths in parallel
//   k6 run scripts/k6-waf-only.js
//
//   # 10k RPS, clean traffic only
//   TARGET_RPS=10000 DURATION=5m k6 run scripts/k6-waf-only.js
//
//   # Attack traffic (paths/UAs that trigger WAF rules) to measure rule cost
//   TRAFFIC=attack TARGET_RPS=2000 k6 run scripts/k6-waf-only.js
//
// ENV
//   WAF_URL          default http://localhost:16880
//   DIRECT_URL       default http://localhost:18080
//   TARGET_RPS       default 5000   — peak rps PER PATH (so total = 2x)
//   START_RPS        default 100
//   DURATION         default 5m     — total ramp duration
//   REQ_TIMEOUT      default 30s
//   PRE_VUS          default 500
//   MAX_VUS          default 3000
//   PROFILE          default ramp   — smoke | constant | ramp
//   TRAFFIC          default clean  — clean | attack | mixed
//   REPORT_DIR       default reports
//   REPORT_NAME      default waf_only_<traffic>_<rps>
// =============================================================================

import http from 'k6/http';
import { check, fail } from 'k6';
import { Trend, Counter, Rate } from 'k6/metrics';
import { randomItem } from 'https://jslib.k6.io/k6-utils/1.4.0/index.js';
import { textSummary } from 'https://jslib.k6.io/k6-summary/0.1.0/index.js';
import { htmlReport } from 'https://raw.githubusercontent.com/benc-uk/k6-reporter/main/dist/bundle.js';

// -----------------------------------------------------------------------------
// Configuration
// -----------------------------------------------------------------------------
const WAF_URL     = __ENV.WAF_URL     || 'http://localhost:16880';
const DIRECT_URL  = __ENV.DIRECT_URL  || 'http://localhost:18080';
const TARGET_RPS  = parseInt(__ENV.TARGET_RPS || '5000', 10);
const START_RPS   = parseInt(__ENV.START_RPS  || '100',  10);
const DURATION    = __ENV.DURATION    || '5m';
const REQ_TIMEOUT = __ENV.REQ_TIMEOUT || '30s';
const PRE_VUS     = parseInt(__ENV.PRE_VUS    || '500',  10);
const MAX_VUS     = parseInt(__ENV.MAX_VUS    || '3000', 10);
const PROFILE     = (__ENV.PROFILE || 'ramp').toLowerCase();
const TRAFFIC     = (__ENV.TRAFFIC || 'clean').toLowerCase();
const REPORT_DIR  = (__ENV.REPORT_DIR  || 'reports').replace(/\/$/, '');
const REPORT_NAME = __ENV.REPORT_NAME || `waf_only_${TRAFFIC}_${TARGET_RPS}`;

// -----------------------------------------------------------------------------
// Custom metrics — tagged by `path` so we can compare in summary
// -----------------------------------------------------------------------------
const wafLatency    = new Trend('waf_latency_ms', true);     // through WAF
const directLatency = new Trend('direct_latency_ms', true);  // bypass WAF
const wafErrors     = new Counter('waf_errors_total');
const directErrors  = new Counter('direct_errors_total');
const wafBlocked    = new Counter('waf_blocked_total');      // 403 from rules
const wafSuccess    = new Rate('waf_success_rate');
const directSuccess = new Rate('direct_success_rate');

// -----------------------------------------------------------------------------
// Traffic profiles
// -----------------------------------------------------------------------------
//   clean   — paths/UAs that should NOT trigger any WAF rule
//   attack  — paths/UAs/headers crafted to trigger WAF rules (worst case for
//             rule engine: every request is fully evaluated and likely blocked)
//   mixed   — 80% clean + 20% attack (realistic production-like)
const CLEAN_PATHS = [
    '/',
    '/api/Products',
    '/api/Quantitys',
    '/api/BasketItems',
    '/rest/admin/application-version',
    '/rest/admin/application-configuration',
    '/rest/products/search?q=apple',
    '/rest/products/search?q=juice',
    '/rest/user/whoami',
    '/assets/i18n/en.json',
    '/assets/public/images/JuiceShop_Logo.png',
];

const ATTACK_PATHS = [
    "/?id=1' OR '1'='1",
    '/api/Products?id=1%20UNION%20SELECT%20*%20FROM%20users--',
    '/rest/products/search?q=<script>alert(1)</script>',
    '/admin/../../etc/passwd',
    '/wp-admin/login.php',
    '/.env',
    '/?cmd=cat%20/etc/passwd',
    '/api/Users?filter[where][role]=admin',
    '/?xss=<img%20src=x%20onerror=alert(1)>',
    '/redirect?url=http://evil.com/phish',
];

const ATTACK_UAS = [
    'sqlmap/1.7.2#stable (https://sqlmap.org)',
    'Nikto/2.5.0',
    'Mozilla/5.0 sqlmap',
    '() { :; }; /bin/bash -c "echo vulnerable"',
    'masscan/1.3',
    'curl/7.68.0',
    'python-requests/2.28.1',
    'WPScan v3.8.22',
];

const BROWSER_UA =
    'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 ' +
    '(KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36';

function pickPath() {
    if (TRAFFIC === 'attack')                       return randomItem(ATTACK_PATHS);
    if (TRAFFIC === 'mixed' && Math.random() < 0.2) return randomItem(ATTACK_PATHS);
    return randomItem(CLEAN_PATHS);
}

function pickUA(isAttackPath) {
    if (TRAFFIC === 'attack')                          return randomItem(ATTACK_UAS);
    if (TRAFFIC === 'mixed' && isAttackPath)           return randomItem(ATTACK_UAS);
    return BROWSER_UA;
}

// -----------------------------------------------------------------------------
// Scenario builders — we ALWAYS run two scenarios in parallel (via_waf + direct)
// so both paths see the exact same request rate at the same time. This makes
// the A/B latency delta directly comparable.
// -----------------------------------------------------------------------------
function rampStages(totalSec) {
    const s = (pct) => `${Math.max(1, Math.round(totalSec * pct))}s`;
    const t = (pct) => Math.round(START_RPS + (TARGET_RPS - START_RPS) * pct);
    return [
        { duration: s(0.15), target: t(0.07) },
        { duration: s(0.20), target: t(0.33) },
        { duration: s(0.20), target: t(0.66) },
        { duration: s(0.20), target: t(1.00) },
        { duration: s(0.25), target: t(1.00) },
    ];
}

function parseDurationSec(d) {
    const re = /(\d+)\s*(h|m|s)/g;
    let total = 0, m;
    while ((m = re.exec(d)) !== null) {
        const n = parseInt(m[1], 10);
        total += m[2] === 'h' ? n * 3600 : m[2] === 'm' ? n * 60 : n;
    }
    if (total === 0) fail(`Invalid DURATION="${d}"`);
    return total;
}

function buildScenario(exec, env) {
    const totalSec = parseDurationSec(DURATION);
    const common = {
        executor: 'ramping-arrival-rate',
        startRate: START_RPS,
        timeUnit: '1s',
        preAllocatedVUs: PRE_VUS,
        maxVUs: MAX_VUS,
        env: { ...env },
        gracefulStop: '30s',
        exec,
    };

    if (PROFILE === 'smoke') {
        return {
            ...common,
            executor: 'constant-arrival-rate',
            rate: 50, duration: '30s',
            preAllocatedVUs: 50, maxVUs: 100,
        };
    }
    if (PROFILE === 'constant') {
        return {
            ...common,
            executor: 'constant-arrival-rate',
            rate: TARGET_RPS, duration: DURATION,
        };
    }
    return { ...common, stages: rampStages(totalSec) };
}

export const options = {
    discardResponseBodies: true,
    noConnectionReuse: false,
    insecureSkipTLSVerify: true,
    scenarios: {
        via_waf: buildScenario('viaWaf', { TARGET: 'waf' }),
        direct:  buildScenario('direct', { TARGET: 'direct' }),
    },
    // SOFT thresholds — we want the run to complete to gather full data.
    thresholds: {
        // Sanity gates only; real analysis is in the comparison summary.
        'http_req_failed{path:via_waf}': [{ threshold: 'rate<0.20', abortOnFail: false }],
        'http_req_failed{path:direct}':  [{ threshold: 'rate<0.05', abortOnFail: false }],
        'waf_success_rate':              [{ threshold: 'rate>0.80', abortOnFail: false }],
        'direct_success_rate':           [{ threshold: 'rate>0.95', abortOnFail: false }],
    },
    summaryTrendStats: ['avg', 'min', 'med', 'p(90)', 'p(95)', 'p(99)', 'max'],
    tags: { test: 'waf-only-bench', traffic: TRAFFIC },
};

// -----------------------------------------------------------------------------
// VU functions
// -----------------------------------------------------------------------------
function commonHeaders(path) {
    const isAttack = TRAFFIC === 'attack' || ATTACK_PATHS.includes(path);
    return {
        'User-Agent':      pickUA(isAttack),
        'Accept':          'text/html,application/json,*/*;q=0.8',
        'Accept-Language': 'en-US,en;q=0.9',
        'Accept-Encoding': 'gzip, deflate',
        'Connection':      'keep-alive',
    };
}

export function viaWaf() {
    const path = pickPath();
    const res  = http.get(`${WAF_URL}${path}`, {
        tags: { path: 'via_waf', endpoint: path },
        headers: commonHeaders(path),
        timeout: REQ_TIMEOUT,
    });

    const ok = res.status >= 200 && res.status < 400;
    wafSuccess.add(ok);
    if (res.status > 0) wafLatency.add(res.timings.duration);

    if      (res.status === 0)   wafErrors.add(1, { reason: 'transport' });
    else if (res.status === 403) wafBlocked.add(1, { endpoint: path });
    else if (res.status >= 500)  wafErrors.add(1, { reason: '5xx' });

    check(res, { 'waf 2xx/3xx/403': () => ok || res.status === 403 });
}

export function direct() {
    const path = pickPath();
    const res  = http.get(`${DIRECT_URL}${path}`, {
        tags: { path: 'direct', endpoint: path },
        headers: commonHeaders(path),
        timeout: REQ_TIMEOUT,
    });

    const ok = res.status >= 200 && res.status < 400;
    directSuccess.add(ok);
    if (res.status > 0) directLatency.add(res.timings.duration);

    if (res.status === 0 || res.status >= 500) {
        directErrors.add(1, { reason: res.status === 0 ? 'transport' : '5xx' });
    }

    check(res, { 'direct 2xx/3xx': () => ok });
}

// -----------------------------------------------------------------------------
// Setup / Summary — A/B comparison printout
// -----------------------------------------------------------------------------
export function setup() {
    const wafProbe    = http.get(`${WAF_URL}/`,    { timeout: '10s', headers: { 'User-Agent': BROWSER_UA }});
    const directProbe = http.get(`${DIRECT_URL}/`, { timeout: '10s', headers: { 'User-Agent': BROWSER_UA }});

    if (wafProbe.status === 0) {
        fail(`WAF unreachable at ${WAF_URL} (err=${wafProbe.error}). Check container + host route.`);
    }
    if (directProbe.status === 0) {
        fail(`Direct upstream unreachable at ${DIRECT_URL} (err=${directProbe.error}). Start static-upstream container.`);
    }

    console.log(`[setup] WAF=${WAF_URL} status=${wafProbe.status} latency=${wafProbe.timings.duration.toFixed(2)}ms`);
    console.log(`[setup] DIRECT=${DIRECT_URL} status=${directProbe.status} latency=${directProbe.timings.duration.toFixed(2)}ms`);
    console.log(`[setup] PROFILE=${PROFILE} TRAFFIC=${TRAFFIC} TARGET_RPS=${TARGET_RPS}/path DURATION=${DURATION}`);
    console.log(`[setup] reports → ${REPORT_DIR}/${REPORT_NAME}.{html,json,txt}`);

    return { startedAt: new Date().toISOString() };
}

function fmt(n, suffix = 'ms') {
    if (n === undefined || n === null || isNaN(n)) return 'n/a';
    if (n < 10)     return `${n.toFixed(2)}${suffix}`;
    if (n < 1000)   return `${n.toFixed(1)}${suffix}`;
    return `${(n / 1000).toFixed(2)}s`;
}

function makeAbReport(data) {
    const m = data.metrics;
    const w = m['http_req_duration{path:via_waf}']?.values || {};
    const d = m['http_req_duration{path:direct}']?.values  || {};
    const wReqs = m['http_reqs{path:via_waf}']?.values?.count ?? 0;
    const dReqs = m['http_reqs{path:direct}']?.values?.count ?? 0;
    const wRate = m['http_reqs{path:via_waf}']?.values?.rate ?? 0;
    const dRate = m['http_reqs{path:direct}']?.values?.rate ?? 0;
    const wFail = m['http_req_failed{path:via_waf}']?.values?.rate ?? 0;
    const dFail = m['http_req_failed{path:direct}']?.values?.rate ?? 0;
    const blocked = m.waf_blocked_total?.values?.count ?? 0;
    const dropped = m.dropped_iterations?.values?.count ?? 0;

    const delta = (k) => {
        const wv = w[k], dv = d[k];
        if (wv == null || dv == null) return { abs: null, pct: null };
        return { abs: wv - dv, pct: dv > 0 ? ((wv - dv) / dv) * 100 : 0 };
    };

    const sep   = '─'.repeat(78);
    const lines = [];
    lines.push('');
    lines.push(sep);
    lines.push(`  WAF-ONLY BENCHMARK A/B REPORT (traffic=${TRAFFIC}, target=${TARGET_RPS} rps/path)`);
    lines.push(sep);
    lines.push('');
    lines.push('  Throughput');
    lines.push(`    via WAF :    ${wReqs.toLocaleString().padStart(10)} reqs   ${wRate.toFixed(1).padStart(8)} rps   fail=${(wFail*100).toFixed(2)}%`);
    lines.push(`    direct  :    ${dReqs.toLocaleString().padStart(10)} reqs   ${dRate.toFixed(1).padStart(8)} rps   fail=${(dFail*100).toFixed(2)}%`);
    lines.push(`    blocked by WAF rules: ${blocked.toLocaleString()} (403)`);
    lines.push(`    dropped iterations:   ${dropped.toLocaleString()} (k6 couldn't keep up)`);
    lines.push('');
    lines.push('  Latency comparison (http_req_duration)');
    lines.push('    Percentile   via WAF        direct         Δ absolute     Δ %');
    lines.push('    ─────────────────────────────────────────────────────────────────');
    for (const k of ['min', 'med', 'avg', 'p(90)', 'p(95)', 'p(99)', 'max']) {
        const dl = delta(k);
        const wv = w[k] != null ? fmt(w[k]) : 'n/a';
        const dv = d[k] != null ? fmt(d[k]) : 'n/a';
        const da = dl.abs != null ? fmt(dl.abs) : 'n/a';
        const dp = dl.pct != null ? `${dl.pct >= 0 ? '+' : ''}${dl.pct.toFixed(1)}%` : 'n/a';
        lines.push(`    ${k.padEnd(10)}   ${wv.padEnd(13)} ${dv.padEnd(13)}  ${da.padEnd(13)} ${dp}`);
    }
    lines.push('');
    lines.push('  Interpretation');
    lines.push('    Δ absolute  = pure WAF overhead (rules + logging + proxy)');
    lines.push('    Δ %         = relative cost — higher means WAF is amplifying upstream latency');
    lines.push('    If Δ p99 < 5ms and fail rate < 5%, the WAF is healthy at this load.');
    lines.push('');
    lines.push(sep);
    lines.push('');
    return lines.join('\n');
}

export function handleSummary(data) {
    const base = `${REPORT_DIR}/${REPORT_NAME}`;
    const ab   = makeAbReport(data);
    return {
        stdout: ab + textSummary(data, { indent: '  ', enableColors: true }),
        [`${base}.html`]: htmlReport(data),
        [`${base}.json`]: JSON.stringify(data, null, 2),
        [`${base}.txt`]:  ab + textSummary(data, { indent: '  ', enableColors: false }),
    };
}
