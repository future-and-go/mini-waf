// =============================================================================
// k6 load test for mini-waf benchmarking
// =============================================================================
// Target: WAF reverse proxy at http://localhost:16880 (forwards to juice-shop)
//
// USAGE
//   # Default: 15-minute ramp 100 -> 15000 RPS
//   k6 run scripts/k6-benchmark-waf.js
//
//   # Pick a different scenario
//   SCENARIO=smoke    k6 run scripts/k6-benchmark-waf.js   # 30s sanity check
//   SCENARIO=baseline k6 run scripts/k6-benchmark-waf.js   # 5 min @ 500 rps
//   SCENARIO=ramp     k6 run scripts/k6-benchmark-waf.js   # 15 min, 100 -> 15k rps (default)
//   SCENARIO=stress   k6 run scripts/k6-benchmark-waf.js   # find breaking point
//   SCENARIO=spike    k6 run scripts/k6-benchmark-waf.js   # sudden burst then recover
//   SCENARIO=soak     k6 run scripts/k6-benchmark-waf.js   # 30 min stability @ 2k rps
//
//   # Tunables (all optional)
//   BASE_URL=http://localhost:16880
//   TARGET_RPS=20000          # peak rps for ramp/stress/spike
//   START_RPS=100             # starting rps for ramp
//   DURATION=15m              # total ramp duration (ramp scenario)
//   REQ_TIMEOUT=30s           # per-request timeout (default 30s)
//   PRE_VUS=1000              # preAllocatedVUs override (default 1000)
//   MAX_VUS=5000              # maxVUs override (default 5000)
//   REPORT_DIR=reports        # where to write HTML/JSON report (must exist)
//   REPORT_NAME=run1          # report file basename
//   STRICT_THRESHOLDS=1       # set to enable hard thresholds (default: soft)
//   HOST_HEADER=juice-shop    # override the Host: header sent to WAF (must
//                             # match a [[hosts]] entry in mini-waf config)
//   SKIP_PROBE=1              # bypass setup() reachability probe
//   SCENARIO=doctor           # run only the diagnostic probe (no load)
//
// PREREQUISITES
//   * mini-waf running: `podman-compose up -d` (ports 16880 / 16843 / 16827)
//   * juice-shop reachable as upstream
//   * mini-waf has a [[hosts]] entry whose `host` matches HOST_HEADER (or the
//     URL host k6 is hitting, e.g. "localhost"). Without this Pingora closes
//     the TCP connection with EOF as soon as it accepts it.
//   * macOS: `ulimit -n 65535` before running k6 to avoid fd exhaustion
//   * `mkdir -p reports` before run if you set REPORT_DIR=reports
// =============================================================================

import http from 'k6/http';
import { check, fail, sleep } from 'k6';
import { Trend, Counter, Rate } from 'k6/metrics';
import { randomItem } from 'https://jslib.k6.io/k6-utils/1.4.0/index.js';
import { textSummary } from 'https://jslib.k6.io/k6-summary/0.1.0/index.js';
import { htmlReport } from 'https://raw.githubusercontent.com/benc-uk/k6-reporter/main/dist/bundle.js';

// -----------------------------------------------------------------------------
// Configuration (env-driven)
// -----------------------------------------------------------------------------
const BASE_URL    = __ENV.BASE_URL    || 'http://localhost:16880';
const SCENARIO    = (__ENV.SCENARIO   || 'ramp').toLowerCase();
const TARGET_RPS  = parseInt(__ENV.TARGET_RPS || '15000', 10);
const START_RPS   = parseInt(__ENV.START_RPS  || '100',   10);
const DURATION    = __ENV.DURATION    || '15m';
const REQ_TIMEOUT = __ENV.REQ_TIMEOUT || '30s';
const PRE_VUS     = parseInt(__ENV.PRE_VUS    || '1000',  10);
const MAX_VUS     = parseInt(__ENV.MAX_VUS    || '5000',  10);
const REPORT_DIR  = (__ENV.REPORT_DIR || '.').replace(/\/$/, '');
const REPORT_NAME = __ENV.REPORT_NAME || `bench_${SCENARIO}`;
const STRICT      = __ENV.STRICT_THRESHOLDS === '1';
const HOST_HEADER = __ENV.HOST_HEADER || '';     // empty = use URL's authority
const SKIP_PROBE  = __ENV.SKIP_PROBE === '1';

// -----------------------------------------------------------------------------
// Custom metrics
// -----------------------------------------------------------------------------
const wafLatency     = new Trend('waf_latency_ms', true);
const wafTimeouts    = new Counter('waf_timeouts_total');
const wafErrors5xx   = new Counter('waf_errors_5xx_total');
const wafBlocked     = new Counter('waf_blocked_total');     // 403 from WAF rules
const wafConnFail    = new Counter('waf_conn_fail_total');   // status 0 (timeout/refused)
const wafSuccessRate = new Rate('waf_success_rate');

// -----------------------------------------------------------------------------
// Realistic juice-shop traffic mix (path, weight)
// -----------------------------------------------------------------------------
const TRAFFIC_MIX = [
    { path: '/',                                          weight: 20 },
    { path: '/assets/i18n/en.json',                       weight: 15 },
    { path: '/assets/public/images/JuiceShop_Logo.png',   weight: 10 },
    { path: '/api/Products',                              weight: 15 },
    { path: '/api/Quantitys',                             weight: 5  },
    { path: '/rest/admin/application-version',            weight: 5  },
    { path: '/rest/admin/application-configuration',      weight: 5  },
    { path: '/rest/products/search?q=apple',              weight: 10 },
    { path: '/rest/products/search?q=juice',              weight: 5  },
    { path: '/rest/captcha/',                             weight: 5  },
    { path: '/api/BasketItems',                           weight: 3  },
    { path: '/rest/user/whoami',                          weight: 2  },
];
const WEIGHTED_PATHS = TRAFFIC_MIX.flatMap(e => Array(e.weight).fill(e.path));

// -----------------------------------------------------------------------------
// Scenario builders
// -----------------------------------------------------------------------------
function rampScenario() {
    // Distribute the total DURATION across 5 stages: 15% warm, 20% ramp1,
    // 20% ramp2, 20% ramp3, 25% sustain. Caller controls total via DURATION.
    const totalSec = parseDurationSec(DURATION);
    const s = (pct) => `${Math.max(1, Math.round(totalSec * pct))}s`;
    const t = (pct) => Math.round(START_RPS + (TARGET_RPS - START_RPS) * pct);
    return {
        executor: 'ramping-arrival-rate',
        startRate: START_RPS,
        timeUnit: '1s',
        preAllocatedVUs: PRE_VUS,
        maxVUs: MAX_VUS,
        stages: [
            { duration: s(0.15), target: t(0.07) },  // warm-up to ~7% of peak
            { duration: s(0.20), target: t(0.33) },  // -> 33% of peak
            { duration: s(0.20), target: t(0.66) },  // -> 66% of peak
            { duration: s(0.20), target: t(1.00) },  // -> 100% of peak
            { duration: s(0.25), target: t(1.00) },  // sustain at peak
        ],
        gracefulStop: '30s',
    };
}

function smokeScenario() {
    return {
        executor: 'constant-arrival-rate',
        rate: 20, timeUnit: '1s',
        duration: '30s',
        preAllocatedVUs: 20, maxVUs: 50,
        gracefulStop: '5s',
    };
}

function baselineScenario() {
    return {
        executor: 'constant-arrival-rate',
        rate: 500, timeUnit: '1s',
        duration: '5m',
        preAllocatedVUs: 200, maxVUs: 1000,
        gracefulStop: '15s',
    };
}

function stressScenario() {
    // Find the breaking point: ramp aggressively beyond TARGET_RPS.
    return {
        executor: 'ramping-arrival-rate',
        startRate: 500, timeUnit: '1s',
        preAllocatedVUs: PRE_VUS, maxVUs: MAX_VUS,
        stages: [
            { duration: '2m', target: Math.round(TARGET_RPS * 0.5) },
            { duration: '3m', target: TARGET_RPS                    },
            { duration: '3m', target: Math.round(TARGET_RPS * 1.5) },
            { duration: '2m', target: Math.round(TARGET_RPS * 1.5) },
        ],
        gracefulStop: '30s',
    };
}

function spikeScenario() {
    return {
        executor: 'ramping-arrival-rate',
        startRate: 100, timeUnit: '1s',
        preAllocatedVUs: PRE_VUS, maxVUs: MAX_VUS,
        stages: [
            { duration: '30s', target: 100         },
            { duration: '10s', target: TARGET_RPS  }, // sudden spike
            { duration: '2m',  target: TARGET_RPS  }, // hold
            { duration: '10s', target: 100         }, // sudden drop
            { duration: '1m',  target: 100         }, // recovery
        ],
        gracefulStop: '15s',
    };
}

function soakScenario() {
    return {
        executor: 'constant-arrival-rate',
        rate: 2000, timeUnit: '1s',
        duration: '30m',
        preAllocatedVUs: 600, maxVUs: 3000,
        gracefulStop: '30s',
    };
}

function doctorScenario() {
    // No load. Just runs the default fn once via per-vu-iterations so the
    // setup probe + handleSummary still execute. Useful to verify routing.
    return {
        executor: 'per-vu-iterations',
        vus: 1, iterations: 1, maxDuration: '10s',
    };
}

const SCENARIOS = {
    smoke:    smokeScenario,
    baseline: baselineScenario,
    ramp:     rampScenario,
    stress:   stressScenario,
    spike:    spikeScenario,
    soak:     soakScenario,
    doctor:   doctorScenario,
};

function pickScenario() {
    const builder = SCENARIOS[SCENARIO];
    if (!builder) {
        fail(`Unknown SCENARIO="${SCENARIO}". Valid: ${Object.keys(SCENARIOS).join(', ')}`);
    }
    return { [SCENARIO]: builder() };
}

// k6's goja runtime lacks the WHATWG URL constructor. This minimal parser
// only needs to extract { host, hostname, port } from typical benchmark URLs
// like "http://localhost:16880" or "https://example.com:8443/path".
function parseUrl(u) {
    const m = /^https?:\/\/([^/:]+)(?::(\d+))?(?:\/.*)?$/i.exec(u);
    if (!m) fail(`Invalid BASE_URL: ${u}`);
    const hostname = m[1];
    const port     = m[2] || '';
    const host     = port ? `${hostname}:${port}` : hostname;
    return { hostname, port, host };
}

function parseDurationSec(d) {
    // Accept "15m", "90s", "1h30m", "2h"
    const re = /(\d+)\s*(h|m|s)/g;
    let total = 0, m;
    while ((m = re.exec(d)) !== null) {
        const n = parseInt(m[1], 10);
        total += m[2] === 'h' ? n * 3600 : m[2] === 'm' ? n * 60 : n;
    }
    if (total === 0) fail(`Invalid DURATION="${d}"`);
    return total;
}

// -----------------------------------------------------------------------------
// k6 options
// -----------------------------------------------------------------------------
const softThresholds = {
    http_req_failed:                  [{ threshold: 'rate<0.10', abortOnFail: false }],
    http_req_duration:                [{ threshold: 'p(95)<2000', abortOnFail: false },
                                       { threshold: 'p(99)<5000', abortOnFail: false }],
    waf_success_rate:                 [{ threshold: 'rate>0.90', abortOnFail: false }],
    'http_req_duration{kind:static}': [{ threshold: 'p(99)<2000', abortOnFail: false }],
    'http_req_duration{kind:api}':    [{ threshold: 'p(99)<3000', abortOnFail: false }],
};

const strictThresholds = {
    http_req_failed:                  ['rate<0.05'],
    http_req_duration:                ['p(95)<500', 'p(99)<1500'],
    waf_success_rate:                 ['rate>0.95'],
    'http_req_duration{kind:static}': ['p(99)<300'],
    'http_req_duration{kind:api}':    ['p(99)<800'],
};

export const options = {
    discardResponseBodies: true,
    noConnectionReuse: false,
    insecureSkipTLSVerify: true,
    scenarios: pickScenario(),
    thresholds: STRICT ? strictThresholds : softThresholds,
    summaryTrendStats: ['avg', 'min', 'med', 'p(90)', 'p(95)', 'p(99)', 'max'],
    // Tag the run for easier filtering in time-series outputs (Prometheus/InfluxDB)
    tags: { test: 'mini-waf-bench', scenario: SCENARIO },
};

// -----------------------------------------------------------------------------
// Helpers
// -----------------------------------------------------------------------------
function classify(path) {
    if (path.startsWith('/api/') || path.startsWith('/rest/')) return 'api';
    if (path.startsWith('/assets/')) return 'static';
    return 'page';
}

// -----------------------------------------------------------------------------
// Main VU function
// -----------------------------------------------------------------------------
// Browser-like User-Agent to avoid being matched by bot-detection rules.
// k6's default `k6/v0.x.x` UA can be flagged as automated tooling (and the
// underlying Go HTTP client UA matches BOT-CRAWL-014). Use a current Chrome UA
// so the WAF sees us as a normal client.
const BROWSER_UA =
    'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 ' +
    '(KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36';

function buildHeaders() {
    const h = {
        'User-Agent':      __ENV.UA || BROWSER_UA,
        'Accept':          'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8',
        'Accept-Language': 'en-US,en;q=0.9',
        'Accept-Encoding': 'gzip, deflate',
        'Connection':      'keep-alive',
        'Cache-Control':   'no-cache',
        'Pragma':          'no-cache',
    };
    if (HOST_HEADER) h['Host'] = HOST_HEADER;
    return h;
}

export default function () {
    const path = randomItem(WEIGHTED_PATHS);
    const kind = classify(path);

    const res = http.get(`${BASE_URL}${path}`, {
        tags: { kind, endpoint: path },
        headers: buildHeaders(),
        timeout: REQ_TIMEOUT,
    });

    const ok = res.status >= 200 && res.status < 400;
    wafSuccessRate.add(ok);

    // Only record latency for completed requests; status=0 means transport
    // failure (timeout / refused / reset) and timing is meaningless.
    if (res.status > 0) {
        wafLatency.add(res.timings.duration, { kind });
    }

    if (res.status === 0) {
        wafConnFail.add(1, { endpoint: path });
        if (res.error && /timeout/i.test(res.error)) {
            wafTimeouts.add(1, { endpoint: path });
        }
    } else if (res.status === 403) {
        wafBlocked.add(1, { endpoint: path });
    } else if (res.status >= 500) {
        wafErrors5xx.add(1, { status: String(res.status), endpoint: path });
    }

    check(res, {
        'status is 2xx/3xx': () => ok,
    });
}

// -----------------------------------------------------------------------------
// Setup / teardown / summary
// -----------------------------------------------------------------------------
export function setup() {
    if (SKIP_PROBE) {
        console.log(`[setup] SKIP_PROBE=1 — bypassing reachability check`);
        return { baseUrl: BASE_URL, scenario: SCENARIO, startedAt: new Date().toISOString() };
    }

    // Doctor-style probe: try multiple Host header candidates so we can tell
    // the user *why* the WAF is closing the connection. Pingora returns EOF
    // (status=0) when no [[hosts]] entry matches the incoming Host header.
    // NOTE: k6's goja runtime does not expose the WHATWG `URL` constructor,
    // so we parse the authority with a regex instead.
    const url   = parseUrl(BASE_URL);
    const hosts = HOST_HEADER
        ? [HOST_HEADER]
        : Array.from(new Set([url.host, url.hostname, 'localhost', '127.0.0.1', 'juice-shop']));

    console.log(`[probe] base=${BASE_URL} candidates=${hosts.join(',')}`);

    // Retry each host up to 3 times with backoff. After a heavy previous run
    // the WAF connection pool may take a few seconds to drain TIME_WAIT/FIN
    // sockets, so the very first probe often gets EOF even when the WAF is
    // healthy (browser already works).
    let firstOk = null;
    const lines = [];
    for (const h of hosts) {
        let result = null;
        for (let attempt = 1; attempt <= 3; attempt++) {
            result = http.get(`${BASE_URL}/`, {
                timeout: '10s',
                headers: { ...buildHeaders(), 'Host': h },
                tags: { probe: '1' },
            });
            if (result.status > 0) break;
            sleep(2);
        }
        const tag = `Host=${h.padEnd(20)} status=${result.status} bytes=${(result.body || '').length} err=${result.error || '-'}`;
        lines.push(`  ${tag}`);
        if (result.status > 0 && firstOk === null) firstOk = h;
    }

    console.log(`[probe] results:\n${lines.join('\n')}`);

    if (firstOk === null) {
        const hint = [
            '',
            'DIAGNOSIS: mini-waf accepted the TCP connection but closed it without',
            'sending an HTTP response (status=0 / EOF) for ALL Host headers tried.',
            '',
            'POSSIBLE CAUSES:',
            '  1) No [[hosts]] route matches the Host header (most common on fresh',
            '     install). Add a route in configs/default.toml or via Admin UI.',
            '  2) Leftover TCP state from a previous high-RPS run still draining;',
            '     wait 30-60s and retry, or restart the container.',
            '  3) WAF bot rule blocking the User-Agent. Override with UA="..." env.',
            '',
            'IF THE BROWSER CAN OPEN http://localhost:16880/ FINE:',
            '  → The WAF is healthy. Just bypass this probe:',
            '       SKIP_PROBE=1 k6 run scripts/k6-benchmark-waf.js',
            '',
            'TO ADD A HOST ROUTE (configs/default.toml):',
            '       [[hosts]]',
            '       host = "localhost"',
            '       port = 80',
            '       remote_host = "host.docker.internal"   # or juice-shop service',
            '       remote_port = 3000',
            '       guard_status = true',
            '  Then: podman-compose restart prx-waf',
            '',
        ].join('\n');
        fail(`Cannot reach WAF at ${BASE_URL} for any Host candidate.${hint}`);
    }

    if (!HOST_HEADER && firstOk !== url.host) {
        console.warn(`[probe] URL Host "${url.host}" failed but "${firstOk}" works.`);
        console.warn(`[probe] Re-run with HOST_HEADER=${firstOk} for accurate routing.`);
    }

    console.log(`[setup] scenario=${SCENARIO} target=${TARGET_RPS}rps base=${BASE_URL} workingHost=${firstOk}`);
    console.log(`[setup] reports will be written to ${REPORT_DIR}/${REPORT_NAME}.{html,json,txt}`);
    return {
        baseUrl: BASE_URL, scenario: SCENARIO,
        workingHost: firstOk, startedAt: new Date().toISOString(),
    };
}

export function teardown(data) {
    console.log(`[teardown] scenario=${data.scenario} startedAt=${data.startedAt} target=${data.baseUrl}`);
}

export function handleSummary(data) {
    const base = `${REPORT_DIR}/${REPORT_NAME}`;
    const out = {
        stdout: textSummary(data, { indent: '  ', enableColors: true }),
    };
    out[`${base}.html`] = htmlReport(data);
    out[`${base}.json`] = JSON.stringify(data, null, 2);
    out[`${base}.txt`]  = textSummary(data, { indent: '  ', enableColors: false });
    return out;
}
