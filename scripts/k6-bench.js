import http from "k6/http";
import { check, sleep } from "k6";
import { Rate, Trend } from "k6/metrics";

// ── Config ────────────────────────────────────────────────────────────────────
const TARGET = __ENV.TARGET_URL || "http://test-prx-waf:80";

// ── Custom metrics ────────────────────────────────────────────────────────────
const wafBlockRate  = new Rate("waf_block_rate");   // % requests blocked by WAF
const legitLatency  = new Trend("legit_latency_ms");
const attackLatency = new Trend("attack_latency_ms");

// ── Test stages ───────────────────────────────────────────────────────────────
export const options = {
  stages: [
    { duration: "30s", target: 10  },   // ramp up
    { duration: "60s", target: 100 },   // sustained load
    { duration: "30s", target: 200 },   // peak load
    { duration: "15s", target: 0   },   // ramp down
  ],
  thresholds: {
    http_req_duration:    ["p(95)<2000"],   // 95% requests < 2s
    http_req_failed:      ["rate<0.1"],     // error rate < 10%
    waf_block_rate:       ["rate>0"],       // WAF must block at least some attacks
  },
};

// ── Attack payloads (should be blocked by WAF) ────────────────────────────────
const ATTACKS = [
  // SQL Injection
  { path: "/rest/products/search?q=' OR '1'='1",            label: "SQLi-1" },
  { path: "/rest/products/search?q=1; DROP TABLE users--",   label: "SQLi-2" },
  // XSS
  { path: "/rest/products/search?q=<script>alert(1)</script>", label: "XSS-1" },
  { path: "/#/search?q=<img src=x onerror=alert(1)>",          label: "XSS-2" },
  // Path Traversal
  { path: "/ftp/../etc/passwd",                               label: "PathTraversal" },
  { path: "/assets/public/images/../../../../etc/shadow",     label: "PathTraversal-2" },
  // Command Injection
  { path: "/rest/products/search?q=`id`",                     label: "CMDi" },
];

// ── Legitimate traffic ────────────────────────────────────────────────────────
const LEGIT = [
  "/",
  "/rest/products/search?q=apple",
  "/rest/products/search?q=juice",
  "/api/Challenges",
];

export default function () {
  const isAttack = Math.random() < 0.3; // 30% traffic = attack payloads

  if (isAttack) {
    const attack = ATTACKS[Math.floor(Math.random() * ATTACKS.length)];
    const res = http.get(`${TARGET}${attack.path}`, {
      headers: { Host: "test-prx-waf" },
      tags:    { type: "attack", payload: attack.label },
    });

    const blocked = res.status === 403 || res.status === 400 || res.status === 429;
    wafBlockRate.add(blocked);
    attackLatency.add(res.timings.duration);

    check(res, {
      [`[${attack.label}] WAF responded`]: (r) => r.status !== 0,
    });
  } else {
    const path = LEGIT[Math.floor(Math.random() * LEGIT.length)];
    const res  = http.get(`${TARGET}${path}`, {
      headers: { Host: "test-prx-waf" },
      tags:    { type: "legit" },
    });

    legitLatency.add(res.timings.duration);
    check(res, {
      "legit request 200": (r) => r.status === 200 || r.status === 304,
    });
  }

  sleep(Math.random() * 0.5);
}
