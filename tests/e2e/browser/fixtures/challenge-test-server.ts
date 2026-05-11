/**
 * Minimal test server for browser challenge tests.
 *
 * Serves the same challenge page HTML as the Rust WAF engine,
 * allowing us to test JavaScript PoW solving, cookie setting,
 * and redirect behavior in real browsers.
 *
 * Run: npx tsx tests/e2e/browser/fixtures/challenge-test-server.ts
 */

import { createServer, IncomingMessage, ServerResponse } from 'http';
import { createHash } from 'crypto';

const PORT = 16880;

// Difficulty: number of leading hex zeros required
// 2 hex zeros = 8 bits = ~256 iterations avg (fast for tests)
// 4 hex zeros = 16 bits = ~65536 iterations avg (production)
const DIFFICULTY = 2;

// Simple token generator (matches Rust HmacSecret behavior)
function generateToken(): string {
  const timestamp = Date.now().toString();
  const random = Math.random().toString(36).substring(2);
  return createHash('sha256')
    .update(timestamp + random)
    .digest('hex')
    .substring(0, 32);
}

// Challenge page HTML template (matches Rust page_template.rs)
function renderChallengePage(token: string, difficulty: number, redirectUrl: string): string {
  const title = 'Security Check';
  const message = 'Verifying your browser...';

  return `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>${title}</title>
<style>
*{margin:0;padding:0;box-sizing:border-box}
body{font-family:system-ui,-apple-system,sans-serif;display:flex;align-items:center;justify-content:center;min-height:100vh;background:#f5f5f5}
.c{text-align:center;padding:2rem;max-width:400px}
.s{width:48px;height:48px;border:4px solid #e0e0e0;border-top-color:#333;border-radius:50%;animation:spin 1s linear infinite;margin:0 auto 1rem}
@keyframes spin{to{transform:rotate(360deg)}}
h1{font-size:1.25rem;margin-bottom:.5rem;color:#333}
p{color:#666;font-size:.875rem}
noscript .b{background:#fee;border:1px solid #fcc;padding:1rem;border-radius:4px;margin-top:1rem}
noscript h2{color:#c00;font-size:1rem;margin-bottom:.5rem}
</style>
</head>
<body>
<div class="c">
<div class="s"></div>
<h1>${title}</h1>
<p>${message}</p>
<noscript>
<div class="b">
<h2>JavaScript Required</h2>
<p>Please enable JavaScript to continue.</p>
</div>
</noscript>
</div>
<script>
(function(){
var t="${token}",d=${difficulty},r="${redirectUrl}";
function h(s){
var a=new Uint8Array(s.length);
for(var i=0;i<s.length;i++)a[i]=s.charCodeAt(i);
return crypto.subtle.digest("SHA-256",a).then(function(b){
return Array.from(new Uint8Array(b)).map(function(x){
return x.toString(16).padStart(2,"0")
}).join("")
})
}
function c(x,n){
for(var i=0;i<n;i++)if(x[i]!=="0")return false;
return true
}
function w(n){
h(t+n).then(function(x){
if(c(x,d)){
document.cookie="__waf_cc="+t+"."+n+";path=/;max-age=300;SameSite=Strict";
location.href=r
}else{
setTimeout(function(){w(n+1)},0)
}
})
}
w(0)
})();
</script>
</body>
</html>`;
}

// Track issued tokens and solved challenges
const issuedTokens = new Map<string, { ip: string; timestamp: number }>();
const solvedTokens = new Set<string>();

// Verify PoW solution
function verifyPow(token: string, nonce: string, difficulty: number): boolean {
  const hash = createHash('sha256')
    .update(token + nonce)
    .digest('hex');

  for (let i = 0; i < difficulty; i++) {
    if (hash[i] !== '0') return false;
  }
  return true;
}

// Parse __waf_cc cookie
function parseCookie(cookieHeader: string | undefined): { token: string; nonce: string } | null {
  if (!cookieHeader) return null;

  const cookies = cookieHeader.split(';').map((c) => c.trim());
  for (const cookie of cookies) {
    if (cookie.startsWith('__waf_cc=')) {
      const value = cookie.substring('__waf_cc='.length);
      const parts = value.split('.');
      if (parts.length === 2) {
        return { token: parts[0], nonce: parts[1] };
      }
    }
  }
  return null;
}

// Request handler
function handleRequest(req: IncomingMessage, res: ServerResponse): void {
  const url = new URL(req.url || '/', `http://localhost:${PORT}`);
  const clientIp = req.socket.remoteAddress || 'unknown';

  // Health check endpoint
  if (url.pathname === '/health') {
    res.writeHead(200, { 'Content-Type': 'text/plain' });
    res.end('OK');
    return;
  }

  // Check for valid challenge cookie
  const cookie = parseCookie(req.headers.cookie);
  if (cookie && issuedTokens.has(cookie.token)) {
    if (verifyPow(cookie.token, cookie.nonce, DIFFICULTY)) {
      // Valid solution - serve actual content
      solvedTokens.add(cookie.token);
      res.writeHead(200, { 'Content-Type': 'text/html' });
      res.end(`<!DOCTYPE html>
<html>
<head><title>Success</title></head>
<body>
<h1>Challenge Passed</h1>
<p>You successfully solved the PoW challenge.</p>
<p>Path: ${url.pathname}</p>
</body>
</html>`);
      return;
    }
  }

  // Issue new challenge
  const token = generateToken();
  issuedTokens.set(token, { ip: clientIp, timestamp: Date.now() });

  // Redirect URL preserves original path and query
  const redirectUrl = url.pathname + url.search;

  const html = renderChallengePage(token, DIFFICULTY, redirectUrl);

  res.writeHead(429, {
    'Content-Type': 'text/html',
    'Cache-Control': 'no-store',
  });
  res.end(html);
}

// Start server
const server = createServer(handleRequest);

server.listen(PORT, () => {
  console.log(`Challenge test server running on http://localhost:${PORT}`);
  console.log(`Difficulty: ${DIFFICULTY} leading zeros`);
  console.log('Press Ctrl+C to stop');
});

// Cleanup old tokens every minute
setInterval(() => {
  const now = Date.now();
  const maxAge = 5 * 60 * 1000; // 5 minutes

  for (const [token, data] of issuedTokens) {
    if (now - data.timestamp > maxAge) {
      issuedTokens.delete(token);
      solvedTokens.delete(token);
    }
  }
}, 60_000);
