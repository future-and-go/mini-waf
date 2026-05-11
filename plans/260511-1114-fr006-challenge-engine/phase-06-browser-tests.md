---
phase: 6
title: "Browser Tests"
status: completed
priority: P2
effort: "0.5d"
dependencies: [1, 2, 3, 4, 5]
---

# Phase 6: Browser Tests

## Overview

Playwright-based browser tests to verify the challenge page works in real browsers. Tests JS PoW solver, cookie setting, and redirect flow.

## Requirements

**Functional:**
- Real browser solves PoW and gets redirected
- NoScript shows block message
- Mobile browsers compatible (iOS Safari, Android Chrome)

**Non-functional:**
- Tests complete in < 30 seconds each
- Tests isolated (fresh browser context per test)

## Related Code Files

**Create:**
- `tests/e2e/challenge.spec.ts` (Playwright)
- `tests/e2e/fixtures/challenge-server.ts` (test server)

**Reference:**
- Existing Playwright config if present

## Implementation Steps

### Step 1: Setup Playwright if not present

```bash
# In project root
npm init playwright@latest --yes
# Or if using existing package.json:
npm install -D @playwright/test
npx playwright install chromium firefox webkit
```

### Step 2: Create test server fixture

```typescript
// tests/e2e/fixtures/challenge-server.ts
import { spawn, ChildProcess } from 'child_process';
import { promisify } from 'util';

const sleep = promisify(setTimeout);

let serverProcess: ChildProcess | null = null;

export async function startTestServer(): Promise<string> {
  // Start WAF in test mode with challenge always triggered
  serverProcess = spawn('./target/release/prx-waf', [
    '--config', 'tests/e2e/fixtures/test-config.toml',
    '--test-mode',
  ], {
    env: {
      ...process.env,
      CHALLENGE_FORCE_TRIGGER: 'true',
    },
  });
  
  // Wait for server to be ready
  for (let i = 0; i < 30; i++) {
    try {
      const res = await fetch('http://localhost:16880/health');
      if (res.ok) return 'http://localhost:16880';
    } catch {}
    await sleep(100);
  }
  throw new Error('Server failed to start');
}

export async function stopTestServer(): Promise<void> {
  if (serverProcess) {
    serverProcess.kill();
    serverProcess = null;
  }
}
```

### Step 3: Create challenge browser tests

```typescript
// tests/e2e/challenge.spec.ts
import { test, expect, Page } from '@playwright/test';

test.describe('Challenge Engine E2E', () => {
  
  test('solves JS challenge and gets redirected', async ({ page }) => {
    // Navigate to a route that triggers challenge
    const response = await page.goto('http://localhost:16880/challenge-test');
    
    // Should get challenge page initially
    expect(response?.status()).toBe(429);
    await expect(page.locator('h1')).toContainText('Security Check');
    
    // Wait for PoW to solve (spinner should be visible)
    await expect(page.locator('.s')).toBeVisible();
    
    // Wait for redirect (PoW solving + redirect)
    await page.waitForURL('**/challenge-test', { timeout: 10000 });
    
    // Should now see actual content (not challenge page)
    const finalResponse = await page.goto('http://localhost:16880/challenge-test');
    expect(finalResponse?.status()).toBe(200);
    
    // Cookie should be set
    const cookies = await page.context().cookies();
    const wafCookie = cookies.find(c => c.name === '__waf_cc');
    expect(wafCookie).toBeDefined();
    expect(wafCookie?.sameSite).toBe('Strict');
  });
  
  test('shows NoScript message when JS disabled', async ({ browser }) => {
    // Create context with JS disabled
    const context = await browser.newContext({ javaScriptEnabled: false });
    const page = await context.newPage();
    
    await page.goto('http://localhost:16880/challenge-test');
    
    // Should show NoScript block message
    await expect(page.locator('noscript')).toBeVisible();
    await expect(page.locator('noscript')).toContainText('JavaScript Required');
    
    await context.close();
  });
  
  test('cookie bypass works on subsequent requests', async ({ page }) => {
    // First request triggers challenge
    await page.goto('http://localhost:16880/challenge-test');
    
    // Wait for redirect after solving
    await page.waitForURL('**/challenge-test', { timeout: 10000 });
    
    // Second request should bypass (cookie present)
    const start = Date.now();
    const response = await page.goto('http://localhost:16880/challenge-test');
    const elapsed = Date.now() - start;
    
    expect(response?.status()).toBe(200);
    // Should be fast (no PoW solving)
    expect(elapsed).toBeLessThan(1000);
  });
  
  test('different fingerprint cannot reuse cookie', async ({ browser }) => {
    // Get cookie from first browser
    const context1 = await browser.newContext();
    const page1 = await context1.newPage();
    await page1.goto('http://localhost:16880/challenge-test');
    await page1.waitForURL('**/challenge-test', { timeout: 10000 });
    
    const cookies = await context1.cookies();
    const wafCookie = cookies.find(c => c.name === '__waf_cc');
    
    // Try to use cookie in different context (different fingerprint)
    const context2 = await browser.newContext();
    if (wafCookie) {
      await context2.addCookies([{
        name: wafCookie.name,
        value: wafCookie.value,
        domain: 'localhost',
        path: '/',
      }]);
    }
    
    const page2 = await context2.newPage();
    const response = await page2.goto('http://localhost:16880/challenge-test');
    
    // Should still get challenge (fingerprint mismatch)
    expect(response?.status()).toBe(429);
    
    await context1.close();
    await context2.close();
  });
  
  test('handles concurrent challenge requests', async ({ browser }) => {
    const contexts = await Promise.all(
      Array.from({ length: 5 }, () => browser.newContext())
    );
    
    const results = await Promise.all(
      contexts.map(async (ctx, i) => {
        const page = await ctx.newPage();
        await page.goto(`http://localhost:16880/challenge-test?id=${i}`);
        await page.waitForURL('**/challenge-test**', { timeout: 15000 });
        return page.url();
      })
    );
    
    // All should complete successfully
    expect(results).toHaveLength(5);
    results.forEach((url, i) => {
      expect(url).toContain(`id=${i}`);
    });
    
    await Promise.all(contexts.map(ctx => ctx.close()));
  });
});

// Mobile browser tests
test.describe('Challenge Engine Mobile', () => {
  test.use({ viewport: { width: 375, height: 667 } }); // iPhone SE
  
  test('works on mobile viewport', async ({ page }) => {
    await page.goto('http://localhost:16880/challenge-test');
    
    // Challenge page should be responsive
    await expect(page.locator('.c')).toBeVisible();
    
    // Wait for solve and redirect
    await page.waitForURL('**/challenge-test', { timeout: 15000 });
    
    const response = await page.goto('http://localhost:16880/challenge-test');
    expect(response?.status()).toBe(200);
  });
});

test.describe('Challenge Engine Performance', () => {
  test('PoW solves within expected time', async ({ page }) => {
    const start = Date.now();
    
    await page.goto('http://localhost:16880/challenge-test');
    await page.waitForURL('**/challenge-test', { timeout: 10000 });
    
    const elapsed = Date.now() - start;
    
    // Should solve within 3 seconds (includes page load + redirect)
    expect(elapsed).toBeLessThan(3000);
    // But should take some time (PoW is real work)
    expect(elapsed).toBeGreaterThan(100);
  });
});
```

### Step 4: Add Playwright config

```typescript
// playwright.config.ts
import { defineConfig, devices } from '@playwright/test';

export default defineConfig({
  testDir: './tests/e2e',
  fullyParallel: true,
  forbidOnly: !!process.env.CI,
  retries: process.env.CI ? 2 : 0,
  workers: process.env.CI ? 1 : undefined,
  reporter: 'html',
  
  use: {
    baseURL: 'http://localhost:16880',
    trace: 'on-first-retry',
  },
  
  projects: [
    { name: 'chromium', use: { ...devices['Desktop Chrome'] } },
    { name: 'firefox', use: { ...devices['Desktop Firefox'] } },
    { name: 'webkit', use: { ...devices['Desktop Safari'] } },
  ],
  
  webServer: {
    command: './target/release/prx-waf --config tests/e2e/fixtures/test-config.toml',
    url: 'http://localhost:16880/health',
    reuseExistingServer: !process.env.CI,
    timeout: 30000,
  },
});
```

### Step 5: Create test config

```toml
# tests/e2e/fixtures/test-config.toml
[server]
http_port = 16880
https_port = 16843

[challenge]
force_trigger = true  # Always trigger challenge for testing
difficulty_override = 12  # Lower difficulty for faster tests

[backend]
url = "http://localhost:8080"
```

### Step 6: Add npm scripts

```json
{
  "scripts": {
    "test:e2e": "npx playwright test",
    "test:e2e:headed": "npx playwright test --headed",
    "test:e2e:ui": "npx playwright test --ui"
  }
}
```

## Success Criteria

- [ ] All Playwright tests pass on Chromium
- [ ] Tests pass on Firefox and WebKit
- [ ] NoScript test verifies block message
- [ ] Cookie bypass test confirms fast second request
- [ ] Concurrent test handles 5 simultaneous challenges
- [ ] Mobile viewport test passes
- [ ] PoW solves within 3 seconds

## Risk Assessment

| Risk | Mitigation |
|------|------------|
| Flaky tests due to timing | Use generous timeouts, retry on CI |
| Browser install issues | Pin Playwright version, cache browsers |
| Test server startup race | Use Playwright's webServer with health check |
| Fingerprint detection in test | May need to mock or use consistent test setup |
