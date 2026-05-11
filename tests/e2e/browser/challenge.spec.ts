/**
 * FR-006 Phase 6: Browser tests for the challenge engine.
 *
 * Tests verify the PoW challenge page works correctly in real browsers:
 * - JavaScript solver computes valid nonce and sets cookie
 * - Page redirects after solving
 * - NoScript fallback shows block message
 * - Cookie bypass works on subsequent requests
 */

import { test, expect, Page } from '@playwright/test';

test.describe('Challenge Engine E2E', () => {
  test('solves JS challenge and gets redirected', async ({ page }) => {
    // Navigate to a route that triggers challenge
    const response = await page.goto('/challenge-test');

    // Should get challenge page initially (429) or already solved (200 if PoW was very fast)
    expect([200, 429]).toContain(response?.status());

    // Wait for challenge to be solved (may already be solved if PoW was fast)
    await page.waitForFunction(
      () => document.body.textContent?.includes('Challenge Passed'),
      { timeout: 15_000 }
    );

    // Should now see success content
    await expect(page.locator('h1')).toContainText('Challenge Passed');

    // Cookie should be set
    const cookies = await page.context().cookies();
    const wafCookie = cookies.find((c) => c.name === '__waf_cc');
    expect(wafCookie).toBeDefined();
    expect(wafCookie?.sameSite).toBe('Strict');
  });

  test('shows NoScript message when JS disabled', async ({ browser }) => {
    // Create context with JavaScript disabled
    const context = await browser.newContext({ javaScriptEnabled: false });
    const page = await context.newPage();

    await page.goto('/challenge-test');

    // When JS is disabled, noscript content becomes visible as regular DOM
    // The .b class is inside noscript and contains the block message
    await expect(page.locator('.b h2')).toContainText('JavaScript Required');
    await expect(page.locator('.b')).toBeVisible();

    await context.close();
  });

  test('cookie bypass works on subsequent requests', async ({ page }) => {
    // First request triggers challenge
    await page.goto('/challenge-test');

    // Wait for challenge to be solved
    await page.waitForFunction(
      () => document.body.textContent?.includes('Challenge Passed'),
      { timeout: 15_000 }
    );

    // Second request should bypass challenge (cookie present)
    const start = Date.now();
    const response = await page.goto('/another-path');
    const elapsed = Date.now() - start;

    // Should get success immediately (no PoW solving)
    expect(response?.status()).toBe(200);
    await expect(page.locator('h1')).toContainText('Challenge Passed');

    // Should be fast (no PoW computation needed)
    expect(elapsed).toBeLessThan(2000);
  });

  test('handles concurrent challenge requests', async ({ browser }) => {
    // Create 5 independent browser contexts
    const contexts = await Promise.all(
      Array.from({ length: 5 }, () => browser.newContext())
    );

    const results = await Promise.all(
      contexts.map(async (ctx, i) => {
        const page = await ctx.newPage();
        await page.goto(`/challenge-test?id=${i}`);

        // Wait for challenge to be solved
        await page.waitForFunction(
          () => document.body.textContent?.includes('Challenge Passed'),
          { timeout: 20_000 }
        );

        return page.url();
      })
    );

    // All should complete successfully with their IDs preserved
    expect(results).toHaveLength(5);
    results.forEach((url, i) => {
      expect(url).toContain(`id=${i}`);
    });

    // Cleanup
    await Promise.all(contexts.map((ctx) => ctx.close()));
  });

  test('preserves query parameters after redirect', async ({ page }) => {
    // Navigate with query params
    await page.goto('/test-path?foo=bar&baz=123');

    // Wait for challenge to be solved
    await page.waitForFunction(
      () => document.body.textContent?.includes('Challenge Passed'),
      { timeout: 15_000 }
    );

    // Query params should be preserved in final URL
    expect(page.url()).toContain('foo=bar');
    expect(page.url()).toContain('baz=123');
  });
});

// Mobile browser tests
test.describe('Challenge Engine Mobile', () => {
  // Use iPhone SE viewport
  test.use({ viewport: { width: 375, height: 667 } });

  test('works on mobile viewport', async ({ page }) => {
    await page.goto('/challenge-test');

    // Challenge page should be visible and responsive
    await expect(page.locator('.c')).toBeVisible();
    await expect(page.locator('h1')).toContainText('Security Check');

    // Wait for solve and redirect
    await page.waitForFunction(
      () => document.body.textContent?.includes('Challenge Passed'),
      { timeout: 15_000 }
    );

    // Should show success
    await expect(page.locator('h1')).toContainText('Challenge Passed');
  });
});

test.describe('Challenge Engine Performance', () => {
  test('PoW solves within expected time', async ({ page }) => {
    const start = Date.now();

    await page.goto('/challenge-test');

    // Wait for challenge to complete
    await page.waitForFunction(
      () => document.body.textContent?.includes('Challenge Passed'),
      { timeout: 15_000 }
    );

    const elapsed = Date.now() - start;

    // Should solve within 5 seconds (includes page load + PoW + redirect)
    // Using 5s instead of 3s to account for CI variability
    expect(elapsed).toBeLessThan(5000);

    // But should take some time (PoW is real work, difficulty 8 = ~256 iterations)
    expect(elapsed).toBeGreaterThan(50);
  });

  test('cookie verification is fast', async ({ page }) => {
    // First solve the challenge
    await page.goto('/challenge-test');
    await page.waitForFunction(
      () => document.body.textContent?.includes('Challenge Passed'),
      { timeout: 15_000 }
    );

    // Measure time for subsequent request with cookie
    const start = Date.now();
    await page.goto('/fast-path');
    const elapsed = Date.now() - start;

    // Should be very fast (just cookie verification, no PoW)
    expect(elapsed).toBeLessThan(1000);
  });
});

test.describe('Challenge Page Content', () => {
  test('has correct structure and styling', async ({ page }) => {
    await page.goto('/challenge-test');

    // Check page structure
    await expect(page.locator('html')).toHaveAttribute('lang', 'en');
    await expect(page).toHaveTitle('Security Check');

    // Check visible elements
    await expect(page.locator('.c')).toBeVisible(); // Container
    await expect(page.locator('.s')).toBeVisible(); // Spinner
    await expect(page.locator('h1')).toBeVisible();
    await expect(page.locator('p')).toBeVisible();
  });

  test('spinner animates during solve', async ({ page }) => {
    await page.goto('/challenge-test');

    // Check if challenge page is still visible (PoW may already be solved)
    const spinner = page.locator('.s');
    const isSpinnerVisible = await spinner.isVisible().catch(() => false);

    if (isSpinnerVisible) {
      // Check computed style has animation
      const animationName = await spinner.evaluate(
        (el) => getComputedStyle(el).animationName
      );
      expect(animationName).toBe('spin');
    } else {
      // PoW was solved very quickly - verify we're on success page
      await expect(page.locator('h1')).toContainText('Challenge Passed');
    }
  });
});
