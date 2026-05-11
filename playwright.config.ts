import { defineConfig, devices } from '@playwright/test';

/**
 * Playwright configuration for PRX-WAF challenge engine browser tests.
 *
 * Tests verify the PoW challenge page works in real browsers:
 * - JavaScript solver computes valid nonce
 * - Cookie is set with correct attributes
 * - Redirect happens after solving
 * - NoScript fallback shows block message
 */
export default defineConfig({
  // Test files location - separate from shell-based e2e tests
  testDir: './tests/e2e/browser',

  // Run tests in parallel for speed
  fullyParallel: true,

  // Fail CI if test.only() is left in source code
  forbidOnly: !!process.env.CI,

  // Retry failed tests in CI for flakiness tolerance
  retries: process.env.CI ? 2 : 0,

  // Limit workers in CI to avoid resource contention
  workers: process.env.CI ? 1 : undefined,

  // Generate HTML report for debugging failed tests
  reporter: 'html',

  // Shared settings for all projects
  use: {
    // Base URL for page.goto() calls
    baseURL: 'http://localhost:16880',

    // Capture trace on first retry for debugging
    trace: 'on-first-retry',

    // Screenshot on failure
    screenshot: 'only-on-failure',
  },

  // Configure browser projects
  projects: [
    {
      name: 'chromium',
      use: { ...devices['Desktop Chrome'] },
    },
    {
      name: 'firefox',
      use: { ...devices['Desktop Firefox'] },
    },
    {
      name: 'webkit',
      use: { ...devices['Desktop Safari'] },
    },
  ],

  // Start challenge test server before running tests
  webServer: {
    // Use Node.js test server that serves challenge pages
    command: 'npx tsx tests/e2e/browser/fixtures/challenge-test-server.ts',

    // Wait for health endpoint to be available
    url: 'http://localhost:16880/health',

    // Reuse existing server in development (faster iteration)
    reuseExistingServer: !process.env.CI,

    // Server startup timeout
    timeout: 30_000,

    // Show server output for debugging
    stdout: 'pipe',
    stderr: 'pipe',
  },
});
