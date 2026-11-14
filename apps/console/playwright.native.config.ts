import { defineConfig } from '@playwright/test';

export default defineConfig({
  testDir: './tests/browser',
  testMatch: 'live.spec.ts',
  workers: 1,
  fullyParallel: false,
  timeout: 90_000,
  expect: { timeout: 10_000 },
  reporter: [['list'], ['json', { outputFile: process.env.FG_CONSOLE_BROWSER_REPORT || 'artifacts/native-results.json' }]],
  use: {
    baseURL: process.env.FG_CONSOLE_LIVE_URL,
    viewport: { width: 1366, height: 900 }, locale: 'en-US',
    trace: 'off', screenshot: 'off', video: 'off'
  },
  projects: [{ name: 'chromium', use: { browserName: 'chromium' } }]
});
