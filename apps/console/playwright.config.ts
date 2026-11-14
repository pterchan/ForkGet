import { defineConfig } from '@playwright/test';
export default defineConfig({
  testDir: './tests/browser',
  fullyParallel: false,
  workers: 1,
  timeout: 30_000,
  expect: { timeout: 6000 },
  reporter: [['list'], ['json', { outputFile: 'artifacts/browser-results.json' }]],
  use: { baseURL: 'http://127.0.0.1:4196', viewport: { width: 1366, height: 900 }, locale: 'en-US', trace: 'off', screenshot: 'off', video: 'off' },
  projects: [{ name: 'chromium', use: { browserName: 'chromium' } }],
  webServer: { command: 'npm run dev -- --port 4196', url: 'http://127.0.0.1:4196', reuseExistingServer: false }
});
