import { test, expect } from '@playwright/test';
import { localeCodes, resources } from '../../src/lib/locales';

test('a consumed one-use approval is translated and cannot be reviewed again', async ({ page }) => {
  const approval = { id: 71, policy_version: 3, table_id: 4, kind: 'update', rows: 1,
    state: 'consumed', expires_at: Math.floor(Date.now() / 1000) + 60 };
  await page.route('**/api/**', async route => {
    const path = new URL(route.request().url()).pathname;
    if (path === '/api/v1/branches') return route.fulfill({ json: [] });
    if (path === '/api/v1/branches/101/approvals') return route.fulfill({ json: { approvals: [approval] } });
    return route.fulfill({ status: 404, json: { code: 'FG-2001', message: 'Not found.' } });
  });
  await page.goto('/');
  await page.locator('#owner-token').fill('disposable-reviewer-token');
  await page.getByRole('button', { name: 'Connect deployment', exact: true }).click();
  await page.getByRole('link', { name: 'Review queue', exact: true }).click();
  await page.locator('#known-branch').fill('101');
  await page.getByRole('button', { name: 'Inspect branch', exact: true }).click();
  for (const code of localeCodes) {
    await page.locator('#locale-picker').selectOption(code);
    const words = resources[code].translation;
    await expect(page.locator('main table .badge')).toHaveText(words.consumed);
    await expect(page.locator('main table').getByRole('button', { name: words.approve, exact: true })).toBeDisabled();
    await expect(page.locator('main table').getByRole('button', { name: words.deny, exact: true })).toBeDisabled();
  }
});
