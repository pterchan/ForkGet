import { test, expect } from '@playwright/test';

test('current API keeps legacy layout, actual write access and authoritative expiry independent', async ({ page }) => {
  const branch = { id: 101, name: 'legacy-mongo', class: 'dev', generation_id: 12, created_by: 'alice',
    expires_at: Math.floor(Date.now() / 1000) + 3600, status: 'active', mode: 'read_only',
    access: 'read_write', layout: 'sparse_delta' };
  await page.route('**/api/**', async route => {
    const path = new URL(route.request().url()).pathname;
    let value: unknown;
    if (path === '/api/v1/branches') value = [branch];
    else if (path === '/api/v1/branches/101') value = branch;
    else if (path.endsWith('/status')) value = { ...branch, expired: true, lease_version: 2,
      snapshot_rows: '9007199254740993', lifecycle_phase: 'cleanup_retry', reason: 'native_cleanup_failed' };
    else if (path.endsWith('/policy')) value = { class: 'dev', version: 3, max_transaction_rows: 2000,
      table_limit_bps: null, approval_after_rows: null, small_table_floor: 10, effective_revision: 7 };
    else return route.fulfill({ status: 404, json: { code: 'FG-2001', message: 'Not found.' } });
    await route.fulfill({ json: value });
  });
  await page.goto('/');
  await page.locator('#owner-token').fill('disposable-token');
  await page.getByRole('button', { name: 'Connect deployment', exact: true }).click();
  await page.getByRole('link', { name: 'legacy-mongo', exact: true }).click();
  await expect(page.locator('.page-head .badge').first()).toHaveText('Expired');
  await expect(page.locator('#detail-panel .detail-metadata').first()).toContainText('Writable');
  await expect(page.locator('#detail-panel')).toContainText('Shared base + sparse delta');
  await expect(page.locator('#detail-panel')).toContainText('9007199254740993');
  await expect(page.locator('#detail-panel')).toContainText('cleanup_retry');
  await expect(page.locator('#detail-panel')).toContainText('Effective branch policy');
  await expect(page.locator('#detail-panel')).toContainText('2000');
  expect(await page.evaluate(() => JSON.stringify({ ...localStorage }))).not.toContain('disposable-token');
});

test('temporary policy expiry refreshes displayed limits without extending the branch lease', async ({ page }) => {
  const started = 1_900_000_000;
  await page.clock.install({ time: new Date((started - 60) * 1000) });
  await page.clock.pauseAt(new Date(started * 1000));
  const branch = { id: 102, name: 'short-grant', class: 'agent', generation_id: 12,
    created_by: 'alice', expires_at: started + 3600, status: 'active', mode: 'native_write',
    access: 'read_write', layout: 'native_copy' };
  let policyReads = 0;
  await page.route('**/api/**', async route => {
    const path = new URL(route.request().url()).pathname;
    let value: unknown;
    if (path === '/api/v1/branches') value = [branch];
    else if (path === '/api/v1/branches/102') value = branch;
    else if (path.endsWith('/status')) value = { ...branch, expired: false, lease_version: 1,
      snapshot_rows: 500, lifecycle_phase: null, reason: null };
    else if (path.endsWith('/policy')) {
      policyReads++;
      value = { class: 'agent', version: 3, max_transaction_rows: policyReads === 1 ? 2000 : 100,
        table_limit_bps: 2500, approval_after_rows: null, small_table_floor: 10,
        effective_revision: policyReads === 1 ? 7 : 8, grant_expires_at: policyReads === 1 ? started + 2 : null };
    } else return route.fulfill({ status: 404, json: { code: 'FG-2001', message: 'Not found.' } });
    await route.fulfill({ json: value });
  });
  await page.goto('/');
  await page.locator('#owner-token').fill('short-grant-token');
  await page.getByRole('button', { name: 'Connect deployment', exact: true }).click();
  await page.getByRole('link', { name: 'short-grant', exact: true }).click();
  const effective = page.locator('dl[aria-label="Effective branch policy"]');
  await expect(effective).toContainText('2000');
  await expect(effective).toContainText('2500');
  await expect(effective).toContainText('Temporary grant expires');
  await expect(effective).toContainText('Disabled');
  await page.clock.fastForward(4000);
  await expect(effective).toContainText('100');
  await expect(effective).not.toContainText('2000');
  await expect(effective).not.toContainText('Temporary grant expires');
  await expect(page.locator('.page-head .badge').first()).toHaveText('Active');
  expect(policyReads).toBeGreaterThan(1);
});
