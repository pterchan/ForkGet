import { test, expect } from '@playwright/test';
import { localeCodes, resources } from '../../src/lib/locales';

for (const code of localeCodes) {
  test(`audit recovery and historical MongoDB unknowns remain distinct in ${code}`, async ({ page }) => {
    const words = resources[code].translation;
    const branch = { id: 104, name: 'audit-retained', class: 'dev', generation_id: 12,
      created_by: 'alice', expires_at: Math.floor(Date.now() / 1000) + 3600,
      status: 'active', mode: 'native_write', access: 'read_write', layout: 'native_copy' };
    let pending = true;
    let liveTransaction = false;
    await page.route('**/api/**', async route => {
      const path = new URL(route.request().url()).pathname;
      let value: unknown;
      if (path === '/api/v1/branches') value = [branch];
      else if (path === '/api/v1/branches/104') value = branch;
      else if (path.endsWith('/status')) value = { ...branch, expired: false, lease_version: 1,
        snapshot_rows: 100, lifecycle_phase: 'audit_recovery_pending', reason: null,
        audit: { protected_writes_paused: pending, requires_witness: pending, witness_ready: false, storage_invalidated: false,
          pending_delivery: pending ? '9007199254740993' : liveTransaction ? 1 : 0, sql_unresolved_unknown: pending ? 1 : 0,
          mongo_unknown: pending ? 0 : 3, mongo_partial: pending ? 0 : 2,
          oldest_pending_at: pending ? 1800000000 : null, cleanup_blocked: pending,
          latest_mongo_observation: null } };
      else return route.fulfill({ status: 404, json: { code: 'FG-2001', message: 'Not found.' } });
      await route.fulfill({ json: value });
    });
    await page.goto('/');
    await page.locator('#owner-token').fill('synthetic-audit-token');
    await page.getByRole('button', { name: 'Connect deployment', exact: true }).click();
    await page.getByRole('link', { name: branch.name, exact: true }).click();
    await page.locator('#locale-picker').selectOption(code);
    const health = page.getByRole('region', { name: words.audit_health, exact: true });
    await expect(health).toContainText(words.audit_preparation_required);
    await expect(health).toContainText(words.audit_delivery_pending_hint);
    await expect(health).toContainText(words.audit_cleanup_blocked);
    await expect(health).toContainText('9007199254740993');
    pending = false;
    await page.getByRole('button', { name: words.refresh, exact: true }).click();
    await expect(health).toContainText(words.audit_mongo_partial);
    await expect(health).toContainText(words.audit_mongo_unknown);
    await expect(health).not.toContainText(words.audit_delivery_pending_hint);
    await expect(health).not.toContainText(words.audit_cleanup_blocked);
    liveTransaction = true;
    await page.getByRole('button', { name: words.refresh, exact: true }).click();
    await expect(health).not.toContainText(words.audit_delivery_pending_hint);
    await expect(health).not.toContainText(words.audit_cleanup_blocked);
  });
}
