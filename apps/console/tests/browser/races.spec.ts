import { expect, test, type Page, type Route } from '@playwright/test';
import type { Branch } from '../../src/lib/model';

// All tokens and deployment responses in this file are synthetic browser fixtures.
const branch = (id: number, name: string): Branch => ({
  id, name, class: 'dev', generation_id: 12, created_by: 'fixture-owner',
  expires_at: Math.floor(Date.now() / 1000) + 3600, status: 'active', mode: 'native_write'
});
const branches = [branch(101, 'fixture-first'), branch(202, 'fixture-second')];
const diff = (id: number) => ({
  format_version: 1, engine: 'postgresql', branch_id: id, generation_id: 12,
  replay_origin: null, native_write: true, tables: []
});
const approval = (id: number) => ({
  id, policy_version: 3, table_id: 4, kind: 'update', rows: 60,
  state: 'pending', expires_at: Math.floor(Date.now() / 1000) + 120
});
function gate() {
  let release!: () => void;
  const promise = new Promise<void>(resolve => { release = resolve; });
  return { promise, release };
}
async function settle(page: Page) {
  await page.evaluate(() => new Promise<void>(resolve => requestAnimationFrame(() => requestAnimationFrame(() => resolve()))));
}
async function visit(page: Page, route: string) {
  await page.evaluate(value => { location.hash = value; }, route);
}
async function login(page: Page) {
  await page.goto('/');
  await page.getByLabel('Owner token', { exact: true }).fill('synthetic-browser-token');
  await page.getByRole('button', { name: 'Connect deployment', exact: true }).click();
  await expect(page.getByRole('link', { name: 'fixture-first', exact: true })).toBeVisible();
}
async function fulfillBasic(route: Route) {
  const path = new URL(route.request().url()).pathname;
  if (path === '/api/v1/branches') return route.fulfill({ json: branches });
  const id = path.match(/^\/api\/v1\/branches\/(\d+)$/)?.[1];
  if (id) return route.fulfill({ json: branches.find(item => String(item.id) === id) });
  if (path.startsWith('/api/health/')) return route.fulfill({ status: 204 });
  return route.fulfill({ status: 404, json: { code: 'FG-2003', message: 'Synthetic fixture route is unavailable.' } });
}

test('focused race: explicit preview cancels a delayed live login', async ({ page }) => {
  const started = gate();
  const release = gate();
  const finished = gate();
  await page.route('**/api/v1/branches', async route => {
    started.release();
    await release.promise;
    try { await route.fulfill({ json: branches }); } finally { finished.release(); }
  });
  await page.goto('/');
  await page.getByLabel('Owner token', { exact: true }).fill('synthetic-delayed-token');
  await page.getByRole('button', { name: 'Connect deployment', exact: true }).click();
  await started.promise;
  const cancelled = page.waitForEvent('requestfailed', request => new URL(request.url()).pathname === '/api/v1/branches');
  await page.getByRole('button', { name: 'Explore demo', exact: true }).click();
  await cancelled;
  await expect(page.getByRole('link', { name: 'checkout-redesign', exact: true })).toBeVisible();
  release.release();
  await finished.promise;
  await settle(page);
  await expect(page.locator('.mode-strip')).toContainText('Design preview');
  await expect(page.getByRole('link', { name: 'fixture-first', exact: true })).toHaveCount(0);
});

test('focused race: static navigation and failed health probes retain disconnected state', async ({ page }) => {
  let unavailable = false;
  await page.route('**/api/**', route => unavailable ? route.abort() : fulfillBasic(route));
  await login(page);
  unavailable = true;
  await page.getByRole('button', { name: 'Refresh', exact: true }).click();
  await expect(page.locator('.connection-badge')).toHaveText('Disconnected');
  for (const route of ['tools', 'snapshots', 'preferences', 'review_queue']) {
    await visit(page, route);
    await settle(page);
    await expect(page.locator('.connection-badge')).toHaveText('Disconnected');
  }
  await visit(page, 'deployment');
  await expect(page.getByRole('alert')).toBeVisible();
  await expect(page.locator('.connection-badge')).toHaveText('Disconnected');
  await visit(page, 'tools');
  await expect(page.locator('.connection-badge')).toHaveText('Disconnected');
});

for (const change of ['route', 'session'] as const) {
  test(`focused race: a delayed diff download is suppressed after ${change} change`, async ({ page }) => {
    const started = gate();
    const release = gate();
    let diffRequests = 0;
    const downloads: string[] = [];
    page.on('download', download => downloads.push(download.suggestedFilename()));
    await page.route('**/api/**', async route => {
      const path = new URL(route.request().url()).pathname;
      if (path === '/api/v1/branches/101/diff') {
        if (++diffRequests === 2) { started.release(); await release.promise; }
        return route.fulfill({ json: diff(101) });
      }
      return fulfillBasic(route);
    });
    await login(page);
    await visit(page, 'branch/101/changes');
    await expect(page.getByRole('button', { name: 'Export diff', exact: true })).toBeEnabled();
    await expect(page.getByRole('heading', { name: 'No changes found', exact: true })).toBeVisible();
    await page.getByRole('button', { name: 'Export diff', exact: true }).click();
    await started.promise;
    if (change === 'session') {
      await page.getByRole('button', { name: 'Sign out', exact: true }).click();
      await page.getByLabel('Owner token', { exact: true }).fill('synthetic-new-session');
      await page.getByRole('button', { name: 'Connect deployment', exact: true }).click();
      await expect(page.getByRole('heading', { name: 'fixture-first', exact: true })).toBeVisible();
    }
    await visit(page, 'branch/202/connection');
    await expect(page.getByRole('heading', { name: 'fixture-second', exact: true })).toBeVisible();
    const response = page.waitForResponse(value => new URL(value.url()).pathname === '/api/v1/branches/101/diff');
    release.release();
    await (await response).finished();
    await settle(page);
    expect(downloads).toEqual([]);
    await expect(page.getByRole('heading', { name: 'fixture-second', exact: true })).toBeVisible();
    await expect(page.getByRole('alert')).toHaveCount(0);
  });
}

test('focused race: audit pagination uses the applied filters with its cursor', async ({ page }) => {
  const queries: URLSearchParams[] = [];
  await page.route('**/api/**', route => {
    const url = new URL(route.request().url());
    if (url.pathname === '/api/v1/branches/101/audit') {
      queries.push(url.searchParams);
      const filtered = url.searchParams.get('event_type') === 'policy_decision';
      const after = url.searchParams.has('after');
      return route.fulfill({ json: {
        events: [{ id: after ? 12 : filtered ? 11 : 1, occurred_at: 1800000000,
          actor: 'fixture-owner', event_type: filtered ? 'policy_decision' : 'branch_created', payload: {} }],
        next_after: after ? null : filtered ? 11 : 1
      } });
    }
    return fulfillBasic(route);
  });
  await login(page);
  await visit(page, 'branch/101/audit');
  await expect(page.locator('tbody')).toContainText('branch_created');
  await page.getByLabel('Event', { exact: true }).fill('policy_decision');
  await page.getByRole('button', { name: 'Filter events', exact: true }).click();
  await expect(page.locator('tbody')).toContainText('policy_decision');
  await page.getByLabel('Event', { exact: true }).fill('policy_outcome');
  await page.getByRole('button', { name: 'Next page', exact: true }).click();
  await expect(page.locator('tbody tr')).toHaveCount(2);
  expect(queries.at(-1)?.get('event_type')).toBe('policy_decision');
  expect(queries.at(-1)?.get('after')).toBe('11');
  expect(queries.at(-1)?.get('limit')).toBe('30');
  expect(queries.some(query => query.get('event_type') === 'policy_outcome')).toBe(false);
});

test('focused race: changing a known review branch removes the old actionable approvals', async ({ page }) => {
  const started = gate();
  const release = gate();
  let secondBranchReleased = false;
  const reviews: string[] = [];
  await page.route('**/api/**', async route => {
    const path = new URL(route.request().url()).pathname;
    if (path === '/api/v1/branches/101/approvals') return route.fulfill({ json: { approvals: [approval(71)] } });
    if (path === '/api/v1/branches/202/approvals') {
      if (!secondBranchReleased) { started.release(); await release.promise; secondBranchReleased = true; }
      return route.fulfill({ json: { approvals: [{ ...approval(82), state: reviews.length ? 'approved' : 'pending' }] } });
    }
    if (route.request().method() === 'POST') {
      reviews.push(path);
      return route.fulfill({ json: { state: 'approved' } });
    }
    return fulfillBasic(route);
  });
  await login(page);
  await visit(page, 'review_queue');
  await page.getByLabel('Known branch', { exact: true }).fill('101');
  await page.getByRole('button', { name: 'Inspect branch', exact: true }).click();
  await expect(page.locator('tbody')).toContainText('#71');
  await expect(page.getByRole('button', { name: 'Approve', exact: true })).toBeEnabled();
  await page.getByLabel('Known branch', { exact: true }).fill('202');
  await page.getByRole('button', { name: 'Inspect branch', exact: true }).click();
  await started.promise;
  await expect(page.getByRole('button', { name: 'Approve', exact: true })).toHaveCount(0);
  release.release();
  await expect(page.locator('tbody')).toContainText('#82');
  await expect(page.locator('tbody')).not.toContainText('#71');
  await page.getByRole('button', { name: 'Approve', exact: true }).click();
  await expect(page.locator('tbody')).toContainText('Approved');
  expect(reviews).toEqual(['/api/v1/branches/202/approvals/82']);
});
