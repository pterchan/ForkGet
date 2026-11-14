import { expect, test, type Page } from '@playwright/test';
import AxeBuilder from '@axe-core/playwright';
import { mkdir } from 'node:fs/promises';
import { localeCodes, resources, type Locale, type TranslationKey } from '../../src/lib/locales';
const words = (code: Locale, key: TranslationKey) => resources[code].translation[key];
async function preview(page: Page) {
  await page.goto('/');
  await page.getByRole('button', { name: words('en', 'demo_action'), exact: true }).click();
  await expect(page.getByRole('link', { name: 'checkout-redesign', exact: true })).toBeVisible();
}
async function visit(page: Page, name: string) {
  await page.evaluate((value) => { location.hash = value; }, name);
}

test('branch lifecycle, diff, approval, filtering, and dialog focus', async ({ page, context }) => {
  const errors: string[] = []; page.on('pageerror', (error) => errors.push(error.message));
  await context.grantPermissions(['clipboard-read', 'clipboard-write']);
  await preview(page);
  await page.getByRole('button', { name: 'New branch', exact: true }).click();
  await page.getByLabel('Branch name', { exact: true }).fill('browser-flow');
  await page.getByRole('radio', { name: /^Writable/ }).check();
  await page.getByRole('button', { name: 'Create branch', exact: true }).click();
  await expect(page.getByRole('heading', { name: 'browser-flow', exact: true })).toBeVisible();
  await expect(page.locator('.page-head .badge').first()).toHaveText('Provisioning');
  await expect(page.locator('.page-head .badge').first()).toHaveText('Active', { timeout: 8000 });
  await page.getByRole('button', { name: 'Copy command', exact: true }).click();
  await expect.poll(() => page.evaluate(() => navigator.clipboard.readText())).toContain('PGSSLMODE=verify-full');
  await page.getByRole('button', { name: 'Drop branch', exact: true }).click();
  await expect(page.getByRole('dialog')).toBeVisible();
  await page.keyboard.press('Escape');
  await expect(page.getByRole('dialog')).not.toBeVisible();
  await expect(page.getByRole('button', { name: 'Drop branch', exact: true })).toBeFocused();
  await page.getByRole('button', { name: 'Drop branch', exact: true }).click();
  await page.getByRole('dialog').getByRole('button', { name: 'Drop branch', exact: true }).click();
  await expect(page.locator('.page-head .badge').first()).toHaveText('Dropped', { timeout: 8000 });
  await visit(page, 'branch/101/changes');
  await expect(page.getByRole('heading', { name: 'public.orders', exact: true })).toBeVisible();
  await expect(page.locator('.diff-value.after').first()).toContainText('"paid"');
  const download = page.waitForEvent('download');
  await page.getByRole('button', { name: words('en', 'export_diff'), exact: true }).click();
  expect((await download).suggestedFilename()).toBe('checkout-redesign-diff.json');
  await page.getByLabel('Operation', { exact: true }).selectOption('insert');
  await expect(page.locator('.diff-value.before')).toHaveCount(1);
  await visit(page, 'branch/101/approvals');
  await page.getByRole('button', { name: 'Approve', exact: true }).first().click();
  await expect(page.locator('tbody tr').first()).toContainText('Approved');
  await expect(page.locator('tbody tr').nth(1).getByRole('button', { name: 'Approve', exact: true })).toBeDisabled();
  await visit(page, 'branch/101/audit');
  await expect(page.getByText('policy_decision', { exact: true })).toBeVisible();
  await visit(page, 'branches');
  await page.getByLabel('Search branches').fill('not-a-branch');
  await expect(page.getByRole('heading', { name: words('en', 'no_results') })).toBeVisible();
  await page.getByRole('button', { name: 'Clear filters' }).click();
  await expect(page.getByRole('link', { name: 'checkout-redesign', exact: true })).toBeVisible();
  expect(errors).toEqual([]);
});

for (const code of localeCodes) {
  test(`complete core journey and pages in ${code}`, async ({ page }) => {
    await preview(page);
    await page.getByLabel('Language', { exact: true }).selectOption(code);
    await expect(page.locator('html')).toHaveAttribute('lang', code);
    await expect(page.locator('main h1')).toHaveText(words(code, 'branches'));
    await page.getByLabel(words(code, 'search_branches')).fill('checkout');
    await page.getByRole('button', { name: words(code, 'new_branch'), exact: true }).click();
    await page.getByLabel(words(code, 'branch_name'), { exact: true }).fill(`locale-${code.toLowerCase()}`);
        await expect(page.getByLabel(words(code, 'branch_name'), { exact: true })).toHaveValue(`locale-${code.toLowerCase()}`);
    await page.getByRole('dialog').getByRole('button', { name: words(code, 'create_branch'), exact: true }).click();
    await expect(page.locator('main h1')).toHaveText(`locale-${code.toLowerCase()}`);
    await page.getByRole('button', { name: words(code, 'drop_branch'), exact: true }).click();
    await page.getByRole('dialog').getByRole('button', { name: words(code, 'drop_branch'), exact: true }).click();
    await expect(page.locator('.page-head .badge').first()).toHaveText(words(code, 'dropped'), { timeout: 8000 });
    await page.setViewportSize({width:390,height:900});
    for (const view of ['tools', 'deployment', 'snapshots', 'policies', 'review_queue', 'github', 'preferences']) {
      await visit(page, view);
      await expect(page.locator('main h1')).toHaveText(words(code, view as TranslationKey));
      await expect(page.locator('body')).not.toContainText('{{');
      expect(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth)).toBe(true);
    }
  });
}

test('language switching keeps filters and form edits, unknown languages fall back', async ({ page }) => {
  await page.addInitScript(() => localStorage.setItem('forkget.locale', 'unsupported-locale'));
  await preview(page);
  await page.getByLabel('Search branches').fill('checkout');
  await page.getByLabel('Language', { exact: true }).selectOption('zh-CN');
  await expect(page.getByLabel('搜索分支')).toHaveValue('checkout');
  await visit(page, 'policies');
  await page.getByLabel(words('zh-CN', 'max_transaction_rows')).fill('125');
  await page.getByLabel('语言', { exact: true }).selectOption('de');
  await expect(page.getByLabel(words('de', 'max_transaction_rows'))).toHaveValue('125');
  await page.getByRole('button', { name: words('de', 'save'), exact: true }).click();
  await expect(page.getByRole('status')).toHaveText(words('de', 'saved'));
});

test('keyboard, responsive layouts, reduced motion, and accessibility', async ({ page }) => {
  await mkdir('artifacts', { recursive: true });
  await preview(page);
  for (const width of [390, 768, 1366, 1920]) {
    await page.setViewportSize({ width, height: 900 });
    await expect(page.locator('main h1')).toBeVisible();
    expect(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth)).toBe(true);
    const axe = await new AxeBuilder({ page }).withTags(['wcag2a', 'wcag2aa', 'wcag21aa', 'wcag22aa']).analyze();
    expect(axe.violations.map((v) => `${v.id}: ${v.nodes.map((n) => n.target).join(', ')}`)).toEqual([]);
    await page.screenshot({ path: `artifacts/branches-${width}.png`, fullPage: true });
  }
  await page.setViewportSize({ width: 683, height: 384 });
  await page.emulateMedia({ reducedMotion: 'reduce' });
  await page.getByRole('button', { name: 'New branch', exact: true }).click();
  await expect(page.getByRole('dialog')).toBeVisible();
  const axe = await new AxeBuilder({ page }).withTags(['wcag2a', 'wcag2aa']).analyze();
  expect(axe.violations).toEqual([]);
  await page.keyboard.press('Escape');
  await expect(page.getByRole('button', { name: 'New branch', exact: true })).toBeFocused();
  await page.getByRole('button', { name: 'New branch', exact: true }).click();
  await page.getByLabel('Branch name', { exact: true }).fill('a'.repeat(63));
  await page.getByRole('dialog').getByRole('button', { name: 'Create branch', exact: true }).click();
  await expect(page.getByRole('heading', { name: 'a'.repeat(63), exact: true })).toBeVisible();
  expect(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth)).toBe(true);
});

test('live failure never becomes demo and token is not persisted', async ({ page }) => {
  await page.route('**/api/v1/branches', (route) => route.abort());
  await page.goto('/');
  await page.getByLabel(words('en', 'owner_token')).fill('browser-test-token');
  await page.getByRole('button', { name: words('en', 'connect_deployment') }).click();
  await expect(page.getByRole('alert')).toBeVisible();
  await expect(page.locator('main')).toHaveCount(0);
  const storage = await page.evaluate(() => JSON.stringify({ ...localStorage }));
  expect(storage).not.toContain('browser-test-token');
});

test('live reads keep stale data, recover, and distinguish create conflicts', async ({ page }) => {
  let unavailable = false;
  const branch = { id: 1, generation_id: 2, name: 'readable-branch', class: 'dev', created_by: 'alice', expires_at: Math.floor(Date.now()/1000)+3600, status: 'active', mode: 'read_only' };
  await page.route('**/api/v1/branches', (route) => {
    if (route.request().method() === 'POST') return route.fulfill({ status:409, json:{code:'FG-2003',message:'A live branch with this name already exists.'} });
    if (unavailable) return route.abort();
    return route.fulfill({ json:[branch] });
  });
  await page.goto('/');
  await page.getByLabel(words('en','owner_token')).fill('test-token');
  await page.getByRole('button',{name:words('en','connect_deployment')}).click();
  await expect(page.getByRole('link',{name:'readable-branch',exact:true})).toBeVisible();
  unavailable = true;
  await page.getByRole('button',{name:'Refresh',exact:true}).click();
  await expect(page.getByRole('alert')).toBeVisible();
  await expect(page.getByRole('link',{name:'readable-branch',exact:true})).toBeVisible();
  await expect(page.getByRole('button',{name:'New branch',exact:true})).toBeDisabled();
  await expect(page.locator('.mode-strip')).toContainText(words('en','live_notice'));
  unavailable = false;
  await page.getByRole('button',{name:'Retry',exact:true}).click();
  await expect(page.getByRole('alert')).toHaveCount(0);
  await page.getByRole('button',{name:'New branch',exact:true}).click();
  await page.getByLabel('Branch name',{exact:true}).fill('readable-branch');
  await page.getByRole('dialog').getByRole('button',{name:'Create branch',exact:true}).click();
  await expect(page.getByRole('alert')).toContainText(words('en','error_conflict'));
  await expect(page.getByRole('alert')).not.toContainText(words('en','version_conflict'));
  await expect(page.getByLabel('Branch name',{exact:true})).toHaveValue('readable-branch');
});

test('mobile navigation contains keyboard focus and closes with Escape', async ({ page }) => {
  await page.setViewportSize({width:390,height:844});
  await preview(page);
  await expect(page.locator('.sidebar')).toHaveAttribute('inert','');
  await page.getByRole('button',{name:'Menu',exact:true}).click();
  await expect(page.locator('.sidebar .brand')).toBeFocused();
  await page.keyboard.press('Shift+Tab');
  await expect(page.locator('.sidebar').getByRole('button',{name:'Sign out',exact:true})).toBeFocused();
  await page.keyboard.press('Tab');
  await expect(page.locator('.sidebar .brand')).toBeFocused();
  await page.keyboard.press('Escape');
  await expect(page.getByRole('button',{name:'Menu',exact:true})).toBeFocused();
  await expect(page.locator('.sidebar')).toHaveAttribute('inert','');
});
