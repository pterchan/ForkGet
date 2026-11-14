import { test, expect } from '@playwright/test';
import { existsSync, readFileSync, mkdirSync } from 'node:fs';
import { dirname, join } from 'node:path';

const liveFile = process.env.FG_CONSOLE_LIVE_FILE;
const available = !!liveFile && existsSync(liveFile);
const config = available ? JSON.parse(readFileSync(liveFile!, 'utf8')) : null;
const url = process.env.FG_CONSOLE_LIVE_URL || 'http://127.0.0.1:4195';

// Disposable credentials must never be captured in traces, videos or login screenshots.
test.use({ trace: 'off', video: 'off', screenshot: 'off', locale: 'en-US', permissions: ['clipboard-read', 'clipboard-write'] });
test.describe.configure({ mode: 'serial' });
// Development HMR must not discard in-memory credentials during parallel type checks.
test.beforeEach(async ({ page }) => { await page.routeWebSocket(/.*/, socket => socket.close()); });
test.beforeEach(async ({ page }) => {
  if (!config) return;
  await page.addInitScript((settings) => {
    localStorage.setItem('forkget.console.connection', JSON.stringify(settings));
  }, { engine: config.engine || 'postgresql', host: '127.0.0.1', port: String(config.proxy_port),
    username: config.database_username, caFile: 'frontend-ca.pem', deployment: 'Disposable native acceptance' });
});


test('real packaged control API: branch lifecycle, connection, changes, audit and policy', async ({ page }) => {
  test.skip(!available, 'Set FG_CONSOLE_LIVE_FILE to a private disposable deployment file.');
  test.setTimeout(90_000);
  const created: string[] = [];
  const name = `console-browser-${Date.now().toString(36)}`;
  const errors: string[] = [];
  page.on('pageerror', error => errors.push(error.message));
  try {
    await page.goto(url);
    await page.locator('#owner-token').fill(config.owner_token);
    await page.getByRole('button', { name: 'Connect deployment', exact: true }).click();
    await expect(page.getByRole('heading', { name: 'Branches', exact: true })).toBeVisible();
    await expect(page.getByRole('link', { name: 'console-live', exact: true })).toBeVisible();
    await expect(page.locator('.mode-strip.live')).toContainText('Connected to your deployment');

    await page.getByRole('button', { name: 'New branch', exact: true }).click();
    await page.locator('#branch-name').fill(`${name}-ro`);
    await page.getByRole('button', { name: 'Create branch', exact: true }).click();
    await expect(page.getByRole('heading', { name: `${name}-ro`, exact: true })).toBeVisible();
    created.push(page.url().split('#branch/')[1].split('/')[0]);
    await expect(page.locator('.page-head .badge').first()).toHaveText('Active');
    await expect(page.locator('.command pre')).toContainText(config.engine === 'mongodb' ? `/${name}-ro?`
      : `${config.engine === 'postgresql' ? '--dbname' : '--database'} '${name}-ro'`);
    await page.getByRole('button', { name: 'Copy command', exact: true }).click();
    expect(await page.evaluate(() => navigator.clipboard.readText())).toContain(`${name}-ro`);
    expect(await page.evaluate(() => navigator.clipboard.readText())).toContain(config.engine === 'postgresql'
      ? 'PGSSLMODE=verify-full' : config.engine === 'mongodb' ? '--tlsCAFile' : '--ssl-mode=VERIFY_IDENTITY');
    await page.getByRole('button', { name: 'Drop branch', exact: true }).click();
    await page.getByRole('dialog').getByRole('button', { name: 'Drop branch', exact: true }).click();
    await expect(page.locator('.page-head .badge').first()).toHaveText('Dropped', { timeout: 20_000 });

    await page.goto(`${url}/#branches`);
    await page.getByRole('button', { name: 'New branch', exact: true }).click();
    await page.locator('#branch-name').fill(`${name}-rw`);
    await page.locator('#writable').check();
    await page.getByRole('button', { name: 'Create branch', exact: true }).click();
    await expect(page.getByRole('heading', { name: `${name}-rw`, exact: true })).toBeVisible();
    created.push(page.url().split('#branch/')[1].split('/')[0]);
    await expect(page.locator('.page-head .badge').first()).toHaveText('Active', { timeout: 20_000 });
    await expect(page.locator('.detail-metadata').first()).toContainText('Writable');

    await page.goto(`${url}/#branch/${config.branch_id}/changes`);
    await expect(page.getByRole('heading', { name: 'console-live', exact: true })).toBeVisible();
    await expect(page.locator('.diff-value.after')).toContainText('console-verified');
    const download = page.waitForEvent('download');
    await page.getByRole('button', { name: 'Export diff', exact: true }).click();
    const downloaded = await download;
    expect(downloaded.suggestedFilename()).toMatch(/\.json$/);
    await page.locator('.tabs').getByRole('link', { name: 'Audit', exact: true }).click();
    await expect(page.getByRole('heading', { name: 'Audit log', exact: true })).toBeVisible();
    await expect(page.locator('#detail-panel')).toContainText('policy_decision');

    await page.getByRole('link', { name: 'Policies', exact: true }).click();
    await expect(page.locator('#max-rows')).toHaveValue('50000');
    await expect(page.locator('#max-rows')).toBeDisabled();
    await page.getByRole('link', { name: 'Deployment', exact: true }).click();
    await expect(page.locator('main')).toContainText('/health/live');
    await expect(page.locator('main')).toContainText('HTTP 204');

    await page.goto(`${url}/#branches`);
    await expect(page.getByRole('heading', { name: 'Branches', exact: true })).toBeVisible();
    await page.getByRole('combobox', { name: 'Status', exact: true }).selectOption('active');
    await expect(page.locator('.toast')).toHaveCount(0, { timeout: 6000 });
    await expect(page.locator('main')).not.toContainText('{{');
    const output = dirname(liveFile!);
    mkdirSync(output, { recursive: true });
    await page.screenshot({ path: join(output, 'live-desktop.png'), fullPage: true });
    await page.setViewportSize({ width: 390, height: 844 });
    await expect.poll(() => page.evaluate(() => document.documentElement.scrollWidth), { timeout: 5000 }).toBeLessThanOrEqual(390);
    await page.screenshot({ path: join(output, 'live-mobile.png'), fullPage: true });
    expect(errors).toEqual([]);
    expect(await page.evaluate(() => localStorage.getItem('FG_OWNER_TOKEN'))).toBeNull();
    expect(await page.evaluate(() => JSON.stringify({ ...localStorage }))).not.toContain(config.owner_token);
  } finally {
    for (const id of created) {
      await fetch(`${config.control_url}/v1/branches/${id}`, { method: 'DELETE', headers: { Authorization: `Bearer ${config.owner_token}` } }).catch(() => {});
    }
  }
});




test('independent reviewer inspects a known branch and approves a real pending native mutation', async ({ page }) => {
  test.skip(!available || !config?.driver_binary || !config?.reviewer_token, 'Disposable fixture must provide a native driver and independent reviewer.');
  test.setTimeout(90_000);
  const { spawn } = await import('node:child_process');
  const name = `console-review-${Date.now().toString(36)}`;
  let branch: { id: number | string } | null = null;
  let driver: ReturnType<typeof spawn> | null = null;
  async function api(method: string, path: string, body?: unknown) {
    const response = await fetch(config.control_url + path, { method, headers: { Authorization: `Bearer ${config.owner_token}`, 'Content-Type': 'application/json' }, body: body === undefined ? undefined : JSON.stringify(body) });
    if (!response.ok) throw new Error(`Disposable setup returned HTTP ${response.status}`);
    return response.json();
  }
  try {
    const policy = await api('GET', '/v1/policies/dev');
    await api('PUT', '/v1/policies/dev', { expected_version: policy.version, max_transaction_rows: 50000, table_limit_bps: null, approval_after_rows: 1 });
    branch = await api('POST', '/v1/branches', { name, mode: 'native_write', class: 'dev', ttl_seconds: 3600 });
    await expect.poll(async () => (await api('GET', `/v1/branches/${branch!.id}`)).status).toBe('active');
    const privatePath = process.platform === 'win32'
      ? liveFile!.replace(/^([A-Za-z]):\\/, (_, drive: string) => `/mnt/${drive.toLowerCase()}/`).replaceAll('\\', '/')
      : liveFile!;
    const script = `import json,os,subprocess,sys
s=json.load(open(sys.argv[1])); name=sys.argv[2]
if s['engine']=='mongodb':
 import pymongo
 from bson import Int64
 client=pymongo.MongoClient(host='127.0.0.1',port=s['proxy_port'],username=s['database_username'],
  password=s['database_password'],authSource='admin',directConnection=True,retryWrites=False,
  tls=True,tlsCAFile=s['ca_file'],serverSelectionTimeoutMS=10000,socketTimeoutMS=75000)
 try:
  client[name].orders.find_one({'_id':Int64(1)})
  print('ready',flush=True)
  result=client[name].orders.update_one({'_id':Int64(1)},{'$set':{'note':'browser-approved'}})
  print(json.dumps({'affected':result.modified_count}),flush=True)
 finally:client.close()
else:
 scheme='postgresql' if s['engine']=='postgresql' else 'mysql'
 url=scheme+'://'+s['database_username']+':'+s['database_password']+'@127.0.0.1:'+str(s['proxy_port'])+'/'+name
 env=os.environ|{'FG_WRITE_PROBE_URL':url,'FG_WRITE_PROBE_CA':s['ca_file']}
 p=subprocess.Popen([s['driver_binary']],env=env,stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True,bufsize=1)
 try:
  print(p.stdout.readline().strip(),flush=True)
  p.stdin.write(json.dumps({'sql':"UPDATE app.orders SET note='browser-approved' WHERE tenant_id=1 AND id=1",'op':'text','params':[]})+'\\n');p.stdin.flush()
  print(p.stdout.readline().strip(),flush=True)
 finally:
  p.stdin.close();p.wait(timeout=5)
`;
    const interpreter = config.driver_python || 'python3';
    driver = process.platform === 'win32'
      ? spawn('wsl', ['-d', config.wsl_distribution || 'Ubuntu-24.04', '--exec', interpreter, '-c', script, privatePath, name], { stdio: ['ignore', 'pipe', 'pipe'], windowsHide: true })
      : spawn(interpreter, ['-c', script, privatePath, name], { stdio: ['ignore', 'pipe', 'pipe'] });
    let output = '';
    driver.stdout!.on('data', data => output += data.toString());
    let stderr = '';
    driver.stderr!.on('data', data => stderr += data.toString());
    await expect.poll(() => output.startsWith('ready\n'), { timeout: 15_000 }).toBe(true);

    await page.goto(url);
    await page.locator('#owner-token').fill(config.reviewer_token);
    await page.getByRole('button', { name: 'Connect deployment', exact: true }).click();
    await expect(page.getByRole('heading', { name: 'Branches', exact: true })).toBeVisible();
    await expect(page.getByRole('link', { name, exact: true })).toHaveCount(0);
    const requested: string[] = [];
    page.on('request', request => requested.push(new URL(request.url()).pathname));
    await page.getByRole('link', { name: 'Review queue', exact: true }).click();
    await page.locator('#known-branch').fill(String(branch!.id));
    await page.getByRole('button', { name: 'Inspect branch', exact: true }).click();
    await expect(page.getByRole('button', { name: 'Approve', exact: true })).toBeEnabled();
    await page.getByRole('button', { name: 'Approve', exact: true }).click();
    // Approval can already be consumed before the review response is rendered.
    // Require the final one-use state and the independently completed write.
    await expect(page.locator('main table .badge')).toHaveText('Used');
    await expect(page.getByRole('button', { name: 'Approve', exact: true })).toBeDisabled();
    await expect(page.getByRole('button', { name: 'Deny', exact: true })).toBeDisabled();
    await expect.poll(() => output.includes('"affected":1') || output.includes('"affected": 1'), { timeout: 15_000 }).toBe(true);
    expect(requested).toContain(`/api/v1/branches/${branch!.id}/approvals`);
    expect(requested).not.toContain(`/api/v1/branches/${branch!.id}`);
    expect(stderr).toBe('');
    await page.screenshot({ path: join(dirname(liveFile!), 'live-reviewer.png'), fullPage: true });
  } finally {
    driver?.kill();
    const current = await api('GET', '/v1/policies/dev');
    await api('PUT', '/v1/policies/dev', { expected_version: current.version, max_transaction_rows: 50000, table_limit_bps: null, approval_after_rows: null });
    if (branch) await api('DELETE', `/v1/branches/${branch.id}`);
  }
});
