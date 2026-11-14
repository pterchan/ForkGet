import { afterEach, describe, expect, it, vi } from 'vitest';
import { createDemoApi } from './demo';

afterEach(() => vi.useRealTimers());

describe('explicit in-memory examples', () => {
  it('keeps accepted lifecycle changes separate from completion and isolates each session', async () => {
    vi.useFakeTimers();
    const api = createDemoApi();
    const branch = await api.create({ name: 'feature-copy', mode: 'native_write' });
    expect(branch.status).toBe('provisioning');
    expect((await api.detail(branch.id)).status).toBe('provisioning');
    await vi.advanceTimersByTimeAsync(1200);
    expect((await api.detail(branch.id)).status).toBe('active');
    expect((await api.drop(branch.id)).status).toBe('dropping');
    await vi.advanceTimersByTimeAsync(800);
    expect((await api.detail(branch.id)).status).toBe('dropped');
    expect((await createDemoApi().list()).some(item => item.name === 'feature-copy')).toBe(false);
  });

  it('does not silently reuse a live name and allows it after deletion completes', async () => {
    vi.useFakeTimers();
    const api = createDemoApi();
    await expect(api.create({ name: 'checkout-redesign' })).rejects.toMatchObject({ status: 409 });
    await api.drop(101);
    await expect(api.create({ name: 'checkout-redesign' })).rejects.toMatchObject({ status: 409 });
    await vi.advanceTimersByTimeAsync(800);
    const recreated = await api.create({ name: 'checkout-redesign' });
    expect(recreated.id).not.toBe(101);
  });

  it('preserves independent one-use review and expiry behavior', async () => {
    vi.useFakeTimers();
    const api = createDemoApi();
    expect(await api.review(101, 71, true)).toEqual({ state: 'approved' });
    await expect(api.review(101, 71, false)).rejects.toMatchObject({ status: 409 });
    const expiredApi = createDemoApi();
    await vi.advanceTimersByTimeAsync(61_000);
    expect((await expiredApi.approvals(101))[0].state).toBe('expired');
    await expect(expiredApi.review(101, 71, true)).rejects.toMatchObject({ status: 409 });
  });

  it('retains the policy version check and yields real cursor pages in the example state', async () => {
    const api = createDemoApi();
    const current = await api.policy('dev');
    const update = { expected_version: current.version, max_transaction_rows: 120, table_limit_bps: 1000, approval_after_rows: 50 };
    expect((await api.updatePolicy('dev', update)).version).toBe(4);
    await expect(api.updatePolicy('dev', update)).rejects.toMatchObject({ status: 409 });
    const first = await api.audit(101, { limit: 2 });
    expect(first.events).toHaveLength(2);
    expect(first.next_after).toBe(9002);
    const second = await api.audit(101, { after: first.next_after!, limit: 2 });
    expect(second.events.map(event => event.id)).toEqual([9003, 9004]);
    expect(second.next_after).toBeNull();
  });

  it('returns independent snapshots instead of exposing mutable fixture objects', async () => {
    const api = createDemoApi();
    const branch = await api.detail(101);
    branch.name = 'changed-outside';
    expect((await api.detail(101)).name).toBe('checkout-redesign');
    const diff = await api.diff(101);
    diff.tables[0].changes = [];
    expect((await api.diff(101)).tables[0].changes).toHaveLength(3);
    const download = await api.downloadDiff(101);
    expect(JSON.parse(await download.text())).toEqual(await api.diff(101));
  });
});
