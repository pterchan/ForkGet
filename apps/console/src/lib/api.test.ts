import { afterEach, describe, expect, it, vi } from 'vitest';
import { ApiError, createApi, parseWireJson } from './api';
import type { Branch } from './model';

const exampleBranch: Branch = {
  id: 101, name: 'checkout-redesign', class: 'dev', generation_id: 12,
  created_by: 'alex', expires_at: 1_800_000_000, status: 'active', mode: 'native_write'
};
const jsonResponse = (value: unknown, status = 200) => new Response(JSON.stringify(value), { status, headers: { 'Content-Type': 'application/json' } });
const mockFetch = () => vi.fn<typeof fetch>();

afterEach(() => vi.useRealTimers());

describe('control API boundary', () => {
  it('preserves exact recovery counts and rejects malformed audit health', async () => {
    const health = { witness_ready: false, storage_invalidated: true, requires_witness: true,
      pending_delivery: '9007199254740993', sql_unresolved_unknown: 1, mongo_unknown: 0,
      mongo_partial: 0, oldest_pending_at: 1800000000, cleanup_blocked: true, latest_mongo_observation: null };
    const status = { ...exampleBranch, access: 'read_write', layout: 'native_copy', expired: false,
      lease_version: 1, snapshot_rows: 10, lifecycle_phase: 'audit_recovery_pending', reason: 'audit_recovery_pending' };
    const fetcher = mockFetch().mockResolvedValueOnce(jsonResponse({ ...status, audit: health }));
    expect((await createApi({ token: 'owner', fetch: fetcher }).status(101)).audit).toEqual(health);
    for (const invalid of [{ ...health, pending_delivery: -1 }, { ...health, cleanup_blocked: 'false' },
      { ...health, oldest_pending_at: 'tomorrow' }, { ...health, latest_mongo_observation: {} }]) {
      fetcher.mockResolvedValueOnce(jsonResponse({ ...status, audit: invalid }));
      await expect(createApi({ token: 'owner', fetch: fetcher }).status(101)).rejects.toMatchObject({ code: 'INVALID_RESPONSE' });
    }
  });

  it('keeps authoritative expiry, layout, policy revisions and large snapshot counts independent', async () => {
    const fetcher = mockFetch()
      .mockResolvedValueOnce(new Response('{"id":101,"status":"active","access":"read_write","layout":"sparse_delta","expires_at":1800000000,"expired":true,"lease_version":2,"snapshot_rows":9007199254740993,"lifecycle_phase":"cleanup_retry","reason":"native_cleanup_failed"}'))
      .mockResolvedValueOnce(jsonResponse({ class: 'dev', version: 3, max_transaction_rows: 2000, table_limit_bps: null,
        approval_after_rows: null, small_table_floor: 10, effective_revision: 7, grant_expires_at: 1800000000 }));
    const api = createApi({ token: 'owner', fetch: fetcher });
    expect(await api.status(101)).toMatchObject({ access: 'read_write', layout: 'sparse_delta', expired: true,
      snapshot_rows: '9007199254740993', lifecycle_phase: 'cleanup_retry' });
    expect(await api.effectivePolicy(101)).toMatchObject({ effective_revision: 7, small_table_floor: 10 });
    expect(fetcher.mock.calls.map(([url]) => url)).toEqual(['/api/v1/branches/101/status', '/api/v1/branches/101/policy']);
  });

  it('exposes backend capability limits and actionable refusal reasons without retrying', async () => {
    const fetcher = mockFetch()
      .mockResolvedValueOnce(jsonResponse({ engine: 'tidb', new_branch_default_access: 'read_only', native_copy_limit: 16,
        physical_generation_limit: 2, budget_scope: 'direct_rows_per_transaction',
        known_limitations: [{ reason: 'native_integrity_unverified', action: 'Inspect the recorded engine qualification.' }] }))
      .mockResolvedValueOnce(jsonResponse({ code: 'FG-5001', message: 'Policy changed.', reason: 'effective_policy_changed',
        hint: 'Start a new transaction.' }, 409));
    const api = createApi({ token: 'owner', fetch: fetcher });
    expect(await api.capabilities()).toMatchObject({ native_copy_limit: 16, physical_generation_limit: 2 });
    await expect(api.create({ name: 'refused' })).rejects.toMatchObject({ reason: 'effective_policy_changed', hint: 'Start a new transaction.' });
    expect(fetcher).toHaveBeenCalledTimes(2);
  });

  it('uses only the same-origin proxy and sends the token in a noncached header', async () => {
    const fetcher = mockFetch().mockResolvedValue(jsonResponse([exampleBranch]));
    const result = await createApi({ token: 'private-owner-token', fetch: fetcher }).list();
    expect(result).toEqual([exampleBranch]);
    const [url, init] = fetcher.mock.calls[0];
    expect(url).toBe('/api/v1/branches');
    expect(new Headers(init?.headers).get('Authorization')).toBe('Bearer private-owner-token');
    expect(init).toMatchObject({ cache: 'no-store', credentials: 'omit', redirect: 'error' });
    expect(String(url)).not.toContain('private-owner-token');
    for (const baseUrl of ['https://outside.example/api', '//outside.example/api', '/api?upstream=x']) {
      expect(() => createApi({ token: 'secret', baseUrl, fetch: fetcher })).toThrow(ApiError);
    }
  });

  it('preserves signed 64-bit identities and leaves typed database strings unchanged', async () => {
    const text = '{"id":9223372036854775807,"generation_id":9007199254740993,"key":["9007199254740993"],"name":"branch","class":"dev","created_by":"alex","expires_at":1800000000,"status":"active","mode":"read_only"}';
    expect(parseWireJson(text)).toMatchObject({ id: '9223372036854775807', generation_id: '9007199254740993', key: ['9007199254740993'] });
    const fetcher = mockFetch().mockResolvedValue(new Response(text));
    const result = await createApi({ token: 'owner', fetch: fetcher }).detail('9223372036854775807');
    expect(result.id).toBe('9223372036854775807');
    expect(fetcher.mock.calls[0][0]).toBe('/api/v1/branches/9223372036854775807');
  });

  it('keeps accepted provisioning and dropping states until a later read confirms completion', async () => {
    const fetcher = mockFetch()
      .mockResolvedValueOnce(jsonResponse({ ...exampleBranch, status: 'provisioning' }, 202))
      .mockResolvedValueOnce(jsonResponse({ ...exampleBranch, status: 'dropping' }, 202));
    const api = createApi({ token: 'owner', fetch: fetcher });
    expect((await api.create({ name: 'checkout-redesign', mode: 'native_write' })).status).toBe('provisioning');
    expect((await api.drop(101)).status).toBe('dropping');
    expect(fetcher.mock.calls.map(([, init]) => init?.method)).toEqual(['POST', 'DELETE']);
  });

  it('preserves policy conflict details and does not retry a mutation', async () => {
    const fetcher = mockFetch().mockResolvedValue(jsonResponse({ code: 'FG-5001', message: 'The policy version changed.' }, 409));
    const api = createApi({ token: 'owner-secret', fetch: fetcher });
    await expect(api.updatePolicy('dev', { expected_version: 3, max_transaction_rows: 100, table_limit_bps: 1000, approval_after_rows: 50 }))
      .rejects.toMatchObject({ status: 409, code: 'FG-5001', message: 'The policy version changed.' });
    expect(fetcher).toHaveBeenCalledTimes(1);
  });

  it('serializes large expected versions and row budgets as exact JSON number tokens', async () => {
    const fetcher = mockFetch().mockResolvedValue(new Response('{"class":"dev","version":9007199254740994,"max_transaction_rows":18446744073709551615,"table_limit_bps":null,"approval_after_rows":null}'));
    const api = createApi({ token: 'owner', fetch: fetcher });
    await api.updatePolicy('dev', { expected_version: '9007199254740993', max_transaction_rows: '18446744073709551615', table_limit_bps: null, approval_after_rows: null });
    const body = fetcher.mock.calls[0][1]?.body;
    expect(body).toBe('{"expected_version":9007199254740993,"max_transaction_rows":18446744073709551615,"table_limit_bps":null,"approval_after_rows":null}');
  });

  it('encodes audit filters and exact cursors without retaining previous filters', async () => {
    const fetcher = mockFetch().mockImplementation(async () => jsonResponse({ events: [], next_after: null }));
    const api = createApi({ token: 'owner', fetch: fetcher });
    await api.audit(101, { since: 0, until: 1800000000, event_type: 'policy_decision', after: '9007199254740993', limit: 25 });
    expect(fetcher.mock.calls[0][0]).toBe('/api/v1/branches/101/audit?since=0&until=1800000000&event_type=policy_decision&after=9007199254740993&limit=25');
    await api.audit(101);
    expect(fetcher.mock.calls[1][0]).toBe('/api/v1/branches/101/audit');
  });

  it('unwraps approvals and bindings and uses the single existing review request', async () => {
    const fetcher = mockFetch()
      .mockResolvedValueOnce(jsonResponse({ approvals: [{ id: 71, policy_version: 3, table_id: 4, kind: 'update', rows: 60, state: 'pending', expires_at: 1800000000 }] }))
      .mockResolvedValueOnce(jsonResponse({ state: 'approved' }))
      .mockResolvedValueOnce(jsonResponse({ bindings: [] }));
    const api = createApi({ token: 'owner', fetch: fetcher });
    expect(await api.approvals(101)).toHaveLength(1);
    expect(await api.review(101, 71, true)).toEqual({ state: 'approved' });
    expect(fetcher.mock.calls[1][0]).toBe('/api/v1/branches/101/approvals/71');
    expect(fetcher.mock.calls[1][1]?.body).toBe('{"approve":true}');
    expect(await api.bindings()).toEqual([]);
  });

  it('preserves typed row images, SQL nulls, and before/after absence in a diff', async () => {
    const report = {
      format_version: 1, engine: 'postgresql', branch_id: 101, generation_id: 12,
      replay_origin: null, native_write: true,
      tables: [{ id: 4, schema: 'public', table: 'orders', generated_key: null,
        columns: [
          { name: 'id', type_name: 'bigint', nullable: false, primary_key_ordinal: 1 },
          { name: 'note', type_name: 'text', nullable: true, primary_key_ordinal: null }
        ],
        changes: [
          { operation: 'update', key: ['9007199254740993'], before: ['9007199254740993', null], after: ['9007199254740993', 'null'] },
          { operation: 'insert', key: ['9007199254740994'], before: null, after: ['9007199254740994', ''] }
        ]
      }]
    };
    const fetcher = mockFetch().mockResolvedValue(jsonResponse(report));
    expect(await createApi({ token: 'owner', fetch: fetcher }).diff(101)).toEqual(report);
  });

  it('downloads the original diff bytes without changing unsafe numeric identifiers into JSON strings', async () => {
    const document = '{\n  "format_version": 1, "engine": "postgresql", "branch_id": 9223372036854775807,\n  "generation_id": 9007199254740993, "replay_origin": null, "native_write": true, "tables": []\n}\n';
    const fetcher = mockFetch().mockResolvedValue(new Response(document));
    const blob = await createApi({ token: 'owner', fetch: fetcher }).downloadDiff('9223372036854775807');
    expect(await blob.text()).toBe(document);
    expect(blob.type).toBe('application/json;charset=utf-8');
    expect(fetcher).toHaveBeenCalledTimes(1);
  });

  it('does not download a malformed or failed diff response', async () => {
    const fetcher = mockFetch()
      .mockResolvedValueOnce(jsonResponse({ tables: [] }))
      .mockResolvedValueOnce(jsonResponse({ code: 'FG-1004', message: 'Backend unavailable.' }, 503));
    const api = createApi({ token: 'owner', fetch: fetcher });
    await expect(api.downloadDiff(101)).rejects.toMatchObject({ code: 'INVALID_RESPONSE' });
    await expect(api.downloadDiff(101)).rejects.toMatchObject({ status: 503, code: 'FG-1004' });
  });

  it('reports live and readiness separately and retains a failed component', async () => {
    const fetcher = mockFetch().mockImplementation(async input => String(input).endsWith('/live')
      ? new Response(null, { status: 204 })
      : jsonResponse({ code: 'FG-1004', message: 'Native backend is unavailable.', component: 'native' }, 503));
    const result = await createApi({ token: 'owner', fetch: fetcher }).health();
    expect(result.live).toEqual({ ok: true, status: 204 });
    expect(result.ready).toMatchObject({ ok: false, status: 503, code: 'FG-1004', component: 'native' });
    expect(fetcher.mock.calls.every(([, init]) => !new Headers(init?.headers).has('Authorization'))).toBe(true);
  });

  it('rejects invalid successful data and keeps server failures actionable', async () => {
    const fetcher = mockFetch()
      .mockResolvedValueOnce(new Response('<html>upstream</html>'))
      .mockResolvedValueOnce(jsonResponse({ branches: [] }))
      .mockResolvedValueOnce(new Response('<html>down</html>', { status: 502 }));
    const api = createApi({ token: 'owner', fetch: fetcher });
    await expect(api.list()).rejects.toMatchObject({ code: 'INVALID_RESPONSE' });
    await expect(api.list()).rejects.toMatchObject({ code: 'INVALID_RESPONSE' });
    await expect(api.list()).rejects.toMatchObject({ status: 502, message: 'The control service returned HTTP 502.' });
  });

  it('never substitutes design examples after network failure', async () => {
    const fetcher = mockFetch().mockRejectedValue(new TypeError('connection failed'));
    await expect(createApi({ token: 'owner-secret', fetch: fetcher }).list())
      .rejects.toMatchObject({ code: 'NETWORK_ERROR', status: null });
    expect(fetcher).toHaveBeenCalledTimes(1);
  });

  it('rejects invalid and already-rounded IDs before making a request', async () => {
    const fetcher = mockFetch();
    const api = createApi({ token: 'owner', fetch: fetcher });
    for (const id of [0, -1, 9007199254740992, '../101', '101/approvals']) {
      await expect(api.detail(id)).rejects.toMatchObject({ code: 'INVALID_ID' });
    }
    expect(fetcher).not.toHaveBeenCalled();
  });

  it('supports cancellation and distinguishes it from a service timeout', async () => {
    vi.useFakeTimers();
    const fetcher = mockFetch().mockImplementation((_input, init) => new Promise((_resolve, reject) => {
      init?.signal?.addEventListener('abort', () => reject(new DOMException('aborted', 'AbortError')), { once: true });
    }));
    const api = createApi({ token: 'owner', fetch: fetcher, timeoutMs: 100 });
    const timeout = expect(api.list()).rejects.toMatchObject({ code: 'CLIENT_TIMEOUT' });
    await vi.advanceTimersByTimeAsync(100);
    await timeout;
    const controller = new AbortController();
    const cancelled = expect(api.list(controller.signal)).rejects.toMatchObject({ name: 'AbortError' });
    controller.abort();
    await cancelled;
  });
});
