import { ApiError } from './api';
import type {
  Approval, AuditEvent, Branch, BranchClass, ConsoleApi, CreateBranch, GitHubBinding,
  Id, Policy, RowDiff, UpdatePolicy
} from './model';

/** Explicit, in-memory design examples. This adapter never makes network requests. */
export function createDemoApi(): ConsoleApi {
  const now = () => Math.floor(Date.now() / 1000);
  const createdAt = now();
  const branches: Branch[] = [
    { id: 101, name: 'checkout-redesign', class: 'dev', generation_id: 12, created_by: 'alex', expires_at: createdAt + 21_600, status: 'active', mode: 'native_write', access: 'read_write', layout: 'native_copy' },
    { id: 102, name: 'pr-184', class: 'ci', generation_id: 12, created_by: 'alex', expires_at: createdAt + 7200, status: 'provisioning', mode: 'native_write', access: 'read_write', layout: 'native_copy' },
    { id: 103, name: 'staging-baseline', class: 'staging', generation_id: 11, created_by: 'alex', expires_at: createdAt + 43_200, status: 'active', mode: 'read_only', access: 'read_only', layout: 'sparse_delta' }
  ];
  let nextBranchId = 104;
  let nextEventId = 9005;
  const transitions = new Map<string, { status: string; at: number }>([['102', { status: 'active', at: Date.now() + 1600 }]]);
  const policies: Record<BranchClass, Policy> = {
    dev: { class: 'dev', version: 3, max_transaction_rows: 100, table_limit_bps: 1000, approval_after_rows: 50 },
    ci: { class: 'ci', version: 1, max_transaction_rows: 1000, table_limit_bps: 10000, approval_after_rows: null },
    agent: { class: 'agent', version: 2, max_transaction_rows: 100, table_limit_bps: 1000, approval_after_rows: 20 },
    staging: { class: 'staging', version: 1, max_transaction_rows: 0, table_limit_bps: null, approval_after_rows: null }
  };
  const approvals = new Map<string, Approval[]>([['101', [
    { id: 71, policy_version: 3, table_id: 4, kind: 'update', rows: 60, state: 'pending', expires_at: createdAt + 60 },
    { id: 70, policy_version: 3, table_id: 4, kind: 'update', rows: 55, state: 'expired', expires_at: createdAt - 120 }
  ]]]);
  const audit = new Map<string, AuditEvent[]>([['101', [
    { id: 9001, occurred_at: createdAt - 600, actor: 'alex', event_type: 'branch_created', payload: {} },
    { id: 9002, occurred_at: createdAt - 598, actor: 'alex', event_type: 'branch_active', payload: {} },
    { id: 9003, occurred_at: createdAt - 120, actor: 'alex', event_type: 'policy_outcome', payload: { generation_id: 12, outcome: 'committed', session_id: 'example:1' } },
    { id: 9004, occurred_at: createdAt - 5, actor: 'alex', event_type: 'policy_decision', payload: { generation_id: 12, policy_version: 3, table_id: 4, kind: 'update', rows: 60, verdict: 'await_approval', approval_id: 71, session_id: 'example:2' } }
  ]]]);
  const bindings: GitHubBinding[] = [
    { repository_id: 42, installation_id: 8, source_kind: 'pull_request', source_key: '184', name: 'pr-184', branch_id: 102, branch_status: 'provisioning', state: 'active', last_error: null }
  ];
  const exampleDiff: RowDiff = {
    format_version: 1, engine: 'postgresql', branch_id: 101, generation_id: 12,
    replay_origin: { deployment_id: '00000000-0000-4000-8000-000000000001', generation_id: 12, snapshot: 'v3' },
    native_write: true,
    tables: [{
      id: 4, schema: 'public', table: 'orders', generated_key: null,
      columns: [
        { name: 'id', type_name: 'bigint', nullable: false, primary_key_ordinal: 1 },
        { name: 'status', type_name: 'text', nullable: false, primary_key_ordinal: null },
        { name: 'total', type_name: 'numeric', nullable: false, primary_key_ordinal: null }
      ],
      changes: [
        { operation: 'update', key: ['1002'], before: ['1002', 'pending', '89.00'], after: ['1002', 'paid', '89.00'] },
        { operation: 'insert', key: ['1005'], before: null, after: ['1005', 'pending', '24.50'] },
        { operation: 'delete', key: ['1004'], before: ['1004', 'cancelled', '12.00'], after: null }
      ]
    }]
  };

  function check(signal?: AbortSignal) {
    if (signal?.aborted) throw new DOMException('The request was cancelled.', 'AbortError');
    for (const branch of branches) {
      const transition = transitions.get(String(branch.id));
      if (transition && transition.at <= Date.now()) {
        branch.status = transition.status;
        transitions.delete(String(branch.id));
        record(branch.id, transition.status === 'active' ? 'branch_active' : 'branch_dropped');
      }
      if (branch.expires_at <= now() && ['active', 'provisioning'].includes(branch.status)) {
        branch.status = 'dropping';
        transitions.set(String(branch.id), { status: 'dropped', at: Date.now() + 800 });
        record(branch.id, 'branch_dropping', { reason: 'ttl' });
      }
    }
  }

  function record(id: Id, event_type: string, payload: AuditEvent['payload'] = {}, actor = 'alex') {
    const events = audit.get(String(id)) ?? [];
    events.push({ id: nextEventId++, occurred_at: now(), actor, event_type, payload });
    audit.set(String(id), events);
  }

  function find(id: Id): Branch {
    const branch = branches.find(candidate => String(candidate.id) === String(id));
    if (!branch) throw new ApiError('Branch is unavailable for this principal.', 404, 'FG-2003');
    return branch;
  }

  function requireActive(id: Id): Branch {
    const branch = find(id);
    if (branch.status !== 'active' || branch.expires_at <= now()) {
      throw new ApiError('The branch is not active.', 409, 'FG-2003');
    }
    return branch;
  }

  function clone<T>(value: T): T { return structuredClone(value); }

  const api: ConsoleApi = {
    async capabilities(signal) {
      check(signal);
      return { engine: 'postgresql', new_branch_default_access: 'read_only', native_copy_limit: 16,
        physical_generation_limit: 2, budget_scope: 'direct_rows_per_transaction', known_limitations: [] };
    },
    async status(id, signal) {
      check(signal);
      const branch = find(id);
      return { id: branch.id, status: branch.status, access: branch.mode === 'native_write' ? 'read_write' : 'read_only',
        layout: branch.mode === 'native_write' ? 'native_copy' : 'sparse_delta', expires_at: branch.expires_at,
        expired: branch.expires_at <= now(), lease_version: 1, snapshot_rows: 25005,
        lifecycle_phase: branch.status === 'active' ? 'active' : branch.status, reason: null };
    },
    async effectivePolicy(id, signal) {
      check(signal);
      return clone(policies[find(id).class as BranchClass]);
    },
    async list(signal) { check(signal); return clone(branches); },
    async create(request: CreateBranch, signal) {
      check(signal);
      if (!/^[a-z][a-z0-9-]{2,62}$/.test(request.name)) {
        throw new ApiError('Use 3–63 lowercase letters, digits or hyphens, starting with a letter.', 400, 'FG-2002');
      }
      if (branches.some(branch => branch.name === request.name && branch.status !== 'dropped')) {
        throw new ApiError('A live branch already has this name.', 409, 'FG-2003');
      }
      const branchClass = request.class ?? 'dev';
      const ttl = request.ttl_seconds ?? (['ci', 'agent'].includes(branchClass) ? 7200 : 86400);
      if (!Number.isInteger(ttl) || ttl < 1 || ttl > 86400) {
        throw new ApiError('Supply a TTL from 1 to 86400 seconds.', 400, 'FG-2002');
      }
      if (branchClass === 'staging' && request.mode === 'native_write') {
        throw new ApiError('Staging branches are read-only.', 403, 'FG-5001');
      }
      const branch: Branch = {
        id: nextBranchId++, name: request.name, class: branchClass, generation_id: 12, created_by: 'alex',
        expires_at: now() + ttl, status: request.mode === 'native_write' ? 'provisioning' : 'active', mode: request.mode ?? 'read_only',
        access: request.mode === 'native_write' ? 'read_write' : 'read_only',
        layout: request.mode === 'native_write' ? 'native_copy' : 'sparse_delta'
      };
      branches.push(branch);
      record(branch.id, 'branch_created');
      if (branch.status === 'provisioning') transitions.set(String(branch.id), { status: 'active', at: Date.now() + 1200 });
      return clone(branch);
    },
    async detail(id, signal) { check(signal); return clone(find(id)); },
    async drop(id, signal) {
      check(signal);
      const branch = find(id);
      if (branch.status !== 'dropped' && branch.status !== 'dropping') {
        branch.status = 'dropping';
        transitions.set(String(id), { status: 'dropped', at: Date.now() + 800 });
        record(id, 'branch_dropping', { reason: 'owner' });
      }
      return clone(branch);
    },
    async diff(id, signal) {
      check(signal);
      const branch = requireActive(id);
      const report = clone(exampleDiff);
      report.branch_id = branch.id;
      report.generation_id = branch.generation_id;
      report.native_write = branch.mode === 'native_write';
      report.replay_origin = { ...report.replay_origin!, generation_id: branch.generation_id };
      if (String(id) !== '101') report.tables = [];
      return report;
    },
    async downloadDiff(id, signal) {
      const report = await api.diff(id, signal);
      return new Blob([JSON.stringify(report, null, 2)], { type: 'application/json;charset=utf-8' });
    },
    async approvals(id, signal) {
      check(signal); find(id);
      for (const approval of approvals.get(String(id)) ?? []) {
        if (['pending', 'approved'].includes(approval.state) && approval.expires_at <= now()) approval.state = 'expired';
      }
      return clone(approvals.get(String(id)) ?? []);
    },
    async review(id, approvalId, approve, signal) {
      check(signal); requireActive(id);
      const approval = (approvals.get(String(id)) ?? []).find(item => String(item.id) === String(approvalId));
      if (!approval) throw new ApiError('Approval is unavailable.', 404, 'FG-2003');
      if (approval.state !== 'pending' || approval.expires_at <= now()) {
        throw new ApiError('The approval conflicts with an existing invocation or decision.', 409, 'FG-5003');
      }
      approval.state = approve ? 'approved' : 'denied';
      record(id, 'approval_state', { approval_id: approval.id, policy_version: approval.policy_version, state: approval.state }, 'reviewer');
      return { state: approval.state };
    },
    async policy(branchClass, signal) { check(signal); return clone(policies[branchClass]); },
    async updatePolicy(branchClass, request: UpdatePolicy, signal) {
      check(signal);
      const current = policies[branchClass];
      if (String(current.version) !== String(request.expected_version)) {
        throw new ApiError('The policy version changed.', 409, 'FG-5001');
      }
      if (BigInt(request.max_transaction_rows) < 0n
        || (request.table_limit_bps !== null && (!Number.isInteger(request.table_limit_bps) || request.table_limit_bps < 1 || request.table_limit_bps > 10000))
        || (request.approval_after_rows !== null && (BigInt(request.approval_after_rows) < 0n || BigInt(request.approval_after_rows) > BigInt(request.max_transaction_rows)))
        || (branchClass === 'staging' && (BigInt(request.max_transaction_rows) !== 0n || request.table_limit_bps !== null || request.approval_after_rows !== null))) {
        throw new ApiError('Invalid policy request.', 400, 'FG-5001');
      }
      const version = BigInt(current.version) + 1n;
      policies[branchClass] = {
        class: branchClass, version: version <= BigInt(Number.MAX_SAFE_INTEGER) ? Number(version) : String(version),
        max_transaction_rows: request.max_transaction_rows, table_limit_bps: request.table_limit_bps,
        approval_after_rows: request.approval_after_rows
      };
      return clone(policies[branchClass]);
    },
    async audit(id, query = {}, signal) {
      check(signal); find(id);
      const events = (audit.get(String(id)) ?? []).filter(event =>
        BigInt(event.id) > BigInt(query.after ?? 0)
        && (query.since === undefined || event.occurred_at >= query.since)
        && (query.until === undefined || event.occurred_at < query.until)
        && (query.event_type === undefined || event.event_type === query.event_type)
      );
      const page = events.slice(0, query.limit ?? 100);
      return { events: clone(page), next_after: events.length > page.length ? page[page.length - 1].id : null };
    },
    async bindings(signal) {
      check(signal);
      return clone(bindings.map(binding => ({ ...binding, branch_status: binding.branch_id === null ? null : find(binding.branch_id).status })));
    },
    async health(signal) { check(signal); return { live: { ok: true, status: 204 }, ready: { ok: true, status: 204 } }; }
  };
  return api;
}
