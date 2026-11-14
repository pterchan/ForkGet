import { LosslessNumber, parse, stringify } from 'lossless-json';
import type {
  Approval, AuditHealth, AuditPage, AuditQuery, Branch, BranchClass, BranchStatus, Capabilities, ConsoleApi, CreateBranch,
  GitHubBinding, HealthProbe, Id, Integer, Policy, RowDiff, UpdatePolicy
} from './model';

export class ApiError extends Error {
  constructor(
    message: string,
    public readonly status: number | null,
    public readonly code: string | null = null,
    public readonly component?: string,
    public readonly reason?: string,
    public readonly hint?: string
  ) {
    super(message);
    this.name = 'ApiError';
  }
}

export interface ApiOptions {
  token: string;
  baseUrl?: string;
  fetch?: typeof globalThis.fetch;
  timeoutMs?: number;
}

type RecordValue = Record<string, unknown>;
const isRecord = (value: unknown): value is RecordValue => value !== null && typeof value === 'object' && !Array.isArray(value);
const isInteger = (value: unknown): value is Integer =>
  (typeof value === 'number' && Number.isSafeInteger(value)) || (typeof value === 'string' && /^-?(?:0|[1-9]\d*)$/.test(value));
const isString = (value: unknown): value is string => typeof value === 'string';
const isTimestamp = (value: unknown): value is number => typeof value === 'number' && Number.isSafeInteger(value);

/** Preserve signed-64-bit identifiers without converting database cell strings. */
export function parseWireJson(text: string): unknown {
  return parse(text, undefined, {
    parseNumber: (value: string) => {
      const number = Number(value);
      return /^-?\d+$/.test(value) && !Number.isSafeInteger(number) ? value : number;
    }
  });
}

function invalidResponse(): never {
  throw new ApiError('The control service returned an invalid response.', null, 'INVALID_RESPONSE');
}

function record(value: unknown): RecordValue {
  return isRecord(value) ? value : invalidResponse();
}

function array<T>(value: unknown, check: (item: unknown) => boolean): T[] {
  return Array.isArray(value) && value.every(check) ? value as T[] : invalidResponse();
}

function isBranch(value: unknown): value is Branch {
  return isRecord(value) && isInteger(value.id) && isInteger(value.generation_id)
    && ['name', 'class', 'created_by', 'status', 'mode'].every(key => isString(value[key]))
    && isTimestamp(value.expires_at);
}

function branch(value: unknown): Branch {
  return isBranch(value) ? value : invalidResponse();
}

function policy(value: unknown): Policy {
  const data = record(value);
  if (!isString(data.class) || !isInteger(data.version) || !isInteger(data.max_transaction_rows)
    || !(data.table_limit_bps === null || isTimestamp(data.table_limit_bps))
    || !(data.approval_after_rows === null || isInteger(data.approval_after_rows))
    || !(data.small_table_floor === undefined || isInteger(data.small_table_floor))
    || !(data.effective_revision === undefined || isInteger(data.effective_revision))
    || !(data.grant_expires_at === undefined || data.grant_expires_at === null || isTimestamp(data.grant_expires_at))) invalidResponse();
  return data as unknown as Policy;
}

function auditHealth(value: unknown): AuditHealth {
  const data = record(value);
  const isCount = (value: unknown) => isInteger(value) && !String(value).startsWith('-');
  if (!(data.protected_writes_paused === undefined || data.protected_writes_paused === null || typeof data.protected_writes_paused === 'boolean')
    || !['witness_ready', 'storage_invalidated', 'requires_witness', 'cleanup_blocked'].every(key => typeof data[key] === 'boolean')
    || !['pending_delivery', 'sql_unresolved_unknown', 'mongo_unknown', 'mongo_partial'].every(key => isCount(data[key]))
    || !(data.oldest_pending_at === null || isTimestamp(data.oldest_pending_at))
    || !(data.latest_mongo_observation === null || (isRecord(data.latest_mongo_observation)
      && isString(data.latest_mongo_observation.attempt_id) && isString(data.latest_mongo_observation.outcome)
      && 'observation' in data.latest_mongo_observation))) invalidResponse();
  return data as unknown as AuditHealth;
}

function isApproval(value: unknown): value is Approval {
  return isRecord(value) && ['id', 'policy_version', 'table_id', 'rows'].every(key => isInteger(value[key]))
    && isString(value.kind) && isString(value.state) && isTimestamp(value.expires_at);
}

function rowDiff(value: unknown): RowDiff {
  const data = record(value);
  if (!isTimestamp(data.format_version) || !isString(data.engine) || !isInteger(data.branch_id)
    || !isInteger(data.generation_id) || typeof data.native_write !== 'boolean'
    || !(data.replay_origin === null || (isRecord(data.replay_origin)
      && isString(data.replay_origin.deployment_id) && isInteger(data.replay_origin.generation_id)
      && isString(data.replay_origin.snapshot)))) invalidResponse();
  array(data.tables, table => isRecord(table) && isInteger(table.id) && isString(table.schema)
    && isString(table.table) && (table.generated_key === null || isString(table.generated_key))
    && Array.isArray(table.columns) && table.columns.every(column => isRecord(column)
      && isString(column.name) && isString(column.type_name) && typeof column.nullable === 'boolean'
      && (column.primary_key_ordinal === null || isTimestamp(column.primary_key_ordinal)))
    && Array.isArray(table.changes) && table.changes.every(change => isRecord(change)
      && isString(change.operation) && Array.isArray(change.key) && change.key.every(isString)
      && ['before', 'after'].every(key => change[key] === null || (Array.isArray(change[key])
        && change[key].every((cell: unknown) => cell === null || isString(cell))))));
  return data as unknown as RowDiff;
}

function auditPage(value: unknown): AuditPage {
  const data = record(value);
  if (!(data.next_after === null || isInteger(data.next_after))) invalidResponse();
  array(data.events, event => isRecord(event) && isInteger(event.id) && isTimestamp(event.occurred_at)
    && isString(event.actor) && isString(event.event_type) && isRecord(event.payload));
  return data as unknown as AuditPage;
}

function isBinding(value: unknown): value is GitHubBinding {
  return isRecord(value) && isInteger(value.repository_id) && isInteger(value.installation_id)
    && ['source_kind', 'source_key', 'state'].every(key => isString(value[key]))
    && (value.branch_id === null || isInteger(value.branch_id))
    && ['name', 'branch_status', 'last_error'].every(key => value[key] === null || isString(value[key]));
}

function pathId(value: Id): string {
  if (!isInteger(value) || !/^[1-9]\d*$/.test(String(value))) {
    throw new ApiError('A positive immutable branch or approval ID is required.', null, 'INVALID_ID');
  }
  return encodeURIComponent(String(value));
}

function wireInteger(value: Integer | null): number | LosslessNumber | null {
  if (value === null) return null;
  if (!isInteger(value)) throw new ApiError('A whole-number policy value is required.', null, 'INVALID_REQUEST');
  return typeof value === 'string' ? new LosslessNumber(value) : value;
}

function policyBody(request: UpdatePolicy): string {
  return stringify({
    expected_version: wireInteger(request.expected_version),
    max_transaction_rows: wireInteger(request.max_transaction_rows),
    table_limit_bps: request.table_limit_bps,
    approval_after_rows: wireInteger(request.approval_after_rows)
  }) ?? invalidResponse();
}

/** Calls only the same-origin proxy. It never chooses a backend or falls back to demo data. */
export function createApi(options: ApiOptions): ConsoleApi {
  const baseUrl = (options.baseUrl ?? '/api').replace(/\/$/, '');
  if (!/^\/(?!\/)[^?#]*$/.test(baseUrl)) {
    throw new ApiError('The API base must be a same-origin path.', null, 'INVALID_API_BASE');
  }
  const fetcher = options.fetch ?? globalThis.fetch.bind(globalThis);
  const timeoutMs = options.timeoutMs ?? 20_000;

  async function requestDocument(path: string, init: RequestInit = {}, signal?: AbortSignal): Promise<{ data: unknown; bytes: ArrayBuffer; status: number }> {
    const controller = new AbortController();
    const abort = () => controller.abort();
    if (signal?.aborted) controller.abort();
    signal?.addEventListener('abort', abort, { once: true });
    const timer = setTimeout(() => controller.abort(), timeoutMs);
    try {
      const headers = new Headers({ Accept: 'application/json' });
      if (!path.startsWith('/health/')) headers.set('Authorization', `Bearer ${options.token}`);
      if (init.body) headers.set('Content-Type', 'application/json');
      const response = await fetcher(`${baseUrl}${path}`, {
        ...init, headers, signal: controller.signal, cache: 'no-store', credentials: 'omit', redirect: 'error'
      });
      if (response.status === 204 && response.ok) return { data: undefined, bytes: new ArrayBuffer(0), status: response.status };
      const bytes = await response.arrayBuffer();
      let data: unknown;
      try {
        data = parseWireJson(new TextDecoder().decode(bytes));
      } catch {
        if (response.ok) invalidResponse();
      }
      if (!response.ok) {
        const problem = isRecord(data) ? data : {};
        throw new ApiError(
          isString(problem.message) ? problem.message : `The control service returned HTTP ${response.status}.`,
          response.status,
          isString(problem.code) ? problem.code : null,
          isString(problem.component) ? problem.component : undefined,
          isString(problem.reason) ? problem.reason : undefined,
          isString(problem.hint) ? problem.hint : undefined
        );
      }
      return { data, bytes, status: response.status };
    } catch (error) {
      if (signal?.aborted) throw new DOMException('The request was cancelled.', 'AbortError');
      if (error instanceof ApiError) throw error;
      if (controller.signal.aborted) throw new ApiError('The control service did not respond in time.', null, 'CLIENT_TIMEOUT');
      throw new ApiError('The control service could not be reached.', null, 'NETWORK_ERROR');
    } finally {
      clearTimeout(timer);
      signal?.removeEventListener('abort', abort);
    }
  }

  async function request(path: string, init: RequestInit = {}, signal?: AbortSignal): Promise<unknown> {
    return (await requestDocument(path, init, signal)).data;
  }

  async function probe(path: string, signal?: AbortSignal): Promise<HealthProbe> {
    try {
      const document = await requestDocument(path, {}, signal);
      return { ok: true, status: document.status };
    } catch (error) {
      if (!(error instanceof ApiError)) throw error;
      return { ok: false, status: error.status, code: error.code, message: error.message, component: error.component };
    }
  }

  return {
    async status(id, signal) {
      const data = record(await request(`/v1/branches/${pathId(id)}/status`, {}, signal));
      if (!isInteger(data.id) || !isString(data.status) || !isString(data.access) || !isString(data.layout)
        || !isTimestamp(data.expires_at) || typeof data.expired !== 'boolean' || !isInteger(data.lease_version)
        || !isInteger(data.snapshot_rows) || !(data.lifecycle_phase === null || isString(data.lifecycle_phase))
        || !(data.reason === null || isString(data.reason))) invalidResponse();
      if (data.audit !== undefined) data.audit = auditHealth(data.audit);
      return data as unknown as BranchStatus;
    },
    async effectivePolicy(id, signal) {
      return policy(await request(`/v1/branches/${pathId(id)}/policy`, {}, signal));
    },
    async capabilities(signal) {
      const data = record(await request('/v1/capabilities', {}, signal));
      if (!['mysql', 'postgresql', 'tidb', 'mongodb'].includes(String(data.engine))
        || !isString(data.new_branch_default_access) || !isString(data.budget_scope)
        || !isTimestamp(data.native_copy_limit) || !isTimestamp(data.physical_generation_limit)) invalidResponse();
      array(data.known_limitations, value => isRecord(value) && isString(value.reason) && isString(value.action));
      return data as unknown as Capabilities;
    },
    async list(signal) { return array<Branch>(await request('/v1/branches', {}, signal), isBranch); },
    async create(body: CreateBranch, signal) {
      return branch(await request('/v1/branches', { method: 'POST', body: JSON.stringify(body) }, signal));
    },
    async detail(id, signal) { return branch(await request(`/v1/branches/${pathId(id)}`, {}, signal)); },
    async drop(id, signal) { return branch(await request(`/v1/branches/${pathId(id)}`, { method: 'DELETE' }, signal)); },
    async diff(id, signal) { return rowDiff(await request(`/v1/branches/${pathId(id)}/diff`, {}, signal)); },
    async downloadDiff(id, signal) {
      const document = await requestDocument(`/v1/branches/${pathId(id)}/diff`, {}, signal);
      rowDiff(document.data);
      return new Blob([document.bytes], { type: 'application/json;charset=utf-8' });
    },
    async approvals(id, signal) {
      const data = record(await request(`/v1/branches/${pathId(id)}/approvals`, {}, signal));
      return array<Approval>(data.approvals, isApproval);
    },
    async review(id, approvalId, approve, signal) {
      const data = record(await request(`/v1/branches/${pathId(id)}/approvals/${pathId(approvalId)}`, {
        method: 'POST', body: JSON.stringify({ approve })
      }, signal));
      return isString(data.state) ? { state: data.state } : invalidResponse();
    },
    async policy(branchClass: BranchClass, signal) {
      return policy(await request(`/v1/policies/${encodeURIComponent(branchClass)}`, {}, signal));
    },
    async updatePolicy(branchClass, body, signal) {
      return policy(await request(`/v1/policies/${encodeURIComponent(branchClass)}`, { method: 'PUT', body: policyBody(body) }, signal));
    },
    async audit(id, query: AuditQuery = {}, signal) {
      const params = new URLSearchParams();
      for (const [key, value] of Object.entries(query)) if (value !== undefined) params.set(key, String(value));
      const suffix = params.size ? `?${params}` : '';
      return auditPage(await request(`/v1/branches/${pathId(id)}/audit${suffix}`, {}, signal));
    },
    async bindings(signal) {
      const data = record(await request('/v1/github/bindings', {}, signal));
      return array<GitHubBinding>(data.bindings, isBinding);
    },
    async health(signal) {
      const [live, ready] = await Promise.all([probe('/health/live', signal), probe('/health/ready', signal)]);
      return { live, ready };
    }
  };
}
