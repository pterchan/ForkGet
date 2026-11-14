/** Public control API models; integer identities are never rounded. */
export type Integer = number | string;
export type Id = Integer;
export type BranchClass = 'dev' | 'ci' | 'agent' | 'staging';
export type Engine = 'mysql' | 'postgresql' | 'tidb' | 'mongodb';
export type Json = null | boolean | number | string | Json[] | { [key: string]: Json };

export interface Branch {
  id: Id;
  name: string;
  class: string;
  generation_id: Id;
  created_by: string;
  expires_at: number;
  status: string;
  mode: string;
  /** Optional authoritative metadata; legacy mode does not infer these. */
  access?: string;
  layout?: string;
  read_strategy?: string;
  expired?: boolean;
}

export interface CreateBranch {
  name: string;
  class?: BranchClass;
  ttl_seconds?: number;
  mode?: 'read_only' | 'native_write';
}

export interface Policy {
  class: BranchClass;
  version: Integer;
  max_transaction_rows: Integer;
  table_limit_bps: number | null;
  approval_after_rows: Integer | null;
  small_table_floor?: Integer;
  effective_revision?: Integer;
  grant_expires_at?: number | null;
}

export interface Capabilities {
  engine: Engine;
  new_branch_default_access: string;
  native_copy_limit: number;
  physical_generation_limit: number;
  budget_scope: string;
  known_limitations: { reason: string; action: string }[];
}

export interface BranchStatus {
  id: Id;
  status: string;
  access: string;
  layout: string;
  expires_at: number;
  expired: boolean;
  lease_version: Integer;
  snapshot_rows: Integer;
  lifecycle_phase: string | null;
  reason: string | null;
  audit?: AuditHealth;
}

export interface AuditHealth {
  protected_writes_paused?: boolean | null;
  witness_ready: boolean;
  storage_invalidated: boolean;
  requires_witness: boolean;
  pending_delivery: Integer;
  sql_unresolved_unknown: Integer;
  mongo_unknown: Integer;
  mongo_partial: Integer;
  oldest_pending_at: number | null;
  cleanup_blocked: boolean;
  latest_mongo_observation: {
    attempt_id: string;
    outcome: string;
    observation: Json;
  } | null;
}

export interface UpdatePolicy {
  expected_version: Integer;
  max_transaction_rows: Integer;
  table_limit_bps: number | null;
  approval_after_rows: Integer | null;
}

export interface Approval {
  id: Id;
  policy_version: Integer;
  table_id: Id;
  kind: string;
  rows: Integer;
  state: string;
  expires_at: number;
}

export interface AuditEvent {
  id: Id;
  occurred_at: number;
  actor: string;
  event_type: string;
  payload: { [key: string]: Json };
}

export interface AuditPage {
  events: AuditEvent[];
  next_after: Id | null;
}

export interface AuditQuery {
  since?: number;
  until?: number;
  event_type?: string;
  after?: Id;
  limit?: number;
}

export interface ReplayOrigin {
  deployment_id: string;
  generation_id: Id;
  snapshot: string;
}

export interface CatalogColumn {
  name: string;
  type_name: string;
  nullable: boolean;
  primary_key_ordinal: number | null;
}

export interface RowChange {
  operation: string;
  key: string[];
  before: (string | null)[] | null;
  after: (string | null)[] | null;
}

export interface TableChanges {
  id: Id;
  schema: string;
  table: string;
  generated_key: string | null;
  columns: CatalogColumn[];
  changes: RowChange[];
}

export interface RowDiff {
  format_version: number;
  engine: string;
  branch_id: Id;
  generation_id: Id;
  replay_origin: ReplayOrigin | null;
  native_write: boolean;
  tables: TableChanges[];
}

export interface GitHubBinding {
  repository_id: Id;
  installation_id: Id;
  source_kind: string;
  source_key: string;
  name: string | null;
  branch_id: Id | null;
  branch_status: string | null;
  state: string;
  last_error: string | null;
}

export interface HealthProbe {
  ok: boolean;
  status: number | null;
  code?: string | null;
  message?: string;
  component?: string;
}

export interface HealthReport {
  live: HealthProbe;
  ready: HealthProbe;
}

export interface ConsoleApi {
  capabilities(signal?: AbortSignal): Promise<Capabilities>;
  status(id: Id, signal?: AbortSignal): Promise<BranchStatus>;
  effectivePolicy(id: Id, signal?: AbortSignal): Promise<Policy>;
  list(signal?: AbortSignal): Promise<Branch[]>;
  create(request: CreateBranch, signal?: AbortSignal): Promise<Branch>;
  detail(id: Id, signal?: AbortSignal): Promise<Branch>;
  drop(id: Id, signal?: AbortSignal): Promise<Branch>;
  diff(id: Id, signal?: AbortSignal): Promise<RowDiff>;
  downloadDiff(id: Id, signal?: AbortSignal): Promise<Blob>;
  approvals(id: Id, signal?: AbortSignal): Promise<Approval[]>;
  review(id: Id, approvalId: Id, approve: boolean, signal?: AbortSignal): Promise<{ state: string }>;
  policy(branchClass: BranchClass, signal?: AbortSignal): Promise<Policy>;
  updatePolicy(branchClass: BranchClass, request: UpdatePolicy, signal?: AbortSignal): Promise<Policy>;
  audit(id: Id, query?: AuditQuery, signal?: AbortSignal): Promise<AuditPage>;
  bindings(signal?: AbortSignal): Promise<GitHubBinding[]>;
  health(signal?: AbortSignal): Promise<HealthReport>;
}
