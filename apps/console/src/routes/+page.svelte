<script lang="ts">
  import { onMount } from 'svelte';
  import Icon from '$lib/Icon.svelte';
  import Dialog from '$lib/Dialog.svelte';
  import AuditHealth from '$lib/AuditHealth.svelte';
  import { t, locale, supportedLocales, setLocale, formatDate, formatNumber, formatRelativeTime } from '$lib/i18n';
  import type { TranslationKey, Locale } from '$lib/locales';
  import { createApi, ApiError } from '$lib/api';
  import { createDemoApi } from '$lib/demo';
  import type { ConsoleApi, Branch, BranchClass, BranchStatus, Capabilities, RowDiff, Approval, AuditPage, AuditQuery, Policy, GitHubBinding } from '$lib/model';
  import { connectionCommand, defaultPort, defaultSettings, type ConnectionSettings } from '$lib/connection';

  const navigation: { key: TranslationKey; icon: string; group: 'developer' | 'admin' }[] = [
    { key: 'branches', icon: 'branch', group: 'developer' }, { key: 'tools', icon: 'terminal', group: 'developer' },
    { key: 'deployment', icon: 'server', group: 'admin' }, { key: 'snapshots', icon: 'layers', group: 'admin' },
    { key: 'policies', icon: 'shield', group: 'admin' }, { key: 'review_queue', icon: 'check', group: 'admin' }, { key: 'github', icon: 'git', group: 'admin' }
  ];
  const classes = ['dev', 'ci', 'agent', 'staging'] as const;
  const tabs = ['connection', 'changes', 'approvals', 'audit'] as const;
  const knownLabels: Record<string, TranslationKey> = { active: 'active', provisioning: 'provisioning', dropping: 'dropping', dropped: 'dropped', pending: 'pending', approved: 'approved', consumed: 'consumed', denied: 'denied', expired: 'expired', invalidated: 'invalidated', read_only: 'read_only', read_write: 'writable', native_write: 'writable', sparse_delta: 'sparse_delta', native_copy: 'native_copy', unknown: 'unknown', failed: 'failed', insert: 'inserted', update: 'updated', delete: 'deleted' };
  let api: ConsoleApi | null = null;
  let demo = $state(false);
  let authenticated = $state(false);
  let token = $state('');
  let loginBusy = $state(false);
  let settings = $state<ConnectionSettings>({ ...defaultSettings });
  let page = $state('branches');
  let tab = $state<(typeof tabs)[number]>('connection');
  let branchId = $state('');
  let branches = $state<Branch[]>([]);
  let selected = $state<Branch | null>(null);
  let diff = $state<RowDiff | null>(null);
  let approvals = $state<Approval[]>([]);
  let audit = $state<AuditPage | null>(null);
  let policy = $state<Policy | null>(null);
  let effectivePolicy = $state<Policy | null>(null);
  let branchStatus = $state<BranchStatus | null>(null);
  let capabilities = $state<Capabilities | null>(null);
  let bindings = $state<GitHubBinding[]>([]);
  let health = $state<Awaited<ReturnType<ConsoleApi['health']>> | null>(null);
  let loading = $state(false);
  let error = $state<unknown>(null);
  let actionError = $state<unknown>(null);
  let stale = $state(false);
  let lastRefreshed = $state<number | null>(null);
  let search = $state('');
  let statusFilter = $state('all');
  let classFilter = $state('all');
  let operationFilter = $state('all');
  let tableFilter = $state('all');
  let auditType = $state('');
  let auditSince = $state('');
  let auditUntil = $state('');
  let appliedAuditFilters: AuditQuery = {};
  let policyClass = $state<BranchClass>('dev');
  let editRows = $state('');
  let editTable = $state('');
  let editApproval = $state('');
  let policyDirty = $state(false);
  let inspectId = $state('');
  let reviewBranchId = $state('');
  let mobileNav = $state(false);
  let narrow = $state(false);
  let sidebar = $state<HTMLElement>();
  let menuButton = $state<HTMLButtonElement>();
  let createOpen = $state(false);
  let dropOpen = $state(false);
  let newName = $state('');
  let newClass = $state<BranchClass>('dev');
  let newMode = $state<'read_only' | 'native_write'>('read_only');
  let ttl = $state('24');
  let actionBusy = $state(false);
  let message = $state('');
  let now = $state(Date.now());
  let requestEpoch = 0;
  let controller: AbortController | null = null;
  let policyEpoch = 0;
  let loginEpoch = 0;
  let loginController: AbortController | null = null;
  let messageTimer: ReturnType<typeof setTimeout>;
  const filtered = $derived(branches.filter((b) => b.name.toLowerCase().includes(search.toLowerCase()) && (statusFilter === 'all' || branchState(b) === statusFilter) && (classFilter === 'all' || b.class === classFilter)));
  const activeBranches = $derived(branches.filter((b) => branchState(b) === 'active'));
  const expiringBranches = $derived(activeBranches.filter((b) => b.expires_at * 1000 - now < 3_600_000));
  const currentTitle = $derived(page === 'branch' ? selected?.name || $t('branch_details') : $t((page in knownLabels ? knownLabels[page] : page) as TranslationKey));

  function label(value?: string): string { return value && !knownLabels[value] ? value : $t(knownLabels[value || 'unknown'] || 'unknown'); }
  function variant(state: string) { return ['dropping', 'provisioning', 'pending'].includes(state) ? 'warning' : ['denied', 'failed'].includes(state) ? 'danger' : ['dropped', 'expired', 'invalidated', 'consumed', 'unknown'].includes(state) ? 'neutral' : ''; }
  function access(branch: Branch) { return branch.access || (branch.mode === 'native_write' ? 'read_write' : 'unknown'); }
  function layout(branch: Branch) { return branch.layout || (branch.mode === 'native_write' ? 'native_copy' : 'sparse_delta'); }
  function branchState(branch: Branch) { return ['active', 'provisioning'].includes(branch.status) && (branch.expired || branch.expires_at * 1000 <= now) ? 'expired' : branch.status; }
  function notify(text: string) { message = text; clearTimeout(messageTimer); messageTimer = setTimeout(() => message = '', 4500); }
  function errorKey(value: unknown): TranslationKey {
    if (!(value instanceof ApiError)) return 'error_unknown';
    if (value.code === 'INVALID_RESPONSE') return 'error_invalid_response';
    if (value.code === 'CLIENT_TIMEOUT') return 'error_timeout';
    if (value.code?.startsWith('INVALID_')) return 'error_validation';
    if (value.status === null || value.status === 0) return 'error_network';
    return ({ 401: 'error_unauthorized', 403: 'error_forbidden', 404: 'error_not_found', 409: 'error_conflict' } as Record<number, TranslationKey>)[value.status] || 'error_server';
  }
  function safeDetail(value: unknown) { return value instanceof Error ? value.message : $t('error_unknown'); }
  function navigate(target: string) { if (mobileNav) toggleNavigation(false); window.location.hash = target; }
  function toggleNavigation(open: boolean) {
    mobileNav = open;
    requestAnimationFrame(() => { if (open) sidebar?.querySelector<HTMLElement>('a,button')?.focus(); else if (narrow) menuButton?.focus(); });
  }
  function readRoute() {
    const parts = window.location.hash.slice(1).split('/');
    const nextPage = parts[0] || 'branches';
    page = ['branch', 'preferences', ...navigation.map((item) => item.key)].includes(nextPage) ? nextPage : 'branches';
    branchId = page === 'branch' && /^\d+$/.test(parts[1] || '') ? parts[1] : '';
    tab = tabs.includes(parts[2] as typeof tab) ? parts[2] as typeof tab : 'connection';
    selected = null; diff = null; approvals = []; audit = null; policy = null; bindings = []; health = null; effectivePolicy = null; branchStatus = null; capabilities = null;
    operationFilter = 'all'; tableFilter = 'all'; error = null; actionError = null; policyDirty = false;
    if (authenticated) void refresh();
  }
  async function connect() {
    if (!token.trim()) return;
    const epoch = ++loginEpoch;
    loginController?.abort(); loginController = new AbortController();
    loginBusy = true; error = null;
    const candidate = createApi({ token: token.trim() });
    try {
      const result = await candidate.list(loginController.signal);
      if (epoch !== loginEpoch) return;
      branches = result; api = candidate; demo = false; authenticated = true; token = ''; lastRefreshed = Date.now(); saveSettings(); readRoute();
    } catch (cause) { if (epoch === loginEpoch) error = cause; }
    finally { if (epoch === loginEpoch) loginBusy = false; }
  }
  function startDemo() { loginEpoch++; loginController?.abort(); loginBusy = false; api = createDemoApi(); demo = true; authenticated = true; token = ''; error = null; readRoute(); }
  function signOut() {
    loginEpoch++; loginController?.abort(); loginBusy = false;
    requestEpoch++; policyEpoch++; controller?.abort(); mobileNav = false; reviewBranchId = ''; api = null; token = ''; authenticated = false; demo = false;
    branches = []; selected = null; diff = null; approvals = []; audit = null; policy = null; bindings = []; health = null; effectivePolicy = null; branchStatus = null; capabilities = null;
    error = null; actionError = null; stale = false; lastRefreshed = null; createOpen = false; dropOpen = false; history.replaceState(null, '', location.pathname + location.hash);
  }
  function saveSettings() { try { localStorage.setItem('forkget.console.connection', JSON.stringify(settings)); } catch { /* Preferences are optional in private browser contexts. */ } }
  async function refresh(quiet = false) {
    if (!api) return;
    const currentApi = api;
    const epoch = ++requestEpoch;
    controller?.abort(); controller = new AbortController();
    const signal = controller.signal;
    if (!quiet) loading = true;
    const canRead = ['branches', 'policies', 'github', 'deployment'].includes(page) || (page === 'branch' && branchId) || (page === 'review_queue' && reviewBranchId);
    if (!canRead) { loading = false; return; }
    try {
      if (page === 'branches') { const result = await currentApi.list(signal); if (epoch !== requestEpoch) return; branches = result; }
      else if (page === 'branch' && branchId) {
        const item = await currentApi.detail(branchId, signal); if (epoch !== requestEpoch) return; selected = item;
        const observations = await Promise.allSettled([currentApi.status(branchId, signal), currentApi.effectivePolicy(branchId, signal)]);
        if (epoch !== requestEpoch) return;
        branchStatus = observations[0].status === 'fulfilled' ? observations[0].value : null;
        effectivePolicy = observations[1].status === 'fulfilled' ? observations[1].value : null;
        if (branchStatus) selected = { ...item, ...branchStatus };
        if (tab === 'changes' && item.status === 'active') { const result = await currentApi.diff(branchId, signal); if (epoch !== requestEpoch) return; diff = result; }
        if (tab === 'approvals') { const result = await currentApi.approvals(branchId, signal); if (epoch !== requestEpoch) return; approvals = result; }
        if (tab === 'audit') {
          const filters = { event_type: auditType || undefined, since: auditSince ? Math.floor(new Date(auditSince).getTime() / 1000) : undefined, until: auditUntil ? Math.floor(new Date(auditUntil).getTime() / 1000) : undefined, limit: 30 };
          const result = await currentApi.audit(branchId, filters, signal);
          if (epoch !== requestEpoch) return; audit = result; appliedAuditFilters = filters;
        }
      } else if (page === 'policies') { const result = await currentApi.policy(policyClass, signal); if (epoch !== requestEpoch) return; policy = result; if (!policyDirty) loadPolicyFields(result); }
      else if (page === 'github') { const result = await currentApi.bindings(signal); if (epoch !== requestEpoch) return; bindings = result; }
      else if (page === 'deployment') {
        const observations = await Promise.allSettled([currentApi.health(signal), currentApi.capabilities(signal)]);
        if (epoch !== requestEpoch) return;
        if (observations[0].status === 'rejected') throw observations[0].reason;
        const result = observations[0].value; health = result;
        capabilities = observations[1].status === 'fulfilled' ? observations[1].value : null;
        if (result.live.status === null && result.ready.status === null) throw new ApiError(result.live.message || '', null, result.live.code || 'NETWORK_ERROR');
      }
      else if (page === 'review_queue' && reviewBranchId) { const result = await currentApi.approvals(reviewBranchId, signal); if (epoch !== requestEpoch) return; approvals = result; }
      if (epoch !== requestEpoch) return;
      stale = false; error = null; lastRefreshed = Date.now();
    } catch (cause) { if (epoch !== requestEpoch || signal.aborted) return; stale = true; error = cause; }
    finally { if (epoch === requestEpoch) loading = false; }
  }
  function loadPolicyFields(value: Policy) { editRows = String(value.max_transaction_rows); editTable = value.table_limit_bps === null ? '' : String(value.table_limit_bps); editApproval = value.approval_after_rows === null ? '' : String(value.approval_after_rows); }
  function openCreate() { actionError = null; newName = ''; newClass = 'dev'; newMode = 'read_only'; ttl = '24'; createOpen = true; }
  function changeClass() { ttl = ['ci', 'agent'].includes(newClass) ? '2' : '24'; if (newClass === 'staging') newMode = 'read_only'; }
  async function createBranch(event: SubmitEvent) {
    event.preventDefault(); if (!api) return;
    actionBusy = true; actionError = null;
    const currentApi = api;
    try {
      const branch = await currentApi.create({ name: newName, class: newClass, mode: newMode, ttl_seconds: Math.round(Number(ttl) * 3600) });
      if (api !== currentApi) return;
      createOpen = false; notify($t(branch.status === 'active' ? 'branch_created' : 'creating_branch')); navigate(`branch/${branch.id}/connection`);
    } catch (cause) { if (api === currentApi) actionError = cause; }
    finally { actionBusy = false; }
  }
  async function dropBranch() {
    if (!api || !selected) return;
    const currentApi = api; const id = selected.id;
    actionBusy = true; actionError = null;
    try { const result = await currentApi.drop(id); if (api !== currentApi) return; selected = result; dropOpen = false; notify($t(result.status === 'dropped' ? 'branch_dropped' : 'dropping_branch')); await refresh(); }
    catch (cause) { if (api === currentApi) actionError = cause; }
    finally { actionBusy = false; }
  }
  async function review(approval: Approval, approve: boolean) {
    if (!api || approval.expires_at * 1000 <= Date.now()) return;
    const currentApi = api; const epoch = requestEpoch;
    const id = page === 'review_queue' ? reviewBranchId : branchId;
    actionBusy = true; actionError = null;
    try { await currentApi.review(id, approval.id, approve); if (api === currentApi && epoch === requestEpoch) await refresh(); }
    catch (cause) { if (api === currentApi && epoch === requestEpoch) actionError = cause; }
    finally { actionBusy = false; }
  }
  async function updatePolicy(event: SubmitEvent) {
    event.preventDefault(); if (!api || !policy) return;
    actionBusy = true; actionError = null;
    const epoch = ++policyEpoch; const targetClass = policyClass; const currentApi = api;
    try {
      const result = await currentApi.updatePolicy(targetClass, { expected_version: policy.version, max_transaction_rows: editRows, table_limit_bps: editTable === '' ? null : Number(editTable), approval_after_rows: editApproval === '' ? null : editApproval });
      if (epoch !== policyEpoch || currentApi !== api || targetClass !== policyClass) return;
      policy = result; loadPolicyFields(result); policyDirty = false; notify($t('saved'));
    } catch (cause) { if (epoch === policyEpoch && currentApi === api && targetClass === policyClass) actionError = cause; }
    finally { actionBusy = false; }
  }
  async function nextAuditPage() {
    if (!api || !audit?.next_after) return;
    const epoch = requestEpoch; const currentApi = api; const id = branchId;
    loading = true;
    try {
      const result = await currentApi.audit(id, { ...appliedAuditFilters, after: audit.next_after });
      if (epoch === requestEpoch && id === branchId && api === currentApi && audit) audit = { events: [...audit.events, ...result.events], next_after: result.next_after };
    } catch (cause) { if (epoch === requestEpoch) error = cause; }
    finally { if (epoch === requestEpoch) loading = false; }
  }
  async function copy(value: string) { try { await navigator.clipboard.writeText(value); notify($t('copied')); } catch { notify($t('error_unknown')); } }
  async function downloadDiff() {
    if (!api || !selected) return;
    const currentApi = api; const target = selected; const epoch = requestEpoch;
    actionBusy = true;
    try {
      const blob = await currentApi.downloadDiff(target.id);
      if (api !== currentApi || epoch !== requestEpoch || selected?.id !== target.id) return;
      const url = URL.createObjectURL(blob); const anchor = document.createElement('a'); anchor.href = url; anchor.download = `${target.name}-diff.json`; anchor.click(); URL.revokeObjectURL(url);
    } catch (cause) { if (api === currentApi && epoch === requestEpoch) actionError = cause; } finally { actionBusy = false; }
  }
  onMount(() => {
    try { const stored = JSON.parse(localStorage.getItem('forkget.console.connection') || 'null'); if (stored) for (const key of Object.keys(defaultSettings) as (keyof ConnectionSettings)[]) if (typeof stored[key] === 'string') settings[key] = stored[key]; } catch { /* A broken preference must not block login. */ }
    if (new URLSearchParams(location.search).get('preview') === '1') startDemo(); else readRoute();
    const media = matchMedia('(max-width: 1023px)');
    const resize = () => { narrow = media.matches; if (!narrow) mobileNav = false; };
    resize(); media.addEventListener('change', resize);
    const trapNavigation = (event: KeyboardEvent) => {
      if (!narrow || !mobileNav || !sidebar) return;
      if (event.key === 'Escape') { event.preventDefault(); toggleNavigation(false); return; }
      if (event.key !== 'Tab') return;
      const links = [...sidebar.querySelectorAll<HTMLElement>('a,button:not(:disabled)')];
      const first = links[0], last = links[links.length - 1];
      if (event.shiftKey && document.activeElement === first) { event.preventDefault(); last?.focus(); }
      else if (!event.shiftKey && document.activeElement === last) { event.preventDefault(); first?.focus(); }
    };
    document.addEventListener('keydown', trapNavigation);
    window.addEventListener('hashchange', readRoute);
    const timer = setInterval(() => {
      now = Date.now();
      if (!authenticated || document.hidden || loading || actionBusy || createOpen || dropOpen) return;
      if (page === 'branches' || (page === 'review_queue' && reviewBranchId) || (page === 'branch' && (tab === 'approvals' || selected?.status === 'provisioning' || selected?.status === 'dropping' || (tab === 'connection' && effectivePolicy?.grant_expires_at != null)))) void refresh(true);
    }, 3000);
    return () => { clearInterval(timer); clearTimeout(messageTimer); controller?.abort(); loginController?.abort(); media.removeEventListener('change', resize); document.removeEventListener('keydown', trapNavigation); window.removeEventListener('hashchange', readRoute); };
  });
</script>

<svelte:head><title>{authenticated ? `${currentTitle} · Forkget` : 'Forkget'}</title></svelte:head>

{#snippet languagePicker()}
  <label class="sr-only" for="locale-picker">{$t('language')}</label>
  <select id="locale-picker" class="locale-select" value={$locale} onchange={(event) => setLocale(event.currentTarget.value as Locale)} aria-label={$t('language')}>
    {#each supportedLocales as item}<option value={item.code}>{item.nativeLabel}</option>{/each}
  </select>
{/snippet}

{#snippet errorPanel(value: unknown, retry = true, policyConflict = false)}
  <div class="notice error" role="alert"><Icon name="alert" /><div><strong>{$t(policyConflict && value instanceof ApiError && value.status === 409 ? 'version_conflict' : errorKey(value))}</strong><details><summary>{$t('show_details')}</summary><div class="mono">{value instanceof ApiError ? value.code || `HTTP ${value.status ?? '—'}` : ''}</div><p>{safeDetail(value)}</p>{#if value instanceof ApiError && value.reason}<p class="mono">{$t('safe_reason')}: {value.reason}</p>{/if}{#if value instanceof ApiError && value.hint}<p>{value.hint}</p>{/if}</details>{#if retry}<button class="text-button" onclick={() => refresh()}>{$t('retry')}</button>{/if}</div></div>
{/snippet}

{#snippet unavailable(text: TranslationKey = 'unavailable_api')}
  <div class="notice neutral"><Icon name="info" /><div><strong>{$t('unavailable')}</strong><p>{$t(text)}</p></div></div>
{/snippet}

{#snippet command(value: string)}
  <div class="command"><pre>{value}</pre><button type="button" aria-label={$t('copy_command')} onclick={() => copy(value)}><Icon name="copy" size={14}/>{$t('copy')}</button></div>
{/snippet}

{#snippet badge(state: string)}<span class="badge {variant(state)}"><span class="dot"></span>{label(state)}</span>{/snippet}

{#if !authenticated}
  <div class="login-layout">
    <section class="login-story">
      <div class="brand"><div class="brand-mark"><Icon size={32}/></div><div><strong>Forkget</strong><small>{$t('data_environments')}</small></div></div>
      <div><p class="eyebrow">{$t('developer_workspace')} / {$t('administration')}</p><h1>{$t('app_tagline')}</h1><div class="login-art"><div class="login-node"><Icon name="layers"/>{$t('snapshot')}</div><Icon name="arrow"/><div class="login-node"><Icon/>{$t('branches')}</div><Icon name="arrow"/><div class="login-node"><Icon name="check"/>{$t('changes')}</div></div></div>
      <p class="hint">{$t('read_only_description')}</p>
    </section>
    <section class="login-form-wrap">
      <div class="login-form"><div class="locale-top row"><Icon name="globe" size={15}/>{@render languagePicker()}</div><p class="eyebrow">{$t('console_title')}</p><h2>{$t('login_title')}</h2><p class="muted">{$t('login_description')}</p>
        {#if error}{@render errorPanel(error, false)}{/if}
        <form onsubmit={(event) => { event.preventDefault(); void connect(); }}>
          <div class="field"><label for="owner-token">{$t('owner_token')}</label><input id="owner-token" type="password" bind:value={token} autocomplete="off" required maxlength="128" spellcheck="false"/><p class="hint">{$t('token_hint')}</p></div>
          <button class="primary full" disabled={loginBusy || !token.trim()} type="submit">{loginBusy ? $t('loading') : $t('connect_deployment')}<Icon name="arrow" size={16}/></button>
        </form>
        <div class="login-divider">{$t('preview_mode')}</div><button class="full" onclick={startDemo}><Icon name="branch"/>{$t('demo_action')}</button><p class="hint" style="margin-top:12px">{$t('demo_description')}</p>
      </div>
    </section>
  </div>
{:else}
  <a class="skip-link" href="#main-content">{$t('navigation')}</a>
  <div class="app-shell">
    <button class="nav-overlay" class:show={mobileNav} aria-label={$t('close')} onclick={() => toggleNavigation(false)}></button>
    <aside id="workspace-navigation" bind:this={sidebar} class="sidebar" class:open={mobileNav} inert={narrow && !mobileNav} aria-hidden={narrow && !mobileNav} aria-label={$t('navigation')}>
      <a class="brand" href="#branches" onclick={() => toggleNavigation(false)}><span class="brand-mark"><Icon size={32}/></span><div><strong>Forkget</strong><small>{$t('data_environments')}</small></div></a>
      <nav>
        {#each ['developer','admin'] as group}<div class="nav-section">{$t(group === 'developer' ? 'developer_workspace' : 'administration')}</div>
          {#each navigation.filter((item) => item.group === group) as item}<a href={`#${item.key}`} class="nav-link" class:active={page === item.key || (page === 'branch' && item.key === 'branches')} aria-current={page === item.key ? 'page' : undefined} onclick={() => toggleNavigation(false)}><Icon name={item.icon} size={17}/><span>{$t(item.key)}</span></a>{/each}
        {/each}
      </nav>
      <div class="sidebar-bottom"><div class="deployment-card"><div class="eyebrow">{$t('deployment')}</div><strong>{demo ? $t('sample_data') : settings.deployment}</strong><div class="row hint"><span class="badge {demo ? 'warning' : 'neutral'}">{demo ? $t('preview_mode') : $t('live_mode')}</span><span>{settings.engine}</span></div></div>
        <a class="nav-link" class:active={page === 'preferences'} href="#preferences" onclick={() => toggleNavigation(false)}><Icon name="settings" size={17}/>{$t('preferences')}</a>
        <button class="nav-link" onclick={signOut}><Icon name="arrow" size={17}/>{$t('sign_out')}</button>
      </div>
    </aside>
    <div class="main-shell" inert={narrow && mobileNav}>
      <header class="topbar"><button bind:this={menuButton} class="icon-button mobile-toggle" aria-expanded={mobileNav} aria-controls="workspace-navigation" onclick={() => toggleNavigation(!mobileNav)} aria-label={$t('menu')}><Icon name="menu"/></button><div class="breadcrumb"><span>{$t(navigation.find((item) => item.key === page)?.group === 'admin' ? 'administration' : 'developer_workspace')}</span><span>/</span><b>{currentTitle}</b></div><span class="spacer"></span><span class="connection-badge badge {stale ? 'warning' : 'neutral'}"><span class="dot"></span>{$t(stale ? 'disconnected' : 'connected')}</span><Icon name="globe" size={15}/>{@render languagePicker()}<div class="account-avatar" title={$t('owner')}>{demo ? 'D' : 'F'}</div></header>
      <div class="mode-strip" class:live={!demo}><Icon name={demo ? 'info' : 'shield'} size={13}/>{demo ? $t('preview_notice') : $t('live_notice')}</div>
      {#if loading}<div class="loading" role="progressbar" aria-label={$t('loading')}></div>{/if}
      <main class="workspace" id="main-content" tabindex="-1">
        {#if error}{@render errorPanel(error)}{/if}
        {#if stale && lastRefreshed}<div class="notice warning"><Icon name="clock"/><p>{$t('stale_data')} · {$t('last_refreshed')}: {formatDate(lastRefreshed, $locale)}</p></div>{/if}

        {#if page === 'branches'}
          <div class="page-head"><div><p class="eyebrow">{$t('developer_workspace')}</p><h1>{$t('branches')}</h1><p>{$t('app_tagline')}</p></div><div class="row"><button onclick={() => refresh()} disabled={loading}><Icon name="refresh" size={15}/>{$t('refresh')}</button><button class="primary" onclick={openCreate} disabled={stale}><Icon name="plus" size={16}/>{$t('new_branch')}</button></div></div>
          <div class="stats"><div class="stat"><div class="stat-icon"><Icon/></div><div><strong>{lastRefreshed ? formatNumber(branches.length, $locale) : '—'}</strong><span>{$t('branch_count', { count: branches.length })}</span></div></div><div class="stat"><div class="stat-icon"><Icon name="check"/></div><div><strong>{lastRefreshed ? formatNumber(activeBranches.length, $locale) : '—'}</strong><span>{$t('active_count', { count: activeBranches.length })}</span></div></div><div class="stat"><div class="stat-icon"><Icon name="clock"/></div><div><strong>{lastRefreshed ? formatNumber(expiringBranches.length, $locale) : '—'}</strong><span>{$t('expiring_count', { count: expiringBranches.length })}</span></div></div></div>
          <section class="panel" aria-label={$t('branches')}>
            <div class="toolbar"><div class="search-box"><Icon name="search" size={16}/><input aria-label={$t('search_branches')} placeholder={$t('search_branches')} bind:value={search}/></div><span class="spacer"></span><select aria-label={$t('status')} bind:value={statusFilter}><option value="all">{$t('status')}: {$t('all')}</option>{#each ['active','provisioning','expired','dropping','dropped'] as state}<option value={state}>{label(state)}</option>{/each}</select><select aria-label={$t('branch_class')} bind:value={classFilter}><option value="all">{$t('branch_class')}: {$t('all')}</option>{#each classes as value}<option>{value}</option>{/each}</select></div>
            {#if filtered.length}<!-- svelte-ignore a11y_no_noninteractive_tabindex (Keyboard access to horizontal table scrolling.) -->
<div class="table-scroll" tabindex="0" role="region" aria-label={$t('branches')}><table><thead><tr><th>{$t('name')}</th><th>{$t('status')}</th><th>{$t('branch_class')}</th><th>{$t('access')}</th><th>{$t('generation')}</th><th>{$t('expires')}</th><th><span class="sr-only">{$t('actions')}</span></th></tr></thead><tbody>
              {#each filtered as branch (String(branch.id))}<tr><td><div class="row"><div class="branch-symbol"><Icon size={17}/></div><div><a href={`#branch/${branch.id}/connection`} class="primary-name">{branch.name}</a><span class="subtext mono">#{branch.id} · {branch.created_by}</span></div></div></td><td>{@render badge(branchState(branch))}</td><td><span class="badge neutral">{branch.class}</span></td><td>{label(access(branch))}<span class="subtext">{label(layout(branch))}</span></td><td><span class="mono">g{branch.generation_id}</span></td><td>{formatDate(branch.expires_at * 1000, $locale)}<span class="subtext">{formatRelativeTime(branch.expires_at * 1000, $locale)}</span></td><td><a class="icon-button row" href={`#branch/${branch.id}/connection`} aria-label={`${$t('open')} ${branch.name}`}><Icon name="arrow" size={15}/></a></td></tr>{/each}
            </tbody></table></div>{:else if !loading && !error}<div class="empty"><div class="empty-icon"><Icon size={25}/></div><h2>{$t(branches.length ? 'no_results' : 'no_branches')}</h2><p>{$t('no_branches_hint')}</p>{#if branches.length}<button onclick={() => { search = ''; statusFilter = 'all'; classFilter = 'all'; }}>{$t('clear_filters')}</button>{:else}<button class="primary" onclick={openCreate}><Icon name="plus"/>{$t('new_branch')}</button>{/if}</div>{/if}
            <div class="table-footer"><span>{formatNumber(filtered.length, $locale)} / {formatNumber(branches.length, $locale)} {$t('branches')}</span><span>{$t('owner')}: {demo ? 'alex' : $t('permission_unknown')}</span></div>
          </section><div class="footer-note"><Icon name="shield" size={14}/>{$t('read_only_description')}</div>

        {:else if page === 'branch'}
          <a class="row" style="margin-bottom:20px;font-size:12px" href="#branches">← {$t('branches')}</a>
          {#if selected}
            <div class="page-head"><div><div class="row" style="margin-bottom:9px"><span class="eyebrow">{$t('branch_details')}</span><span class="mono muted">#{selected.id}</span></div><h1>{selected.name}</h1><div class="row wrap">{@render badge(branchState(selected))}<span class="badge neutral">{selected.class}</span><span class="muted">{selected.created_by}</span></div></div><div class="row"><button disabled={loading} onclick={() => refresh()}><Icon name="refresh" size={15}/>{$t('refresh')}</button><button class="danger" disabled={stale || ['dropped','dropping'].includes(selected.status)} onclick={() => { actionError = null; dropOpen = true; }}>{$t('drop_branch')}</button></div></div>
            <div class="overview-card"><div class="node"><Icon name="layers"/><div><small>{$t('source_generation')}</small><span class="mono">g{selected.generation_id}</span></div></div><Icon name="arrow"/><div class="node"><Icon/><div><small>{label(access(selected))}</small><span>{selected.name}</span></div></div><span class="spacer"></span><div><small>{$t('expires')}</small><span>{formatDate(selected.expires_at * 1000, $locale)}</span></div></div>
            <section class="panel"><nav class="tabs" aria-label={$t('branch_details')}>{#each tabs as item}<a class="tab" class:active={tab === item} aria-current={tab === item ? 'page' : undefined} href={`#branch/${selected?.id}/${item}`}>{$t(item)}</a>{/each}</nav><div id="detail-panel" aria-label={$t(tab)} class="panel-body">
              {#if tab === 'connection'}<h2>{$t('connect')}</h2><p class="muted">{$t('connect_description')}</p><dl class="detail-metadata"><div><dt>{$t('engine')}</dt><dd>{settings.engine}</dd></div><div><dt>{$t('database')}</dt><dd class="mono">{selected.name}</dd></div><div><dt>{$t('access')}</dt><dd>{label(access(selected))}</dd></div><div><dt>{$t('layout')}</dt><dd>{label(layout(selected))}</dd></div></dl>
                {#if branchState(selected) !== 'active'}<div class="notice warning"><Icon name="clock"/><p>{label(branchState(selected))} · {$t('branch_not_connectable')}</p></div>{/if}
                {#if branchStatus}<dl class="detail-metadata"><div><dt>{$t('lifecycle_phase')}</dt><dd>{branchStatus.lifecycle_phase || $t('not_reported')}</dd></div><div><dt>{$t('snapshot_rows')}</dt><dd>{String(branchStatus.snapshot_rows)}</dd></div></dl>{#if branchStatus.reason}<p class="hint mono">{$t('safe_reason')}: {branchStatus.reason}</p>{/if}{/if}
                {#if branchStatus?.audit}<AuditHealth health={branchStatus.audit}/>{/if}
                {#if effectivePolicy}
                  <h3>{$t('effective_policy')}</h3>
                  <dl class="detail-metadata" aria-label={$t('effective_policy')}>
                    <div><dt>{$t('policy_version')}</dt><dd>v{String(effectivePolicy.version)}</dd></div>
                    <div><dt>{$t('max_transaction_rows')}</dt><dd>{String(effectivePolicy.max_transaction_rows)}</dd></div>
                    <div><dt>{$t('table_limit_bps')}</dt><dd>{effectivePolicy.table_limit_bps === null ? $t('unlimited') : String(effectivePolicy.table_limit_bps)}</dd></div>
                    <div><dt>{$t('small_table_floor')}</dt><dd>{effectivePolicy.small_table_floor === undefined ? $t('not_reported') : String(effectivePolicy.small_table_floor)}</dd></div>
                    <div><dt>{$t('approval_after_rows')}</dt><dd>{effectivePolicy.approval_after_rows === null ? $t('disabled') : String(effectivePolicy.approval_after_rows)}</dd></div>
                    {#if effectivePolicy.grant_expires_at != null}<div><dt>{$t('grant_expires')}</dt><dd>{formatDate(effectivePolicy.grant_expires_at * 1000, $locale)} {#if effectivePolicy.grant_expires_at * 1000 <= now}{@render badge('expired')}{/if}</dd></div>{/if}
                  </dl>
                  <p class="hint">{$t('transaction_budget_note')}</p>
                {/if}
                <h3>{$t('client_command')} <span class="version">POSIX / WSL</span></h3>{@render command(connectionCommand(settings, selected.name))}<div class="notice neutral"><Icon name="shield"/><p>{$t('connection_hint')}</p></div><a href="#preferences">{$t('local_settings')} →</a>
              {:else if tab === 'changes'}<div class="row between wrap" style="margin-bottom:15px"><div><h2 style="margin-bottom:5px">{$t('changes')}</h2><p class="hint" style="margin:0">{$t('diff_description')}</p></div><button disabled={stale || actionBusy || selected.status !== 'active'} onclick={downloadDiff}><Icon name="download" size={15}/>{$t('export_diff')}</button></div>
                <p class="hint">{$t('download_diff_note')}</p>
                {#if actionError}{@render errorPanel(actionError, false)}{/if}
                {#if diff}<div class="toolbar" style="padding:12px 0"><select bind:value={tableFilter} aria-label={$t('table')}><option value="all">{$t('all_tables')}</option>{#each diff.tables as table}<option value={String(table.id)}>{table.schema}.{table.table}</option>{/each}</select><select bind:value={operationFilter} aria-label={$t('operation')}><option value="all">{$t('all_operations')}</option>{#each ['insert','update','delete'] as op}<option value={op}>{label(op)}</option>{/each}</select></div>
                  {#each diff.tables.filter((table) => tableFilter === 'all' || String(table.id) === tableFilter) as table}<div style="margin-top:20px"><h3 class="mono">{table.schema}.{table.table}</h3><!-- svelte-ignore a11y_no_noninteractive_tabindex (Keyboard access to horizontal table scrolling.) -->
<div class="table-scroll" tabindex="0" role="region" aria-label={`${table.schema}.${table.table}`}><table><thead><tr><th>{$t('operation')}</th><th>{$t('primary_key')}</th><th>{$t('before')}</th><th>{$t('after')}</th></tr></thead><tbody>{#each table.changes.filter((change) => operationFilter === 'all' || change.operation === operationFilter) as change}<tr><td><span class="badge {change.operation === 'delete' ? 'danger' : change.operation === 'update' ? 'purple' : ''}">{label(change.operation)}</span></td><td class="mono">{JSON.stringify(change.key)}</td><td class="diff-value before">{@render rowValues(change.before, table.columns)}</td><td class="diff-value after">{@render rowValues(change.after, table.columns)}</td></tr>{/each}</tbody></table></div></div>{/each}
                  {#if !diff.tables.some((table) => (tableFilter === 'all' || String(table.id) === tableFilter) && table.changes.some((change) => operationFilter === 'all' || change.operation === operationFilter))}<div class="empty"><Icon name="check"/><h2>{$t(operationFilter !== 'all' || tableFilter !== 'all' ? 'table_empty_matches' : 'no_changes')}</h2><p>{$t(operationFilter !== 'all' || tableFilter !== 'all' ? 'table_empty_hint' : 'no_changes_hint')}</p></div>{/if}
                {:else if selected.status !== 'active'}{@render unavailable('branch_not_connectable')}{/if}
              {:else if tab === 'approvals'}<h2>{$t('approvals')}</h2><p class="muted">{$t('approval_note')}</p>{#if actionError}{@render errorPanel(actionError, false)}{/if}
                {@render approvalList()}
              {:else if tab === 'audit'}<h2>{$t('audit_log')}</h2><form class="toolbar" onsubmit={(event) => { event.preventDefault(); void refresh(); }}><div class="field" style="margin:0"><label for="event-type">{$t('event')}</label><input id="event-type" bind:value={auditType} pattern={'[a-z_]{1,32}'} placeholder="policy_decision"/></div><div class="field" style="margin:0"><label for="audit-since">{$t('timestamp')} ≥</label><input id="audit-since" type="datetime-local" bind:value={auditSince}/></div><div class="field" style="margin:0"><label for="audit-until">{$t('timestamp')} &lt;</label><input id="audit-until" type="datetime-local" bind:value={auditUntil}/></div><button type="submit" disabled={loading}>{$t('filter_events')}</button></form>
                {#if audit?.events.length}<div class="table-scroll"><table><thead><tr><th>{$t('timestamp')}</th><th>{$t('actor')}</th><th>{$t('event')}</th><th>{$t('event_details')}</th></tr></thead><tbody>{#each audit.events as item}<tr><td>{formatDate(item.occurred_at * 1000, $locale)}</td><td>{item.actor}</td><td class="mono">{item.event_type}</td><td><details><summary class="mono">#{item.id}</summary><pre class="json-view">{JSON.stringify(item.payload, null, 2)}</pre></details></td></tr>{/each}</tbody></table></div>{#if audit.next_after}<button style="margin-top:16px" disabled={loading} onclick={nextAuditPage}>{$t('next_page')}</button>{/if}{:else if !loading && !error}<div class="empty"><Icon name="clock"/><h2>{$t('no_audit')}</h2></div>{/if}
              {/if}
            </div></section>
          {:else if !loading && !error}<div class="empty"><h1>{$t('branch_not_found')}</h1><a href="#branches">{$t('back')}</a></div>{/if}

        {:else if page === 'policies'}
          <div class="page-head"><div><p class="eyebrow">{$t('administration')}</p><h1>{$t('policies')}</h1><p>{$t('policy_description')}</p></div><select style="width:150px" aria-label={$t('branch_class')} bind:value={policyClass} onchange={() => { policyEpoch++; policyDirty = false; actionError = null; void refresh(); }}>{#each classes as value}<option>{value}</option>{/each}</select></div>
          {#if !demo}{@render unavailable('policy_edit_unavailable')}{/if}
          {#if policy}<section class="panel"><div class="panel-head"><h2>{policy.class} <span class="version">v{policy.version}</span></h2><button disabled={loading} onclick={() => refresh()}><Icon name="refresh" size={15}/>{$t('refresh_policy')}</button></div><form class="panel-body" onsubmit={updatePolicy} oninput={() => policyDirty = true}>
            {#if actionError}{@render errorPanel(actionError, false, true)}{/if}
            <div class="grid2"><div class="field"><label for="max-rows">{$t('max_transaction_rows')}</label><input id="max-rows" bind:value={editRows} required pattern="[0-9]+" inputmode="numeric" disabled={!demo}/></div><div class="field"><label for="table-limit">{$t('table_limit_bps')}</label><input id="table-limit" type="number" min="1" max="10000" step="1" value={editTable} oninput={(event) => editTable = event.currentTarget.value} disabled={!demo}/></div><div class="field"><label for="approval-after">{$t('approval_after_rows')}</label><input id="approval-after" bind:value={editApproval} pattern="[0-9]*" inputmode="numeric" disabled={!demo}/></div><div class="field"><span class="field-label">{$t('expected_version')}</span><p class="mono">{policy.version}</p></div></div>
            <div class="form-actions"><span class="hint">{$t('policy_version')}: {policy.version}</span><button class="primary" disabled={!demo || actionBusy || stale || !policyDirty} type="submit">{$t('save')}</button></div>
          </form></section>{/if}

        {:else if page === 'deployment'}
          <div class="page-head"><div><p class="eyebrow">{$t('administration')}</p><h1>{$t('deployment')}</h1><p>{$t('deployment_description')}</p></div><button disabled={loading} onclick={() => refresh()}><Icon name="refresh" size={15}/>{$t('refresh')}</button></div>
          <section class="panel"><div class="panel-head"><h2>{$t('deployment_health')}</h2><span class="badge neutral">{demo ? $t('sample_data') : settings.deployment}</span></div><div class="panel-body"><div class="grid2">{#each ['live','ready'] as probe}<div class="panel"><div class="panel-body"><div class="row between"><h3 class="mono" style="margin:0">/health/{probe}</h3><Icon name="server"/></div><div style="margin-top:18px">{#if health}{@render badge(health[probe as 'live' | 'ready'].ok ? 'active' : 'unknown')}<p class="hint" style="margin:10px 0 0">HTTP {health[probe as 'live' | 'ready'].status ?? '—'}</p>{#if !health[probe as 'live' | 'ready'].ok}<p class="hint">{health[probe as 'live' | 'ready'].message}</p>{/if}{:else}<span class="muted">{$t('not_reported')}</span>{/if}</div></div></div>{/each}</div><dl class="detail-metadata"><div><dt>{$t('deployment_engine')}</dt><dd>{settings.engine}</dd></div><div><dt>{$t('proxy_endpoint')}</dt><dd class="mono">{settings.host}:{settings.port}</dd></div><div><dt>{$t('transport')}</dt><dd>TLS</dd></div><div><dt>{$t('owner')}</dt><dd>{demo ? 'alex' : $t('permission_unknown')}</dd></div></dl>{#if capabilities}<h3>{$t('capabilities')}</h3><dl class="detail-metadata"><div><dt>{$t('deployment_engine')}</dt><dd>{capabilities.engine}</dd></div><div><dt>{$t('access')}</dt><dd>{label(capabilities.new_branch_default_access)}</dd></div><div><dt>{$t('native_copy_limit')}</dt><dd>{capabilities.native_copy_limit}</dd></div><div><dt>{$t('generation_limit')}</dt><dd>{capabilities.physical_generation_limit}</dd></div></dl>{#each capabilities.known_limitations as limitation}<div class="notice warning"><Icon name="alert"/><div><strong class="mono">{limitation.reason}</strong><p>{limitation.action}</p></div></div>{/each}{:else}{@render unavailable('status_probes_only')}{/if}<a href="#preferences">{$t('local_settings')} →</a></div></section>

        {:else if page === 'snapshots'}
          <div class="page-head"><div><p class="eyebrow">{$t('administration')}</p><h1>{$t('snapshots')}</h1><p>{$t('snapshot_description')}</p></div></div>
          <section class="panel"><div class="panel-head"><h2>{$t('generation')}</h2><span class="badge neutral">{$t('cli_only')}</span></div><div class="snapshot-cli">{@render unavailable()}<h3><span class="step">1</span>{$t('refresh_snapshot')}</h3>{@render command('fg-control refresh --snapshot v2')}<h3><span class="step">2</span>{$t('retire_snapshot')}</h3><p class="hint">{$t('retire_warning')}</p>{@render command('fg-control retire --generation <generation-id>')}</div></section>

        {:else if page === 'review_queue'}
          <div class="page-head"><div><p class="eyebrow">{$t('administration')}</p><h1>{$t('review_queue')}</h1><p>{$t('approval_note')}</p></div></div>
          <section class="panel"><div class="panel-body"><div class="notice neutral"><Icon name="info"/><p>{$t('review_queue_unavailable')}</p></div><form class="row wrap" onsubmit={(event) => { event.preventDefault(); reviewBranchId = inspectId; approvals = []; actionError = null; void refresh(); }}><div class="field" style="margin:0;max-width:300px;flex:1"><label for="known-branch">{$t('known_branch')}</label><input id="known-branch" bind:value={inspectId} required pattern="[1-9][0-9]*" inputmode="numeric" placeholder="123"/></div><button class="primary" type="submit" style="align-self:flex-end">{$t('inspect_branch')}<Icon name="arrow" size={15}/></button></form><p class="hint" style="margin-top:18px">{$t('reviewer_hint')}</p>{#if actionError}{@render errorPanel(actionError, false)}{/if}{#if reviewBranchId}<h3 class="mono" style="margin-top:20px">{$t('branch_id')}: #{reviewBranchId}</h3>{@render approvalList()}{/if}</div></section>

        {:else if page === 'github'}
          <div class="page-head"><div><p class="eyebrow">{$t('administration')}</p><h1>{$t('github')}</h1><p>{$t('github_description')}</p></div><button disabled={loading} onclick={() => refresh()}><Icon name="refresh" size={15}/>{$t('refresh')}</button></div>
          <section class="panel">{#if bindings.length}<div class="table-scroll"><table><thead><tr><th>{$t('repository')}</th><th>{$t('source')}</th><th>{$t('name')}</th><th>{$t('status')}</th><th>{$t('branches')}</th><th>{$t('safe_reason')}</th></tr></thead><tbody>{#each bindings as binding}<tr><td class="mono">#{binding.repository_id}</td><td><span class="badge neutral">{binding.source_kind}</span><span class="subtext mono">{binding.source_key}</span></td><td>{binding.name || '—'}</td><td>{binding.state}<span class="subtext">{binding.branch_status ? label(binding.branch_status) : '—'}</span></td><td>{#if binding.branch_id}<a href={`#branch/${binding.branch_id}/connection`}>#{binding.branch_id}</a>{:else}—{/if}</td><td>{binding.last_error || '—'}</td></tr>{/each}</tbody></table></div>{:else if !loading && !error}<div class="empty"><div class="empty-icon"><Icon name="git" size={25}/></div><h2>{$t('no_repositories')}</h2><p>{$t('github_description')}</p></div>{/if}</section>

        {:else if page === 'tools'}
          <div class="page-head"><div><p class="eyebrow">{$t('developer_workspace')}</p><h1>{$t('tools')}</h1><p>{$t('cli_only')}</p></div></div>
          <div class="grid2"><section class="panel tool-card"><h2><span class="step">1</span>{$t('dry_run')}</h2><p class="muted">{$t('dry_run_description')}</p>{@render command(`forkget dryrun --engine ${settings.engine === 'mongodb' ? '<sql-engine>' : settings.engine} --manifest changes.json --output report.json`)}<span class="badge neutral">{$t('cli_only')}</span></section><section class="panel tool-card"><h2><span class="step">2</span>{$t('export')}</h2><p class="muted">{$t('download_diff_note')}</p>{@render command('forkget export --id <branch-id> --output changes.json')}<span class="badge neutral">{$t('cli_only')}</span></section><section class="panel tool-card"><h2><span class="step">3</span>{$t('replay')}</h2><p class="muted">{$t('replay_description')}</p>{@render command(`forkget replay --engine ${settings.engine} --input changes.json --name replay-check`)}<span class="badge neutral">{$t('cli_only')}</span></section><section class="panel tool-card"><h2><span class="step">4</span>{$t('audit_log')}</h2><p class="muted">{$t('audit')}</p>{@render command('forkget audit --id <branch-id> --output audit.json')}<a href="#branches">{$t('branches')} →</a></section></div>

        {:else if page === 'preferences'}
          <div class="page-head"><div><p class="eyebrow">{$t('console_title')}</p><h1>{$t('preferences')}</h1><p>{$t('preferences_description')}</p></div></div>
          <section class="panel"><div class="panel-head"><h2>{$t('language')}</h2><Icon name="globe"/></div><div class="panel-body"><div style="max-width:330px"><label for="preference-language">{$t('language')}</label><select id="preference-language" value={$locale} onchange={(event) => setLocale(event.currentTarget.value as Locale)}>{#each supportedLocales as item}<option value={item.code}>{item.nativeLabel}</option>{/each}</select><p class="hint" style="margin-top:8px">{$t('language_description')}</p></div></div></section>
          <section class="panel" style="margin-top:20px"><div class="panel-head"><h2>{$t('local_settings')}</h2><span class="badge neutral">{$t('connection')}</span></div><form class="panel-body" onsubmit={(event) => { event.preventDefault(); saveSettings(); notify($t('saved')); }}><div class="notice neutral"><Icon name="info"/><p>{$t('endpoint_hint')}</p></div><div class="grid2">
            <div class="field"><label for="deployment-label">{$t('deployment_label')}</label><input id="deployment-label" bind:value={settings.deployment} maxlength="100" required/></div>
            <div class="field"><label for="engine">{$t('deployment_engine')}</label><select id="engine" bind:value={settings.engine} onchange={() => settings.port = defaultPort(settings.engine)}><option value="postgresql">PostgreSQL</option><option value="mysql">MySQL</option><option value="tidb">TiDB</option><option value="mongodb">MongoDB</option></select></div>
            <div class="field"><label for="host">{$t('host')}</label><input id="host" bind:value={settings.host} required/></div><div class="field"><label for="port">{$t('port')}</label><input id="port" bind:value={settings.port} pattern={'[0-9]{1,5}'} required/></div><div class="field"><label for="frontend-user">{$t('frontend_account')}</label><input id="frontend-user" bind:value={settings.username} autocomplete="off"/></div><div class="field"><label for="ca-file">{$t('ca_file')}</label><input id="ca-file" bind:value={settings.caFile} required/></div>
          </div><div class="form-actions"><span class="hint">{$t('timezone')}: {Intl.DateTimeFormat().resolvedOptions().timeZone}</span><button class="primary" type="submit">{$t('save')}</button></div></form></section>
        {/if}
        {#if lastRefreshed && !['preferences','tools','snapshots','review_queue'].includes(page)}<div class="footer-note"><Icon name="clock" size={13}/>{$t('last_refreshed')}: {formatDate(lastRefreshed, $locale)}{#if loading}<span class="busy-label">· {$t('loading')}</span>{/if}</div>{/if}
      </main>
    </div>
  </div>
{/if}

{#snippet approvalList()}
  {#if approvals.length}<div class="table-scroll"><table><thead><tr><th>ID</th><th>{$t('table')}</th><th>{$t('operation')}</th><th>{$t('row_count')}</th><th>{$t('policy_version')}</th><th>{$t('status')}</th><th>{$t('expires')}</th><th>{$t('actions')}</th></tr></thead><tbody>{#each approvals as item}<tr><td class="mono">#{item.id}</td><td class="mono">#{item.table_id}</td><td>{label(item.kind)}</td><td>{String(item.rows)}</td><td>v{item.policy_version}</td><td>{@render badge(item.state === 'pending' && item.expires_at * 1000 <= now ? 'expired' : item.state)}</td><td>{formatRelativeTime(item.expires_at * 1000, $locale)}</td><td><div class="row"><button disabled={stale || loading || actionBusy || item.state !== 'pending' || item.expires_at * 1000 <= now} onclick={() => review(item, true)}>{$t('approve')}</button><button class="danger" disabled={stale || loading || actionBusy || item.state !== 'pending' || item.expires_at * 1000 <= now} onclick={() => review(item, false)}>{$t('deny')}</button></div></td></tr>{/each}</tbody></table></div>{:else if !loading && !error}<div class="empty"><Icon name="check"/><h2>{$t('no_approvals')}</h2><p>{$t('no_approvals_hint')}</p></div>{/if}
{/snippet}

{#snippet rowValues(values: (string | null)[] | null, columns: {name: string; type_name: string}[])}
  {#if values === null}<span class="null">—</span>{:else}{#each values as value, index}<div class="mono"><span class="muted" title={columns[index]?.type_name}>{columns[index]?.name}: </span>{#if value === null}<span class="null">NULL</span>{:else}{JSON.stringify(value)}{/if}</div>{/each}{/if}
{/snippet}

<Dialog bind:open={createOpen} title={$t('create_branch')}>
  <p class="muted">{$t('create_summary')}</p>
  {#if actionError}{@render errorPanel(actionError, false)}{/if}
  <form onsubmit={createBranch}>
    <div class="field"><label for="branch-name">{$t('branch_name')}</label><input id="branch-name" bind:value={newName} pattern={'[a-z][a-z0-9\\-]{2,62}'} required minlength="3" maxlength="63" placeholder="dev-checkout" spellcheck="false"/><p class="hint">{$t('branch_name_hint')}</p></div>
    <div class="form-row"><div class="field"><label for="new-class">{$t('branch_class')}</label><select id="new-class" bind:value={newClass} onchange={changeClass}>{#each classes as value}<option>{value}</option>{/each}</select></div><div class="field"><label for="ttl">{$t('ttl_hours')}</label><input id="ttl" type="number" min="0.0002777778" max="24" step="any" bind:value={ttl} required/><p class="hint">{$t('validation_ttl')}</p></div></div>
    <fieldset style="border:0;margin:0;padding:0"><legend class="field-label">{$t('access')}</legend><div class="choices"><div class="choice" class:selected={newMode === 'read_only'}><input type="radio" id="read-only" name="access" value="read_only" bind:group={newMode}/><label for="read-only">{$t('read_only')}<p>{$t('read_only_description')}</p></label></div><div class="choice" class:selected={newMode === 'native_write'}><input type="radio" id="writable" name="access" value="native_write" bind:group={newMode} disabled={newClass === 'staging'}/><label for="writable">{$t('writable')}<p>{$t('writable_description')}</p></label></div></div></fieldset>
    <div class="form-actions"><button type="button" disabled={actionBusy} onclick={() => createOpen = false}>{$t('cancel')}</button><button class="primary" type="submit" disabled={actionBusy}>{actionBusy ? $t('creating_branch') : $t('create_branch')}<Icon name="arrow" size={16}/></button></div>
  </form>
</Dialog>

<Dialog bind:open={dropOpen} title={$t('drop_branch')}>
  {#if selected}<div class="notice warning"><Icon name="alert"/><p>{$t('drop_warning')}</p></div><h2>{selected.name}</h2><dl class="detail-metadata"><div><dt>{$t('branch_id')}</dt><dd class="mono">#{selected.id}</dd></div><div><dt>{$t('owner')}</dt><dd>{selected.created_by}</dd></div><div><dt>{$t('generation')}</dt><dd>g{selected.generation_id}</dd></div><div><dt>{$t('access')}</dt><dd>{label(access(selected))}</dd></div></dl><p class="muted">{$t('drop_description')}</p>{#if actionError}{@render errorPanel(actionError, false)}{/if}<div class="form-actions"><button disabled={actionBusy} onclick={() => dropOpen = false}>{$t('cancel')}</button><button class="danger filled" disabled={actionBusy} onclick={dropBranch}>{actionBusy ? $t('dropping_branch') : $t('drop_branch')}</button></div>{/if}
</Dialog>
{#if message}<div class="toast" role="status">{message}</div>{/if}

<style>.sr-only{position:absolute;width:1px;height:1px;margin:-1px;padding:0;overflow:hidden;clip:rect(0,0,0,0);white-space:nowrap;border:0}</style>
