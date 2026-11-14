<script lang="ts">
  import type { AuditHealth } from './model';
  import { t, locale, formatDate } from './i18n';

  let { health }: { health: AuditHealth } = $props();
  const hasCount = (count: number | string) => String(count) !== '0';
</script>

<section aria-label={$t('audit_health')}>
  <h3>{$t('audit_health')}</h3>
  {#if health.requires_witness && !health.witness_ready}
    <div class="notice warning"><p>{$t('audit_preparation_required')}</p></div>
  {/if}
  {#if health.protected_writes_paused === true}
    <div class="notice warning"><p>{$t('audit_delivery_pending_hint')}</p></div>
  {/if}
  {#if health.cleanup_blocked}
    <div class="notice warning"><p>{$t('audit_cleanup_blocked')}</p></div>
  {/if}
  <dl class="detail-metadata">
    <div><dt>{$t('audit_delivery_state')}</dt><dd>{health.protected_writes_paused === true ? $t('audit_delivery_paused') : health.protected_writes_paused === false ? $t('audit_delivery_current') : $t('not_reported')}</dd></div>
    <div><dt>{$t('audit_pending_delivery')}</dt><dd>{String(health.pending_delivery)}</dd></div>
    <div><dt>{$t('audit_sql_unknown')}</dt><dd>{String(health.sql_unresolved_unknown)}</dd></div>
    {#if hasCount(health.mongo_unknown)}
      <div><dt>{$t('audit_mongo_unknown')}</dt><dd>{String(health.mongo_unknown)}</dd></div>
    {/if}
    {#if hasCount(health.mongo_partial)}
      <div><dt>{$t('audit_mongo_partial')}</dt><dd>{String(health.mongo_partial)}</dd></div>
    {/if}
    {#if health.oldest_pending_at !== null}
      <div><dt>{$t('audit_oldest_pending')}</dt><dd>{formatDate(health.oldest_pending_at * 1000, $locale)}</dd></div>
    {/if}
  </dl>
</section>
