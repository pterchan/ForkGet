<script lang="ts">
  import type { Snippet } from 'svelte';
  import { onDestroy } from 'svelte';
  import { t } from './i18n';
  import Icon from './Icon.svelte';
  let { open = $bindable(false), title, wide = false, children }: { open?: boolean; title: string; wide?: boolean; children: Snippet } = $props();
  let dialog: HTMLDialogElement;
  let trigger: HTMLElement | null = null;
  const id = $props.id();
  $effect(() => {
    if (!dialog) return;
    if (open && !dialog.open) { trigger = document.activeElement as HTMLElement; dialog.showModal(); }
    if (!open && dialog.open) dialog.close();
  });
  function closed() { open = false; if (trigger?.isConnected) trigger.focus(); trigger = null; }
  onDestroy(() => dialog?.close());
</script>
<dialog bind:this={dialog} class:wide aria-labelledby={id} onclose={closed} oncancel={() => open = false}>
  <header class="dialog-head"><h2 id={id}>{title}</h2><button type="button" class="icon-button" aria-label={$t('close')} onclick={() => open = false}><Icon name="close" /></button></header>
  <div class="dialog-body">{#if open}{@render children()}{/if}</div>
</dialog>
