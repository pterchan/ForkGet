<script lang="ts">let { name = 'branch', size = 18 }: { name?: string; size?: number } = $props();</script>
<svg width={size} height={size} viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.6" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">
  {#if name === 'branch'}<circle cx="6" cy="5" r="2.5"/><circle cx="6" cy="19" r="2.5"/><circle cx="18" cy="5" r="2.5"/><path d="M6 8v8m12-8c0 7-12 1-12 8"/>
  {:else if name === 'layers'}<path d="m3 7 9-5 9 5-9 5zm0 5 9 5 9-5M3 17l9 5 9-5"/>
  {:else if name === 'shield'}<path d="m12 2 8 3v6c0 5-8 11-8 11S4 16 4 11V5z"/><path d="m8 11 3 3 5-6"/>
  {:else if name === 'check'}<path d="m5 12 4 4L19 6"/>
  {:else if name === 'clock'}<circle cx="12" cy="12" r="9"/><path d="M12 7v5l3 2"/>
  {:else if name === 'terminal'}<rect x="3" y="4" width="18" height="16" rx="2"/><path d="m7 9 3 3-3 3m6 0h4"/>
  {:else if name === 'server'}<rect x="3" y="3" width="18" height="7" rx="2"/><rect x="3" y="14" width="18" height="7" rx="2"/><path d="M7 6.5h.01M7 17.5h.01m5-11h5m-5 11h5"/>
  {:else if name === 'settings'}<circle cx="12" cy="12" r="3"/><path d="m9 3-1 3-3 1-2 5 2 5 3 1 1 3h6l1-3 3-1 2-5-2-5-3-1-1-3z"/>
  {:else if name === 'search'}<circle cx="10.5" cy="10.5" r="6.5"/><path d="m16 16 5 5"/>
  {:else if name === 'plus'}<path d="M12 5v14M5 12h14"/>
  {:else if name === 'refresh'}<path d="M20 8A8.5 8.5 0 1 0 21 14M20 3v5h-5"/>
  {:else if name === 'arrow'}<path d="M5 12h14m-5-5 5 5-5 5"/>
  {:else if name === 'copy'}<rect x="8" y="8" width="12" height="13" rx="2"/><path d="M15 8V3H3v13h5"/>
  {:else if name === 'close'}<path d="m6 6 12 12M18 6 6 18"/>
  {:else if name === 'menu'}<path d="M4 6h16M4 12h16M4 18h16"/>
  {:else if name === 'globe'}<circle cx="12" cy="12" r="9"/><ellipse cx="12" cy="12" rx="4" ry="9"/><path d="M3 12h18"/>
  {:else if name === 'alert'}<path d="m12 3 10 18H2zM12 9v5m0 3h.01"/>
  {:else if name === 'download'}<path d="M12 3v12m-5-5 5 5 5-5M4 16v5h16v-5"/>
  {:else if name === 'git'}<path d="m12 2 10 10-10 10L2 12zM9 5v9m0-6 6 6"/><circle cx="9" cy="15" r="1.5"/><circle cx="15" cy="15" r="1.5"/>
  {:else}<circle cx="12" cy="12" r="9"/><path d="M12 11v6m0-10h.01"/>{/if}
</svg>
