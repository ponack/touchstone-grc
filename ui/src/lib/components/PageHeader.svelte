<script lang="ts">
	import type { Snippet } from 'svelte';

	interface Props {
		/** Small-caps kicker line above the title (e.g. "Phase 7 · GRC register"). Optional. */
		kicker?: string;
		/** Main page title — rendered in the Plex Serif display face. */
		title: string;
		/** Optional sub-line below the title. */
		subtitle?: string;
		/** Right-aligned slot for action buttons (Add / CSV / Filter / etc.). */
		actions?: Snippet;
		/** Bottom-row slot for live metrics — usually a <PageHeaderMetric> grid. */
		metrics?: Snippet;
	}

	let { kicker, title, subtitle, actions, metrics }: Props = $props();
</script>

<header class="border-b border-zinc-800/70 pb-6">
	<div class="flex items-start justify-between gap-6">
		<div class="min-w-0">
			{#if kicker}
				<p
					class="text-[0.65rem] font-medium uppercase tracking-[0.22em] text-zinc-500"
				>
					{kicker}
				</p>
			{/if}
			<h1
				class="font-serif text-3xl text-zinc-100 {kicker ? 'mt-1' : ''}"
				style="letter-spacing: -0.01em;"
			>
				{title}
			</h1>
			{#if subtitle}
				<p class="mt-2 max-w-2xl text-sm text-zinc-400">{subtitle}</p>
			{/if}
		</div>
		{#if actions}
			<div class="flex shrink-0 items-center gap-2">{@render actions()}</div>
		{/if}
	</div>
	{#if metrics}
		<div class="mt-5">{@render metrics()}</div>
	{/if}
</header>
