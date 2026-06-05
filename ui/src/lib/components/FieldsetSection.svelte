<script lang="ts">
	import type { Snippet } from 'svelte';

	interface Props {
		/** Small-caps label that names the field group (e.g. "Identity", "Tenure"). */
		legend: string;
		/** Optional fine-print under the legend. */
		description?: string;
		/** Whether to draw the top divider line. First section in a form typically opts out. */
		divider?: boolean;
		children?: Snippet;
	}

	let { legend, description, divider = true, children }: Props = $props();
</script>

<fieldset class="space-y-5 {divider ? 'border-t border-zinc-800/60 pt-6' : ''}">
	<legend
		class="text-[0.65rem] font-medium uppercase tracking-[0.22em] text-zinc-500"
	>
		{legend}
	</legend>
	{#if description}
		<p class="-mt-3 text-xs text-zinc-500">{description}</p>
	{/if}
	{@render children?.()}
</fieldset>
