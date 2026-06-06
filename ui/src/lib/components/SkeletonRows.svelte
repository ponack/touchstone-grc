<script lang="ts">
	interface Props {
		/** How many placeholder rows to render. Defaults to 6 — about
		 * what fits above the fold on a list page. */
		count?: number;
		/** Column widths, in Tailwind size classes. Drives the per-row
		 * grid layout. The longest column gets the title slot; the
		 * remaining columns suggest pills / dates / counts. */
		columns?: string[];
	}

	let {
		count = 6,
		columns = ['w-48', 'w-24', 'w-32', 'w-16', 'w-20', 'w-20']
	}: Props = $props();
</script>

<div class="divide-y divide-zinc-800/60">
	{#each Array(count) as _, i (i)}
		<div class="flex items-center gap-6 px-4 py-3">
			{#each columns as col, ci (ci)}
				<div class="h-3 animate-pulse rounded bg-zinc-800/70 {col}"></div>
			{/each}
		</div>
	{/each}
</div>
