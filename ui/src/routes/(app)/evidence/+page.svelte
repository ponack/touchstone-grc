<script lang="ts">
	import { listLatest, type LatestEvidence } from '$lib/api/evidence';
	import { toasts } from '$lib/stores/toasts.svelte';
	import StatusPill from '$lib/components/StatusPill.svelte';
	import { Loader2, Download } from 'lucide-svelte';

	let evidence = $state<LatestEvidence[]>([]);
	let loading = $state(true);
	let filter = $state<'all' | 'fail' | 'pass' | 'not_applicable' | 'error' | 'partial'>('all');

	$effect(() => {
		(async () => {
			try {
				evidence = await listLatest();
			} catch (e) {
				toasts.error((e as Error).message);
			} finally {
				loading = false;
			}
		})();
	});

	const counts = $derived.by(() => {
		const c = { total: 0, pass: 0, fail: 0, partial: 0, not_applicable: 0, error: 0 };
		for (const e of evidence) {
			c.total++;
			c[e.status]++;
		}
		return c;
	});

	const visible = $derived(
		filter === 'all' ? evidence : evidence.filter((e) => e.status === filter)
	);
</script>

<svelte:head>
	<title>Evidence · Touchstone GRC</title>
</svelte:head>

<div class="mx-auto max-w-5xl px-8 py-10">
	<div class="flex items-start justify-between">
		<div>
			<h1 class="text-2xl font-semibold tracking-tight text-zinc-100">Current compliance state</h1>
			<p class="mt-1 text-sm text-zinc-400">
				The most recent evidence row for every control across every framework you have enabled.
				This is the view to share with an auditor for a point-in-time snapshot.
			</p>
		</div>
		{#if evidence.length > 0}
			<a
				href="/api/v1/exports/latest.csv"
				class="flex items-center gap-1.5 rounded-md border border-zinc-700 px-3 py-1.5 text-sm text-zinc-200 hover:border-zinc-600"
			>
				<Download class="h-4 w-4" />
				Export CSV
			</a>
		{/if}
	</div>

	{#if loading}
		<div class="mt-8 flex items-center gap-2 text-zinc-500">
			<Loader2 class="h-4 w-4 animate-spin" /> Loading…
		</div>
	{:else if evidence.length === 0}
		<div class="mt-8 rounded-md border border-zinc-800 bg-zinc-900/40 p-5 text-sm">
			<p class="text-zinc-300">No evidence yet.</p>
			<p class="mt-2 text-zinc-500">
				<a href="/scans/new" class="underline decoration-dotted underline-offset-4">
					Trigger a scan →
				</a>
			</p>
		</div>
	{:else}
		<div class="mt-6 flex flex-wrap gap-2 text-xs">
			{#each [{ k: 'all', label: `All ${counts.total}` }, { k: 'fail', label: `Fail ${counts.fail}` }, { k: 'pass', label: `Pass ${counts.pass}` }, { k: 'partial', label: `Partial ${counts.partial}` }, { k: 'not_applicable', label: `N/A ${counts.not_applicable}` }, { k: 'error', label: `Error ${counts.error}` }] as f (f.k)}
				<button
					type="button"
					onclick={() => (filter = f.k as typeof filter)}
					class="rounded-md px-2.5 py-1 {filter === f.k
						? 'text-zinc-100'
						: 'text-zinc-400 hover:text-zinc-200'}"
					style={filter === f.k ? 'background-color: var(--accent-muted);' : ''}
				>
					{f.label}
				</button>
			{/each}
		</div>

		<div class="mt-3 overflow-hidden rounded-md border border-zinc-800">
			<table class="w-full text-sm">
				<thead class="bg-zinc-900/60 text-left text-xs uppercase tracking-wide text-zinc-500">
					<tr>
						<th class="px-4 py-2 font-medium">Framework</th>
						<th class="px-4 py-2 font-medium">Control</th>
						<th class="px-4 py-2 font-medium">Status</th>
						<th class="px-4 py-2 font-medium">Collected</th>
					</tr>
				</thead>
				<tbody class="divide-y divide-zinc-800">
					{#each visible as e (e.id)}
						<tr class="hover:bg-zinc-900/40">
							<td class="px-4 py-2.5">
								<span class="rounded bg-zinc-800 px-1.5 py-0.5 text-xs uppercase text-zinc-400">
									{e.framework_code}
								</span>
							</td>
							<td class="px-4 py-2.5">
								<a
									href={`/evidence/${e.id}`}
									class="font-mono text-xs text-zinc-100 underline-offset-4 hover:underline"
								>
									{e.control_code}
								</a>
								<span class="ml-2 text-zinc-400">{e.control_title}</span>
							</td>
							<td class="px-4 py-2.5"><StatusPill status={e.status} /></td>
							<td class="px-4 py-2.5 text-zinc-400">
								{new Date(e.collected_at).toLocaleString()}
							</td>
						</tr>
					{/each}
				</tbody>
			</table>
		</div>
	{/if}
</div>
