<script lang="ts">
	import { listConnectors, type Connector } from '$lib/api/connectors';
	import { toasts } from '$lib/stores/toasts.svelte';
	import { Plus, Loader2 } from 'lucide-svelte';

	let connectors = $state<Connector[]>([]);
	let loading = $state(true);

	$effect(() => {
		(async () => {
			try {
				connectors = await listConnectors();
			} catch (e) {
				toasts.error((e as Error).message);
			} finally {
				loading = false;
			}
		})();
	});

	function fmtTime(s?: string | null) {
		if (!s) return '—';
		return new Date(s).toLocaleString();
	}
</script>

<svelte:head>
	<title>Connectors · Touchstone GRC</title>
</svelte:head>

<div class="mx-auto max-w-5xl px-8 py-10">
	<div class="flex items-center justify-between">
		<div>
			<h1 class="text-2xl font-semibold tracking-tight text-zinc-100">Connectors</h1>
			<p class="mt-1 text-sm text-zinc-400">
				Read-only integrations Touchstone uses to gather evidence.
			</p>
		</div>
		<a
			href="/connectors/new"
			class="flex items-center gap-1.5 rounded-md px-3 py-1.5 text-sm font-medium text-zinc-950"
			style="background-color: var(--accent);"
		>
			<Plus class="h-4 w-4" />
			New connector
		</a>
	</div>

	<div class="mt-8 overflow-hidden rounded-md border border-zinc-800">
		{#if loading}
			<div class="flex items-center justify-center py-10 text-zinc-500">
				<Loader2 class="h-5 w-5 animate-spin" />
			</div>
		{:else if connectors.length === 0}
			<div class="px-6 py-16 text-center">
				<p class="text-sm text-zinc-400">No connectors yet.</p>
				<a
					href="/connectors/new"
					class="mt-3 inline-block text-sm underline decoration-dotted underline-offset-4"
					style="color: var(--accent);">Create the first one →</a
				>
			</div>
		{:else}
			<table class="w-full text-sm">
				<thead class="bg-zinc-900/60 text-left text-xs uppercase tracking-wide text-zinc-500">
					<tr>
						<th class="px-4 py-2 font-medium">Name</th>
						<th class="px-4 py-2 font-medium">Kind</th>
						<th class="px-4 py-2 font-medium">Schedule</th>
						<th class="px-4 py-2 font-medium">Last scan</th>
						<th class="px-4 py-2 font-medium">Status</th>
					</tr>
				</thead>
				<tbody class="divide-y divide-zinc-800">
					{#each connectors as c (c.id)}
						<tr class="hover:bg-zinc-900/40">
							<td class="px-4 py-2.5">
								<a
									href={`/connectors/${c.id}`}
									class="font-medium text-zinc-100 underline-offset-4 hover:underline"
								>
									{c.name}
								</a>
							</td>
							<td class="px-4 py-2.5 text-zinc-400 uppercase">{c.kind}</td>
							<td class="px-4 py-2.5 text-zinc-400">{c.schedule_cron ?? 'on-demand'}</td>
							<td class="px-4 py-2.5 text-zinc-400">{fmtTime(c.last_scan_at)}</td>
							<td class="px-4 py-2.5">
								{#if c.is_disabled}
									<span class="rounded bg-zinc-800 px-1.5 py-0.5 text-xs text-zinc-400"
										>disabled</span
									>
								{:else}
									<span class="rounded bg-emerald-950/50 px-1.5 py-0.5 text-xs text-emerald-300"
										>enabled</span
									>
								{/if}
							</td>
						</tr>
					{/each}
				</tbody>
			</table>
		{/if}
	</div>
</div>
