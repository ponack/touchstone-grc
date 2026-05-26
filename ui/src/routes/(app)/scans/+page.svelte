<script lang="ts">
	import { listScans, type Scan } from '$lib/api/scans';
	import { listConnectors, type Connector } from '$lib/api/connectors';
	import { toasts } from '$lib/stores/toasts.svelte';
	import StatusPill from '$lib/components/StatusPill.svelte';
	import { Plus, Loader2 } from 'lucide-svelte';

	let scans = $state<Scan[]>([]);
	let connectors = $state<Connector[]>([]);
	let loading = $state(true);
	let pollHandle: ReturnType<typeof setInterval> | null = null;

	const connectorName = $derived((id: string) => connectors.find((c) => c.id === id)?.name ?? id);
	const hasActive = $derived(scans.some((s) => s.status === 'queued' || s.status === 'running'));

	async function refresh() {
		try {
			scans = await listScans({ limit: 100 });
		} catch (e) {
			toasts.error((e as Error).message);
		}
	}

	$effect(() => {
		(async () => {
			try {
				[scans, connectors] = await Promise.all([listScans({ limit: 100 }), listConnectors()]);
			} catch (e) {
				toasts.error((e as Error).message);
			} finally {
				loading = false;
			}
		})();
	});

	// Poll while any scan is still in-flight; stop when all terminal.
	$effect(() => {
		if (hasActive && !pollHandle) {
			pollHandle = setInterval(refresh, 3000);
		} else if (!hasActive && pollHandle) {
			clearInterval(pollHandle);
			pollHandle = null;
		}
		return () => {
			if (pollHandle) {
				clearInterval(pollHandle);
				pollHandle = null;
			}
		};
	});

	function fmtDuration(s?: string | null, f?: string | null): string {
		if (!s) return '—';
		const start = new Date(s).getTime();
		const end = f ? new Date(f).getTime() : Date.now();
		const ms = end - start;
		if (ms < 1000) return `${ms}ms`;
		if (ms < 60_000) return `${(ms / 1000).toFixed(1)}s`;
		return `${Math.floor(ms / 60_000)}m ${Math.floor((ms % 60_000) / 1000)}s`;
	}
</script>

<svelte:head>
	<title>Scans · Touchstone GRC</title>
</svelte:head>

<div class="mx-auto max-w-5xl px-8 py-10">
	<div class="flex items-center justify-between">
		<div>
			<h1 class="text-2xl font-semibold tracking-tight text-zinc-100">Scans</h1>
			<p class="mt-1 text-sm text-zinc-400">
				Each scan enumerates a connector and evaluates its results against every enabled control.
			</p>
		</div>
		<a
			href="/scans/new"
			class="flex items-center gap-1.5 rounded-md px-3 py-1.5 text-sm font-medium text-zinc-950"
			style="background-color: var(--accent);"
		>
			<Plus class="h-4 w-4" />
			Run scan
		</a>
	</div>

	<div class="mt-8 overflow-hidden rounded-md border border-zinc-800">
		{#if loading}
			<div class="flex items-center justify-center py-10 text-zinc-500">
				<Loader2 class="h-5 w-5 animate-spin" />
			</div>
		{:else if scans.length === 0}
			<div class="px-6 py-16 text-center">
				<p class="text-sm text-zinc-400">No scans yet.</p>
				<a
					href="/scans/new"
					class="mt-3 inline-block text-sm underline decoration-dotted underline-offset-4"
					style="color: var(--accent);">Trigger the first one →</a
				>
			</div>
		{:else}
			<table class="w-full text-sm">
				<thead class="bg-zinc-900/60 text-left text-xs uppercase tracking-wide text-zinc-500">
					<tr>
						<th class="px-4 py-2 font-medium">Connector</th>
						<th class="px-4 py-2 font-medium">Status</th>
						<th class="px-4 py-2 font-medium">Trigger</th>
						<th class="px-4 py-2 font-medium">Resources</th>
						<th class="px-4 py-2 font-medium">Duration</th>
						<th class="px-4 py-2 font-medium">Started</th>
					</tr>
				</thead>
				<tbody class="divide-y divide-zinc-800">
					{#each scans as s (s.id)}
						<tr class="hover:bg-zinc-900/40">
							<td class="px-4 py-2.5">
								<a
									href={`/scans/${s.id}`}
									class="font-medium text-zinc-100 underline-offset-4 hover:underline"
								>
									{connectorName(s.connector_id)}
								</a>
							</td>
							<td class="px-4 py-2.5"><StatusPill status={s.status} /></td>
							<td class="px-4 py-2.5 text-zinc-400">{s.trigger}</td>
							<td class="px-4 py-2.5 text-zinc-400">{s.resources_count}</td>
							<td class="px-4 py-2.5 text-zinc-400">{fmtDuration(s.started_at, s.finished_at)}</td>
							<td class="px-4 py-2.5 text-zinc-400">
								{new Date(s.created_at).toLocaleString()}
							</td>
						</tr>
					{/each}
				</tbody>
			</table>
		{/if}
	</div>
</div>
