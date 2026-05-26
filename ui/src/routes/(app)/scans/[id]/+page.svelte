<script lang="ts">
	import { page } from '$app/state';
	import { getScan, type Scan } from '$lib/api/scans';
	import { listForScan, type EvidenceSummary } from '$lib/api/evidence';
	import { getConnector, type Connector } from '$lib/api/connectors';
	import { toasts } from '$lib/stores/toasts.svelte';
	import StatusPill from '$lib/components/StatusPill.svelte';
	import { Loader2, Download } from 'lucide-svelte';

	let scan = $state<Scan | null>(null);
	let connector = $state<Connector | null>(null);
	let evidence = $state<EvidenceSummary[]>([]);
	let loading = $state(true);
	let pollHandle: ReturnType<typeof setInterval> | null = null;

	const id = $derived(page.params.id!);
	const isActive = $derived(scan?.status === 'queued' || scan?.status === 'running');

	async function refreshAll() {
		try {
			const fresh = await getScan(id);
			scan = fresh;
			if (fresh.status !== 'queued' && fresh.status !== 'running') {
				evidence = await listForScan(id);
			}
		} catch (e) {
			toasts.error((e as Error).message);
		}
	}

	$effect(() => {
		(async () => {
			try {
				scan = await getScan(id);
				connector = await getConnector(scan.connector_id);
				if (scan.status !== 'queued' && scan.status !== 'running') {
					evidence = await listForScan(id);
				}
			} catch (e) {
				toasts.error((e as Error).message);
			} finally {
				loading = false;
			}
		})();
	});

	$effect(() => {
		if (isActive && !pollHandle) {
			pollHandle = setInterval(refreshAll, 2000);
		} else if (!isActive && pollHandle) {
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

	const counts = $derived.by(() => {
		const c = { pass: 0, fail: 0, partial: 0, not_applicable: 0, error: 0 };
		for (const e of evidence) c[e.status]++;
		return c;
	});

	function fmtTime(s?: string | null) {
		return s ? new Date(s).toLocaleString() : '—';
	}
</script>

<svelte:head>
	<title>Scan · Touchstone GRC</title>
</svelte:head>

<div class="mx-auto max-w-5xl px-8 py-10">
	<a href="/scans" class="text-sm text-zinc-500 underline-offset-4 hover:underline">← Scans</a>

	{#if loading}
		<div class="mt-6 flex items-center gap-2 text-zinc-500">
			<Loader2 class="h-4 w-4 animate-spin" /> Loading…
		</div>
	{:else if !scan}
		<p class="mt-6 text-sm text-red-400">Scan not found.</p>
	{:else}
		<div class="mt-2 flex items-start justify-between gap-3">
			<div class="flex items-center gap-3">
				<h1 class="text-2xl font-semibold tracking-tight text-zinc-100">
					{connector?.name ?? 'Scan'}
				</h1>
				<StatusPill status={scan.status} />
			</div>
			{#if !isActive && evidence.length > 0}
				<a
					href={`/api/v1/scans/${scan.id}/export.csv`}
					class="flex items-center gap-1.5 rounded-md border border-zinc-700 px-3 py-1.5 text-sm text-zinc-200 hover:border-zinc-600"
				>
					<Download class="h-4 w-4" />
					Export CSV
				</a>
			{/if}
		</div>
		<p class="mt-1 text-xs text-zinc-500">{scan.id}</p>

		<div class="mt-8 grid gap-4 sm:grid-cols-4">
			<div class="rounded-md border border-zinc-800 bg-zinc-900/40 p-3">
				<div class="text-xs uppercase tracking-wide text-zinc-500">Resources</div>
				<div class="mt-1 text-lg font-semibold text-zinc-100">{scan.resources_count}</div>
			</div>
			<div class="rounded-md border border-zinc-800 bg-zinc-900/40 p-3">
				<div class="text-xs uppercase tracking-wide text-zinc-500">Trigger</div>
				<div class="mt-1 text-sm text-zinc-200">{scan.trigger}</div>
			</div>
			<div class="rounded-md border border-zinc-800 bg-zinc-900/40 p-3">
				<div class="text-xs uppercase tracking-wide text-zinc-500">Started</div>
				<div class="mt-1 text-sm text-zinc-200">{fmtTime(scan.started_at)}</div>
			</div>
			<div class="rounded-md border border-zinc-800 bg-zinc-900/40 p-3">
				<div class="text-xs uppercase tracking-wide text-zinc-500">Finished</div>
				<div class="mt-1 text-sm text-zinc-200">{fmtTime(scan.finished_at)}</div>
			</div>
		</div>

		{#if scan.error_message}
			<div class="mt-4 rounded-md border border-red-900 bg-red-950/30 p-3 text-sm text-red-300">
				{scan.error_message}
			</div>
		{/if}

		<h2 class="mt-10 text-lg font-semibold text-zinc-100">Evidence</h2>

		{#if isActive}
			<div class="mt-3 flex items-center gap-2 text-sm text-zinc-500">
				<Loader2 class="h-4 w-4 animate-spin" />
				Evaluating controls — this page updates automatically.
			</div>
		{:else if evidence.length === 0}
			<p class="mt-3 text-sm text-zinc-500">
				This scan did not produce any evidence rows. Enable a framework for this org and re-run.
			</p>
		{:else}
			<div class="mt-3 flex flex-wrap gap-4 text-xs text-zinc-400">
				<span><StatusPill status="pass" /> {counts.pass}</span>
				<span><StatusPill status="fail" /> {counts.fail}</span>
				<span><StatusPill status="partial" /> {counts.partial}</span>
				<span><StatusPill status="not_applicable" /> {counts.not_applicable}</span>
				{#if counts.error > 0}
					<span><StatusPill status="error" /> {counts.error}</span>
				{/if}
			</div>

			<div class="mt-4 overflow-hidden rounded-md border border-zinc-800">
				<table class="w-full text-sm">
					<thead class="bg-zinc-900/60 text-left text-xs uppercase tracking-wide text-zinc-500">
						<tr>
							<th class="px-4 py-2 font-medium">Control</th>
							<th class="px-4 py-2 font-medium">Status</th>
							<th class="px-4 py-2 font-medium">Collected</th>
						</tr>
					</thead>
					<tbody class="divide-y divide-zinc-800">
						{#each evidence as e (e.id)}
							<tr class="hover:bg-zinc-900/40">
								<td class="px-4 py-2.5">
									<a
										href={`/evidence/${e.id}`}
										class="font-medium text-zinc-100 underline-offset-4 hover:underline"
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
	{/if}
</div>
