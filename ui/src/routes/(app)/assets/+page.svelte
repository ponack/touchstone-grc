<script lang="ts">
	import {
		listAssets,
		type Asset,
		type AssetCriticality,
		type AssetStatus,
		type AssetType
	} from '$lib/api/assets';
	import { toasts } from '$lib/stores/toasts.svelte';
	import { Plus, Loader2, Download } from 'lucide-svelte';
	import Pill from '$lib/components/Pill.svelte';
	import PageHeader from '$lib/components/PageHeader.svelte';
	import PageHeaderMetric from '$lib/components/PageHeaderMetric.svelte';

	let assets = $state<Asset[]>([]);
	let loading = $state(true);
	let typeFilter = $state<'' | AssetType>('');
	let statusFilter = $state<'' | AssetStatus>('');

	async function refresh() {
		try {
			assets = await listAssets({
				asset_type: typeFilter || undefined,
				status: statusFilter || undefined
			});
		} catch (e) {
			toasts.error((e as Error).message);
		}
	}

	$effect(() => {
		(async () => {
			loading = true;
			await refresh();
			loading = false;
		})();
	});

	const totalCount = $derived(assets.length);
	const criticalHighCount = $derived(
		assets.filter((a) => a.criticality === 'critical' || a.criticality === 'high').length
	);
	const decommissionedCount = $derived(assets.filter((a) => a.status === 'decommissioned').length);

	function typeLabel(t: AssetType): string {
		return t.replace('_', ' ');
	}

	function critKind(c: AssetCriticality): 'danger' | 'warn' | 'neutral' | 'muted' {
		switch (c) {
			case 'critical':
				return 'danger';
			case 'high':
				return 'warn';
			case 'medium':
				return 'neutral';
			case 'low':
				return 'muted';
		}
	}

	function statusKind(s: AssetStatus): 'success' | 'warn' | 'muted' {
		switch (s) {
			case 'active':
				return 'success';
			case 'planned':
				return 'warn';
			case 'decommissioned':
				return 'muted';
		}
	}

	function csvEscape(v: string): string {
		if (v.includes(',') || v.includes('"') || v.includes('\n')) {
			return '"' + v.replaceAll('"', '""') + '"';
		}
		return v;
	}

	function exportCsv() {
		const headers = [
			'name',
			'asset_type',
			'classification',
			'environment',
			'criticality',
			'status',
			'owner_name',
			'external_ref',
			'tags'
		];
		const rows = assets.map((a) =>
			[
				a.name,
				a.asset_type,
				a.classification ?? '',
				a.environment,
				a.criticality,
				a.status,
				a.owner_name ?? '',
				a.external_ref ?? '',
				a.tags.join(' ')
			]
				.map(csvEscape)
				.join(',')
		);
		const blob = new Blob([headers.join(',') + '\n' + rows.join('\n')], {
			type: 'text/csv;charset=utf-8'
		});
		const url = URL.createObjectURL(blob);
		const a = document.createElement('a');
		a.href = url;
		a.download = `assets-${new Date().toISOString().slice(0, 10)}.csv`;
		a.click();
		URL.revokeObjectURL(url);
	}
</script>

<svelte:head>
	<title>Assets · Touchstone GRC</title>
</svelte:head>

<div class="mx-auto max-w-6xl px-8 py-10">
	<PageHeader
		kicker="Phase 7 · GRC register"
		title="Assets"
		subtitle="Audited boundary: applications, services, data stores, cloud accounts, repos, and infrastructure. Every asset carries a named owner from the personnel register."
	>
		{#snippet actions()}
			<button
				type="button"
				onclick={exportCsv}
				disabled={assets.length === 0}
				class="flex items-center gap-1.5 rounded-md border border-zinc-800 px-3 py-1.5 text-sm text-zinc-300 hover:text-zinc-100 disabled:opacity-50"
			>
				<Download class="h-4 w-4" />
				CSV
			</button>
			<a
				href="/assets/new"
				class="flex items-center gap-1.5 rounded-md px-3 py-1.5 text-sm font-medium text-zinc-950"
				style="background-color: var(--accent);"
			>
				<Plus class="h-4 w-4" />
				Add asset
			</a>
		{/snippet}
		{#snippet metrics()}
			<dl class="grid grid-cols-3 gap-8 sm:max-w-sm">
				<PageHeaderMetric label="Total" value={totalCount} />
				<PageHeaderMetric label="High / critical" value={criticalHighCount} tone="warn" />
				<PageHeaderMetric label="Decommissioned" value={decommissionedCount} />
			</dl>
		{/snippet}
	</PageHeader>

	<div class="mt-6 flex flex-wrap items-center gap-4 text-sm">
		<label class="flex items-center gap-2 text-zinc-400">
			Type
			<select
				bind:value={typeFilter}
				onchange={refresh}
				class="rounded-md border border-zinc-800 bg-zinc-950/40 px-2 py-1 text-zinc-200"
			>
				<option value="">All</option>
				<option value="application">Application</option>
				<option value="service">Service</option>
				<option value="database">Database</option>
				<option value="repository">Repository</option>
				<option value="data_store">Data store</option>
				<option value="cloud_account">Cloud account</option>
				<option value="infrastructure">Infrastructure</option>
				<option value="device">Device</option>
				<option value="other">Other</option>
			</select>
		</label>
		<label class="flex items-center gap-2 text-zinc-400">
			Status
			<select
				bind:value={statusFilter}
				onchange={refresh}
				class="rounded-md border border-zinc-800 bg-zinc-950/40 px-2 py-1 text-zinc-200"
			>
				<option value="">All</option>
				<option value="active">Active</option>
				<option value="planned">Planned</option>
				<option value="decommissioned">Decommissioned</option>
			</select>
		</label>
	</div>

	<div class="mt-3 overflow-hidden rounded-md border border-zinc-800">
		{#if loading}
			<div class="flex items-center justify-center py-10 text-zinc-500">
				<Loader2 class="h-5 w-5 animate-spin" />
			</div>
		{:else if assets.length === 0}
			<div class="px-6 py-16 text-center">
				<p class="text-sm text-zinc-400">No assets matching the current filters.</p>
				<a
					href="/assets/new"
					class="mt-3 inline-block text-sm underline decoration-dotted underline-offset-4"
					style="color: var(--accent);">Add the first one →</a
				>
			</div>
		{:else}
			<table class="w-full text-sm">
				<thead class="bg-zinc-900/60 text-left text-xs uppercase tracking-wide text-zinc-500">
					<tr>
						<th class="px-4 py-2 font-medium">Name</th>
						<th class="px-4 py-2 font-medium">Type</th>
						<th class="px-4 py-2 font-medium">Owner</th>
						<th class="px-4 py-2 font-medium">Env</th>
						<th class="px-4 py-2 font-medium">Criticality</th>
						<th class="px-4 py-2 font-medium">Status</th>
					</tr>
				</thead>
				<tbody class="divide-y divide-zinc-800">
					{#each assets as a (a.id)}
						<tr class="hover:bg-zinc-900/40">
							<td class="px-4 py-2.5">
								<a href="/assets/{a.id}" class="text-zinc-100 underline-offset-4 hover:underline">
									{a.name}
								</a>
								{#if a.tags.length > 0}
									<div class="mt-0.5 flex flex-wrap gap-1">
										{#each a.tags as tag (tag)}
											<span class="rounded bg-zinc-900 px-1.5 py-0.5 text-xs text-zinc-500"
												>{tag}</span
											>
										{/each}
									</div>
								{/if}
							</td>
							<td class="px-4 py-2.5 text-zinc-300">{typeLabel(a.asset_type)}</td>
							<td class="px-4 py-2.5 text-zinc-400">{a.owner_name ?? '—'}</td>
							<td class="px-4 py-2.5 text-zinc-400">{a.environment}</td>
							<td class="px-4 py-2.5">
								<Pill kind={critKind(a.criticality)}>{a.criticality}</Pill>
							</td>
							<td class="px-4 py-2.5">
								<Pill kind={statusKind(a.status)}>{a.status}</Pill>
							</td>
						</tr>
					{/each}
				</tbody>
			</table>
		{/if}
	</div>
</div>
