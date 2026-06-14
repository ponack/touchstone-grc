<script lang="ts">
	import { goto } from '$app/navigation';
	import { auth } from '$lib/stores/auth.svelte';
	import { toasts } from '$lib/stores/toasts.svelte';
	import {
		listTrustIncidents,
		type IncidentSeverity,
		type IncidentStatus,
		type TrustIncident
	} from '$lib/api/trust-incidents';
	import { Plus, AlertOctagon } from 'lucide-svelte';
	import PageHeader from '$lib/components/PageHeader.svelte';
	import PageHeaderMetric from '$lib/components/PageHeaderMetric.svelte';
	import Pill from '$lib/components/Pill.svelte';
	import SkeletonRows from '$lib/components/SkeletonRows.svelte';
	import EmptyState from '$lib/components/EmptyState.svelte';

	let incidents = $state<TrustIncident[]>([]);
	let loading = $state(true);
	let statusFilter = $state<'' | IncidentStatus>('');

	async function refresh() {
		try {
			incidents = await listTrustIncidents({ status: statusFilter || undefined });
		} catch (e) {
			toasts.error((e as Error).message);
		}
	}

	$effect(() => {
		(async () => {
			if (auth.me && !auth.me.is_admin) {
				await goto('/');
				return;
			}
			loading = true;
			await refresh();
			loading = false;
		})();
	});

	const ongoingCount = $derived(
		incidents.filter((i) => i.status === 'ongoing' || i.status === 'monitoring').length
	);
	const publishedCount = $derived(incidents.filter((i) => i.is_public).length);
	const resolvedCount = $derived(incidents.filter((i) => i.status === 'resolved').length);

	function severityKind(s: IncidentSeverity): 'success' | 'neutral' | 'warn' | 'danger' {
		switch (s) {
			case 'low':
				return 'success';
			case 'medium':
				return 'neutral';
			case 'high':
				return 'warn';
			case 'critical':
				return 'danger';
		}
	}

	function statusKind(s: IncidentStatus): 'warn' | 'info' | 'success' {
		switch (s) {
			case 'ongoing':
				return 'warn';
			case 'monitoring':
				return 'info';
			case 'resolved':
				return 'success';
		}
	}

	function fmtTime(iso?: string | null): string {
		if (!iso) return '—';
		const d = new Date(iso);
		return d.toLocaleString();
	}
</script>

<svelte:head>
	<title>Trust incidents · Settings · Touchstone GRC</title>
</svelte:head>

<div class="mx-auto max-w-5xl px-8 py-10">
	<a href="/settings" class="text-sm text-zinc-500 underline-offset-4 hover:underline">
		← Settings
	</a>

	<div class="mt-2">
		<PageHeader
			kicker="Phase 8 · Trust Center"
			title="Incident history"
			subtitle="Log security / availability events you want a record of. Mark individual rows public on the edit page; they appear on the public Trust Center when the 'Incident history' section is enabled."
		>
			{#snippet actions()}
				<a
					href="/settings/trust-incidents/new"
					class="flex items-center gap-1.5 rounded-md px-3 py-1.5 text-sm font-medium text-zinc-950"
					style="background-color: var(--accent);"
				>
					<Plus class="h-4 w-4" />
					Log incident
				</a>
			{/snippet}
			{#snippet metrics()}
				<dl class="grid grid-cols-3 gap-8 sm:max-w-sm">
					<PageHeaderMetric label="Open" value={ongoingCount} tone="warn" />
					<PageHeaderMetric label="Resolved" value={resolvedCount} tone="success" />
					<PageHeaderMetric label="Published" value={publishedCount} />
				</dl>
			{/snippet}
		</PageHeader>
	</div>

	<div class="mt-6 flex items-center gap-2 text-sm">
		<label for="status-filter" class="text-zinc-400">Status</label>
		<select
			id="status-filter"
			bind:value={statusFilter}
			onchange={refresh}
			class="rounded-md border border-zinc-800 bg-zinc-950/40 px-2 py-1 text-zinc-200"
		>
			<option value="">All</option>
			<option value="ongoing">Ongoing</option>
			<option value="monitoring">Monitoring</option>
			<option value="resolved">Resolved</option>
		</select>
	</div>

	<div class="mt-3 overflow-hidden rounded-md border border-zinc-800">
		{#if loading}
			<SkeletonRows count={5} columns={['w-56', 'w-24', 'w-20', 'w-32', 'w-20']} />
		{:else if incidents.length === 0}
			<EmptyState
				icon={AlertOctagon}
				title={statusFilter ? `No ${statusFilter} incidents` : 'No incidents logged yet'}
				body="Keep an internal log of security and availability events here. You decide which rows reach customers via the public Trust Center — the rest stay on the audit trail for SOC 2 CC7.4 review."
				samples={[
					'Brief degraded latency due to a regional outage at a cloud provider',
					'Customer-impacting deploy bug rolled back within the SLO window',
					'Investigation closed with no exploitation confirmed (e.g. log4j scare)'
				]}
			>
				{#snippet cta()}
					<a
						href="/settings/trust-incidents/new"
						class="inline-flex items-center gap-1.5 rounded-md px-3 py-1.5 text-sm font-medium text-zinc-950"
						style="background-color: var(--accent);"
					>
						<Plus class="h-4 w-4" /> Log the first incident
					</a>
				{/snippet}
			</EmptyState>
		{:else}
			<table class="w-full text-sm">
				<thead class="bg-zinc-900/60 text-left text-xs uppercase tracking-wide text-zinc-500">
					<tr>
						<th class="px-4 py-2 font-medium">Title</th>
						<th class="px-4 py-2 font-medium">Severity</th>
						<th class="px-4 py-2 font-medium">Status</th>
						<th class="px-4 py-2 font-medium">Occurred</th>
						<th class="px-4 py-2 font-medium">Resolved</th>
						<th class="px-4 py-2 font-medium">Public</th>
					</tr>
				</thead>
				<tbody class="divide-y divide-zinc-800">
					{#each incidents as i (i.id)}
						<tr class="hover:bg-zinc-900/40">
							<td class="px-4 py-2.5">
								<a
									href="/settings/trust-incidents/{i.id}"
									class="text-zinc-100 underline-offset-4 hover:underline"
								>
									{i.title}
								</a>
							</td>
							<td class="px-4 py-2.5">
								<Pill kind={severityKind(i.severity)}>{i.severity}</Pill>
							</td>
							<td class="px-4 py-2.5">
								<Pill kind={statusKind(i.status)}>{i.status}</Pill>
							</td>
							<td class="px-4 py-2.5 text-zinc-400">{fmtTime(i.occurred_at)}</td>
							<td class="px-4 py-2.5 text-zinc-400">{fmtTime(i.resolved_at)}</td>
							<td class="px-4 py-2.5">
								{#if i.is_public}
									<Pill kind="success">published</Pill>
								{:else}
									<Pill kind="muted">private</Pill>
								{/if}
							</td>
						</tr>
					{/each}
				</tbody>
			</table>
		{/if}
	</div>
</div>
