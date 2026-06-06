<script lang="ts">
	import {
		listRisks,
		riskScore,
		type Risk,
		type RiskCategory,
		type RiskLevel,
		type RiskStatus
	} from '$lib/api/risks';
	import { toasts } from '$lib/stores/toasts.svelte';
	import { Plus, Download, AlertOctagon, AlertTriangle } from 'lucide-svelte';
	import Pill from '$lib/components/Pill.svelte';
	import PageHeader from '$lib/components/PageHeader.svelte';
	import PageHeaderMetric from '$lib/components/PageHeaderMetric.svelte';
	import SkeletonRows from '$lib/components/SkeletonRows.svelte';
	import EmptyState from '$lib/components/EmptyState.svelte';

	let risks = $state<Risk[]>([]);
	let loading = $state(true);
	let categoryFilter = $state<'' | RiskCategory>('');
	let statusFilter = $state<'' | RiskStatus>('');
	let reviewDueOnly = $state(false);

	async function refresh() {
		try {
			risks = await listRisks({
				category: categoryFilter || undefined,
				status: statusFilter || undefined,
				review_due: reviewDueOnly || undefined
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

	const openCount = $derived(
		risks.filter((r) => r.status === 'identified' || r.status === 'treating').length
	);
	const residualCriticalCount = $derived(
		risks.filter((r) => riskScore(r.residual_likelihood, r.residual_impact) >= 12).length
	);
	const overdueReviewCount = $derived(
		risks.filter((r) => {
			if (!r.next_review_date) return r.status === 'identified' || r.status === 'treating';
			return (
				new Date(r.next_review_date) < new Date() &&
				(r.status === 'identified' || r.status === 'treating')
			);
		}).length
	);

	function categoryLabel(c: RiskCategory): string {
		if (c === 'third_party') return 'third-party';
		return c;
	}

	function levelKind(l: RiskLevel): 'success' | 'neutral' | 'warn' | 'danger' {
		switch (l) {
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

	function scoreTone(s: number): 'success' | 'neutral' | 'warn' | 'danger' {
		if (s >= 12) return 'danger';
		if (s >= 6) return 'warn';
		if (s >= 3) return 'neutral';
		return 'success';
	}

	function statusKind(s: RiskStatus): 'warn' | 'info' | 'muted' | 'success' {
		switch (s) {
			case 'identified':
				return 'warn';
			case 'treating':
				return 'info';
			case 'accepted':
				return 'muted';
			case 'closed':
				return 'success';
		}
	}

	function fmtDate(s?: string | null): string {
		if (!s) return '—';
		return new Date(s).toLocaleDateString();
	}

	function csvEscape(v: string): string {
		if (v.includes(',') || v.includes('"') || v.includes('\n')) {
			return '"' + v.replaceAll('"', '""') + '"';
		}
		return v;
	}

	function exportCsv() {
		const headers = [
			'title',
			'risk_category',
			'inherent_likelihood',
			'inherent_impact',
			'inherent_score',
			'residual_likelihood',
			'residual_impact',
			'residual_score',
			'treatment_strategy',
			'status',
			'owner_name',
			'related_asset_name',
			'related_vendor_name',
			'identified_date',
			'next_review_date',
			'closed_date',
			'tags'
		];
		const rows = risks.map((r) => {
			const inh = riskScore(r.inherent_likelihood, r.inherent_impact);
			const res = riskScore(r.residual_likelihood, r.residual_impact);
			return [
				r.title,
				r.risk_category,
				r.inherent_likelihood,
				r.inherent_impact,
				String(inh),
				r.residual_likelihood,
				r.residual_impact,
				String(res),
				r.treatment_strategy,
				r.status,
				r.owner_name ?? '',
				r.related_asset_name ?? '',
				r.related_vendor_name ?? '',
				r.identified_date,
				r.next_review_date ?? '',
				r.closed_date ?? '',
				r.tags.join(' ')
			]
				.map(csvEscape)
				.join(',');
		});
		const blob = new Blob([headers.join(',') + '\n' + rows.join('\n')], {
			type: 'text/csv;charset=utf-8'
		});
		const url = URL.createObjectURL(blob);
		const a = document.createElement('a');
		a.href = url;
		a.download = `risks-${new Date().toISOString().slice(0, 10)}.csv`;
		a.click();
		URL.revokeObjectURL(url);
	}
</script>

<svelte:head>
	<title>Risks · Touchstone GRC</title>
</svelte:head>

<div class="mx-auto max-w-6xl px-8 py-10">
	<PageHeader
		kicker="Phase 7 · GRC register"
		title="Risks"
		subtitle="Identified information-security risks the audited boundary carries. Each row captures the inherent and residual L × I rating, the treatment strategy, and a named risk owner."
	>
		{#snippet actions()}
			<button
				type="button"
				onclick={exportCsv}
				disabled={risks.length === 0}
				class="flex items-center gap-1.5 rounded-md border border-zinc-800 px-3 py-1.5 text-sm text-zinc-300 hover:text-zinc-100 disabled:opacity-50"
			>
				<Download class="h-4 w-4" />
				CSV
			</button>
			<a
				href="/risks/new"
				class="flex items-center gap-1.5 rounded-md px-3 py-1.5 text-sm font-medium text-zinc-950"
				style="background-color: var(--accent);"
			>
				<Plus class="h-4 w-4" />
				Log risk
			</a>
		{/snippet}
		{#snippet metrics()}
			<dl class="grid grid-cols-3 gap-8 sm:max-w-md">
				<PageHeaderMetric label="Open" value={openCount} tone="warn" />
				<PageHeaderMetric label="Residual critical" value={residualCriticalCount} tone="danger" />
				<PageHeaderMetric label="Review overdue" value={overdueReviewCount} tone="danger" />
			</dl>
		{/snippet}
	</PageHeader>

	<div class="mt-6 flex flex-wrap items-center gap-4 text-sm">
		<label class="flex items-center gap-2 text-zinc-400">
			Category
			<select
				bind:value={categoryFilter}
				onchange={refresh}
				class="rounded-md border border-zinc-800 bg-zinc-950/40 px-2 py-1 text-zinc-200"
			>
				<option value="">All</option>
				<option value="operational">Operational</option>
				<option value="security">Security</option>
				<option value="privacy">Privacy</option>
				<option value="compliance">Compliance</option>
				<option value="financial">Financial</option>
				<option value="reputational">Reputational</option>
				<option value="strategic">Strategic</option>
				<option value="third_party">Third-party</option>
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
				<option value="identified">Identified</option>
				<option value="treating">Treating</option>
				<option value="accepted">Accepted</option>
				<option value="closed">Closed</option>
			</select>
		</label>
		<label class="flex items-center gap-2 text-zinc-400">
			<input type="checkbox" bind:checked={reviewDueOnly} onchange={refresh} />
			Review due (missing or past)
		</label>
	</div>

	<div class="mt-3 overflow-hidden rounded-md border border-zinc-800">
		{#if loading}
			<SkeletonRows count={6} columns={['w-64', 'w-24', 'w-16', 'w-16', 'w-24', 'w-24']} />
		{:else if risks.length === 0}
			<EmptyState
				icon={AlertOctagon}
				title={reviewDueOnly
					? 'No risks with overdue or missing reviews'
					: 'No risks in the register yet'}
				body="The auditor will ask 'what are your top risks, who owns them, and what's the treatment plan'. Capture every meaningful exposure here so the answer is on a single page."
				samples={[
					'Key-rotation gaps on third-party API tokens',
					'Lack of segregation between dev and prod data',
					'Vendor lock-in for the data-warehouse pipeline',
					'GDPR DSAR response capacity during peak season'
				]}
			>
				{#snippet cta()}
					<a
						href="/risks/new"
						class="inline-flex items-center gap-1.5 rounded-md px-3 py-1.5 text-sm font-medium text-zinc-950"
						style="background-color: var(--accent);"
					>
						<Plus class="h-4 w-4" /> Log the first risk
					</a>
				{/snippet}
			</EmptyState>
		{:else}
			<table class="w-full text-sm">
				<thead class="bg-zinc-900/60 text-left text-xs uppercase tracking-wide text-zinc-500">
					<tr>
						<th class="px-4 py-2 font-medium">Risk</th>
						<th class="px-4 py-2 font-medium">Category</th>
						<th class="px-4 py-2 font-medium">Inherent</th>
						<th class="px-4 py-2 font-medium">Residual</th>
						<th class="px-4 py-2 font-medium">Owner</th>
						<th class="px-4 py-2 font-medium">Status</th>
						<th class="px-4 py-2 font-medium">Next review</th>
					</tr>
				</thead>
				<tbody class="divide-y divide-zinc-800">
					{#each risks as r (r.id)}
						{@const inh = riskScore(r.inherent_likelihood, r.inherent_impact)}
						{@const res = riskScore(r.residual_likelihood, r.residual_impact)}
						<tr class="hover:bg-zinc-900/40">
							<td class="px-4 py-2.5">
								<a
									href="/risks/{r.id}"
									class="text-zinc-100 underline-offset-4 hover:underline"
								>
									{r.title}
								</a>
								{#if r.related_asset_name || r.related_vendor_name}
									<div class="mt-0.5 text-xs text-zinc-500">
										{#if r.related_asset_name}asset · {r.related_asset_name}{/if}
										{#if r.related_asset_name && r.related_vendor_name} · {/if}
										{#if r.related_vendor_name}vendor · {r.related_vendor_name}{/if}
									</div>
								{/if}
							</td>
							<td class="px-4 py-2.5 text-zinc-400">{categoryLabel(r.risk_category)}</td>
							<td class="px-4 py-2.5">
								<div class="flex items-center gap-2">
									<Pill kind={levelKind(r.inherent_likelihood)}>{r.inherent_likelihood}</Pill>
									<span class="text-zinc-600">×</span>
									<Pill kind={levelKind(r.inherent_impact)}>{r.inherent_impact}</Pill>
									<span class="font-mono text-xs text-zinc-500">{inh}</span>
								</div>
							</td>
							<td class="px-4 py-2.5">
								<div class="flex items-center gap-2">
									<Pill kind={scoreTone(res)}>{res}</Pill>
									{#if res > inh}
										<AlertTriangle class="h-3.5 w-3.5 text-red-400" />
									{/if}
								</div>
							</td>
							<td class="px-4 py-2.5 text-zinc-400">{r.owner_name ?? '—'}</td>
							<td class="px-4 py-2.5">
								<Pill kind={statusKind(r.status)}>{r.status}</Pill>
							</td>
							<td class="px-4 py-2.5 text-zinc-400">{fmtDate(r.next_review_date)}</td>
						</tr>
					{/each}
				</tbody>
			</table>
		{/if}
	</div>
</div>
