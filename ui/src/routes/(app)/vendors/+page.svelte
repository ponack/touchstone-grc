<script lang="ts">
	import {
		listVendors,
		type Vendor,
		type VendorCriticality,
		type VendorStatus,
		type VendorType
	} from '$lib/api/vendors';
	import { toasts } from '$lib/stores/toasts.svelte';
	import { Plus, Loader2, Download, AlertTriangle } from 'lucide-svelte';
	import Pill from '$lib/components/Pill.svelte';

	let vendors = $state<Vendor[]>([]);
	let loading = $state(true);
	let typeFilter = $state<'' | VendorType>('');
	let statusFilter = $state<'' | VendorStatus>('');
	let reviewDueOnly = $state(false);

	async function refresh() {
		try {
			vendors = await listVendors({
				vendor_type: typeFilter || undefined,
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

	function typeLabel(t: VendorType): string {
		if (t === 'saas') return 'SaaS';
		if (t === 'paas') return 'PaaS';
		if (t === 'iaas') return 'IaaS';
		return t.replace('_', ' ');
	}

	function critKind(c: VendorCriticality): 'danger' | 'warn' | 'neutral' | 'muted' {
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

	function statusKind(s: VendorStatus): 'success' | 'info' | 'muted' {
		switch (s) {
			case 'active':
				return 'success';
			case 'prospective':
				return 'info';
			case 'terminated':
				return 'muted';
		}
	}

	function fmtDate(s?: string | null): string {
		if (!s) return '—';
		return new Date(s).toLocaleDateString();
	}

	function reviewState(next?: string | null): 'overdue' | 'upcoming' | 'ok' | 'unset' {
		if (!next) return 'unset';
		const d = new Date(next);
		const now = new Date();
		const inDays = (d.getTime() - now.getTime()) / (1000 * 60 * 60 * 24);
		if (inDays < 0) return 'overdue';
		if (inDays < 30) return 'upcoming';
		return 'ok';
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
			'vendor_type',
			'criticality',
			'status',
			'data_classification',
			'owner_name',
			'website',
			'contact_email',
			'onboarded_date',
			'offboarded_date',
			'assurance_report',
			'last_review_date',
			'next_review_date',
			'tags'
		];
		const rows = vendors.map((v) =>
			[
				v.name,
				v.vendor_type,
				v.criticality,
				v.status,
				v.data_classification ?? '',
				v.owner_name ?? '',
				v.website ?? '',
				v.contact_email ?? '',
				v.onboarded_date ?? '',
				v.offboarded_date ?? '',
				v.assurance_report ?? '',
				v.last_review_date ?? '',
				v.next_review_date ?? '',
				v.tags.join(' ')
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
		a.download = `vendors-${new Date().toISOString().slice(0, 10)}.csv`;
		a.click();
		URL.revokeObjectURL(url);
	}
</script>

<svelte:head>
	<title>Vendors · Touchstone GRC</title>
</svelte:head>

<div class="mx-auto max-w-6xl px-8 py-10">
	<div class="flex items-center justify-between">
		<div>
			<h1 class="text-2xl font-semibold tracking-tight text-zinc-100">Vendors</h1>
			<p class="mt-1 text-sm text-zinc-400">
				Third-party suppliers within the audited boundary. Each row carries an internal owner from
				the personnel register and the assurance evidence the auditor expects to see.
			</p>
		</div>
		<div class="flex items-center gap-2">
			<button
				type="button"
				onclick={exportCsv}
				disabled={vendors.length === 0}
				class="flex items-center gap-1.5 rounded-md border border-zinc-800 px-3 py-1.5 text-sm text-zinc-300 hover:text-zinc-100 disabled:opacity-50"
			>
				<Download class="h-4 w-4" />
				CSV
			</button>
			<a
				href="/vendors/new"
				class="flex items-center gap-1.5 rounded-md px-3 py-1.5 text-sm font-medium text-zinc-950"
				style="background-color: var(--accent);"
			>
				<Plus class="h-4 w-4" />
				Add vendor
			</a>
		</div>
	</div>

	<div class="mt-6 flex flex-wrap items-center gap-4 text-sm">
		<label class="flex items-center gap-2 text-zinc-400">
			Type
			<select
				bind:value={typeFilter}
				onchange={refresh}
				class="rounded-md border border-zinc-800 bg-zinc-950/40 px-2 py-1 text-zinc-200"
			>
				<option value="">All</option>
				<option value="saas">SaaS</option>
				<option value="paas">PaaS</option>
				<option value="iaas">IaaS</option>
				<option value="processor">Processor</option>
				<option value="subprocessor">Subprocessor</option>
				<option value="hardware">Hardware</option>
				<option value="professional_services">Professional services</option>
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
				<option value="prospective">Prospective</option>
				<option value="active">Active</option>
				<option value="terminated">Terminated</option>
			</select>
		</label>
		<label class="flex items-center gap-2 text-zinc-400">
			<input type="checkbox" bind:checked={reviewDueOnly} onchange={refresh} />
			Review due (missing or past)
		</label>
	</div>

	<div class="mt-3 overflow-hidden rounded-md border border-zinc-800">
		{#if loading}
			<div class="flex items-center justify-center py-10 text-zinc-500">
				<Loader2 class="h-5 w-5 animate-spin" />
			</div>
		{:else if vendors.length === 0}
			<div class="px-6 py-16 text-center">
				<p class="text-sm text-zinc-400">
					{reviewDueOnly
						? 'No vendors with overdue or missing reviews.'
						: 'No vendors matching the current filters.'}
				</p>
				<a
					href="/vendors/new"
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
						<th class="px-4 py-2 font-medium">Criticality</th>
						<th class="px-4 py-2 font-medium">Status</th>
						<th class="px-4 py-2 font-medium">Next review</th>
					</tr>
				</thead>
				<tbody class="divide-y divide-zinc-800">
					{#each vendors as v (v.id)}
						{@const rs = reviewState(v.next_review_date)}
						<tr class="hover:bg-zinc-900/40">
							<td class="px-4 py-2.5">
								<a href="/vendors/{v.id}" class="text-zinc-100 underline-offset-4 hover:underline">
									{v.name}
								</a>
								{#if v.tags.length > 0}
									<div class="mt-0.5 flex flex-wrap gap-1">
										{#each v.tags as tag (tag)}
											<span class="rounded bg-zinc-900 px-1.5 py-0.5 text-xs text-zinc-500"
												>{tag}</span
											>
										{/each}
									</div>
								{/if}
							</td>
							<td class="px-4 py-2.5 text-zinc-300">{typeLabel(v.vendor_type)}</td>
							<td class="px-4 py-2.5 text-zinc-400">{v.owner_name ?? '—'}</td>
							<td class="px-4 py-2.5">
								<Pill kind={critKind(v.criticality)}>{v.criticality}</Pill>
							</td>
							<td class="px-4 py-2.5">
								<Pill kind={statusKind(v.status)}>{v.status}</Pill>
							</td>
							<td class="px-4 py-2.5">
								<span class="flex items-center gap-1.5 text-zinc-400">
									{#if rs === 'overdue'}
										<AlertTriangle class="h-3.5 w-3.5 text-red-400" />
										<span class="text-red-300">{fmtDate(v.next_review_date)}</span>
									{:else if rs === 'upcoming'}
										<span class="text-amber-300">{fmtDate(v.next_review_date)}</span>
									{:else if rs === 'unset'}
										<span class="text-zinc-500">unset</span>
									{:else}
										{fmtDate(v.next_review_date)}
									{/if}
								</span>
							</td>
						</tr>
					{/each}
				</tbody>
			</table>
		{/if}
	</div>
</div>
