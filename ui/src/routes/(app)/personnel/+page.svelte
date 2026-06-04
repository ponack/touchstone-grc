<script lang="ts">
	import { listPersonnel, type Person, type PersonStatus } from '$lib/api/personnel';
	import { toasts } from '$lib/stores/toasts.svelte';
	import { Plus, Loader2, Download } from 'lucide-svelte';

	let personnel = $state<Person[]>([]);
	let loading = $state(true);
	let statusFilter = $state<'' | PersonStatus>('');

	async function refresh() {
		try {
			personnel = await listPersonnel(statusFilter || undefined);
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

	function fmtDate(s?: string | null) {
		if (!s) return '—';
		return new Date(s).toLocaleDateString();
	}

	function statusClass(s: PersonStatus): string {
		switch (s) {
			case 'active':
				return 'rounded bg-emerald-950/50 px-1.5 py-0.5 text-xs text-emerald-300';
			case 'on_leave':
				return 'rounded bg-amber-950/50 px-1.5 py-0.5 text-xs text-amber-300';
			case 'terminated':
				return 'rounded bg-zinc-800 px-1.5 py-0.5 text-xs text-zinc-400';
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
			'full_name',
			'email',
			'role',
			'department',
			'start_date',
			'end_date',
			'status',
			'manager_id'
		];
		const rows = personnel.map((p) =>
			[
				p.full_name,
				p.email,
				p.role,
				p.department ?? '',
				p.start_date,
				p.end_date ?? '',
				p.status,
				p.manager_id ?? ''
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
		a.download = `personnel-${new Date().toISOString().slice(0, 10)}.csv`;
		a.click();
		URL.revokeObjectURL(url);
	}
</script>

<svelte:head>
	<title>Personnel · Touchstone GRC</title>
</svelte:head>

<div class="mx-auto max-w-6xl px-8 py-10">
	<div class="flex items-center justify-between">
		<div>
			<h1 class="text-2xl font-semibold tracking-tight text-zinc-100">Personnel</h1>
			<p class="mt-1 text-sm text-zinc-400">
				Workforce members whose access to in-scope systems is governed by the audited control set.
				Auditors can confirm "who had access when" from start / end dates here.
			</p>
		</div>
		<div class="flex items-center gap-2">
			<button
				type="button"
				onclick={exportCsv}
				disabled={personnel.length === 0}
				class="flex items-center gap-1.5 rounded-md border border-zinc-800 px-3 py-1.5 text-sm text-zinc-300 hover:text-zinc-100 disabled:opacity-50"
			>
				<Download class="h-4 w-4" />
				CSV
			</button>
			<a
				href="/personnel/new"
				class="flex items-center gap-1.5 rounded-md px-3 py-1.5 text-sm font-medium text-zinc-950"
				style="background-color: var(--accent);"
			>
				<Plus class="h-4 w-4" />
				Add member
			</a>
		</div>
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
			<option value="active">Active</option>
			<option value="on_leave">On leave</option>
			<option value="terminated">Terminated</option>
		</select>
	</div>

	<div class="mt-3 overflow-hidden rounded-md border border-zinc-800">
		{#if loading}
			<div class="flex items-center justify-center py-10 text-zinc-500">
				<Loader2 class="h-5 w-5 animate-spin" />
			</div>
		{:else if personnel.length === 0}
			<div class="px-6 py-16 text-center">
				<p class="text-sm text-zinc-400">
					{statusFilter
						? `No ${statusFilter.replace('_', ' ')} personnel.`
						: 'No personnel records yet.'}
				</p>
				<a
					href="/personnel/new"
					class="mt-3 inline-block text-sm underline decoration-dotted underline-offset-4"
					style="color: var(--accent);">Add the first one →</a
				>
			</div>
		{:else}
			<table class="w-full text-sm">
				<thead class="bg-zinc-900/60 text-left text-xs uppercase tracking-wide text-zinc-500">
					<tr>
						<th class="px-4 py-2 font-medium">Name</th>
						<th class="px-4 py-2 font-medium">Role</th>
						<th class="px-4 py-2 font-medium">Department</th>
						<th class="px-4 py-2 font-medium">Start</th>
						<th class="px-4 py-2 font-medium">End</th>
						<th class="px-4 py-2 font-medium">Status</th>
					</tr>
				</thead>
				<tbody class="divide-y divide-zinc-800">
					{#each personnel as p (p.id)}
						<tr class="hover:bg-zinc-900/40">
							<td class="px-4 py-2.5">
								<a
									href="/personnel/{p.id}"
									class="text-zinc-100 underline-offset-4 hover:underline"
								>
									{p.full_name}
								</a>
								<div class="text-xs text-zinc-500">{p.email}</div>
							</td>
							<td class="px-4 py-2.5 text-zinc-300">{p.role}</td>
							<td class="px-4 py-2.5 text-zinc-400">{p.department ?? '—'}</td>
							<td class="px-4 py-2.5 text-zinc-400">{fmtDate(p.start_date)}</td>
							<td class="px-4 py-2.5 text-zinc-400">{fmtDate(p.end_date)}</td>
							<td class="px-4 py-2.5">
								<span class={statusClass(p.status)}>{p.status.replace('_', ' ')}</span>
							</td>
						</tr>
					{/each}
				</tbody>
			</table>
		{/if}
	</div>
</div>
