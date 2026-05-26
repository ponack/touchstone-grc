<script lang="ts">
	import { listExceptions, revokeException, type Exception } from '$lib/api/exceptions';
	import { toasts } from '$lib/stores/toasts.svelte';
	import { Plus, Loader2 } from 'lucide-svelte';

	let exceptions = $state<Exception[]>([]);
	let loading = $state(true);
	let includeRevoked = $state(false);
	let revokingID = $state<string | null>(null);

	async function refresh() {
		try {
			exceptions = await listExceptions(includeRevoked);
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

	async function handleRevoke(id: string, label: string) {
		if (!confirm(`Revoke exception for ${label}? Future scans will fail this control again.`)) return;
		revokingID = id;
		try {
			await revokeException(id);
			await refresh();
			toasts.info('Exception revoked.');
		} catch (e) {
			toasts.error((e as Error).message);
		} finally {
			revokingID = null;
		}
	}

	function fmtExpiry(s?: string | null) {
		if (!s) return 'permanent';
		const d = new Date(s);
		const now = new Date();
		if (d < now) return `expired ${d.toLocaleDateString()}`;
		return `until ${d.toLocaleDateString()}`;
	}
</script>

<svelte:head>
	<title>Exceptions · Touchstone GRC</title>
</svelte:head>

<div class="mx-auto max-w-5xl px-8 py-10">
	<div class="flex items-center justify-between">
		<div>
			<h1 class="text-2xl font-semibold tracking-tight text-zinc-100">Exceptions</h1>
			<p class="mt-1 text-sm text-zinc-400">
				Acknowledged gaps. Each exception explains why a failing control is accepted; the failed
				evidence row stays intact for audit.
			</p>
		</div>
		<a
			href="/exceptions/new"
			class="flex items-center gap-1.5 rounded-md px-3 py-1.5 text-sm font-medium text-zinc-950"
			style="background-color: var(--accent);"
		>
			<Plus class="h-4 w-4" />
			Grant exception
		</a>
	</div>

	<label class="mt-6 inline-flex items-center gap-2 text-sm text-zinc-400">
		<input type="checkbox" bind:checked={includeRevoked} onchange={refresh} />
		Include revoked
	</label>

	<div class="mt-3 overflow-hidden rounded-md border border-zinc-800">
		{#if loading}
			<div class="flex items-center justify-center py-10 text-zinc-500">
				<Loader2 class="h-5 w-5 animate-spin" />
			</div>
		{:else if exceptions.length === 0}
			<div class="px-6 py-16 text-center">
				<p class="text-sm text-zinc-400">
					{includeRevoked ? 'No exceptions granted yet.' : 'No active exceptions.'}
				</p>
				<a
					href="/exceptions/new"
					class="mt-3 inline-block text-sm underline decoration-dotted underline-offset-4"
					style="color: var(--accent);">Grant one →</a
				>
			</div>
		{:else}
			<table class="w-full text-sm">
				<thead class="bg-zinc-900/60 text-left text-xs uppercase tracking-wide text-zinc-500">
					<tr>
						<th class="px-4 py-2 font-medium">Control</th>
						<th class="px-4 py-2 font-medium">Reason</th>
						<th class="px-4 py-2 font-medium">Granted</th>
						<th class="px-4 py-2 font-medium">Expires</th>
						<th class="px-4 py-2 font-medium">Status</th>
						<th class="px-4 py-2"></th>
					</tr>
				</thead>
				<tbody class="divide-y divide-zinc-800">
					{#each exceptions as e (e.id)}
						<tr class="hover:bg-zinc-900/40">
							<td class="px-4 py-2.5">
								<span class="font-mono text-xs text-zinc-300">{e.control_code}</span>
								<span class="ml-2 text-zinc-400">{e.control_title}</span>
								{#if e.resource_key}
									<div class="mt-0.5 break-all text-xs text-zinc-500">{e.resource_key}</div>
								{/if}
							</td>
							<td class="px-4 py-2.5 text-zinc-300">{e.reason}</td>
							<td class="px-4 py-2.5 text-zinc-400">
								{new Date(e.granted_at).toLocaleDateString()}
							</td>
							<td class="px-4 py-2.5 text-zinc-400">{fmtExpiry(e.expires_at)}</td>
							<td class="px-4 py-2.5">
								{#if e.revoked_at}
									<span class="rounded bg-zinc-800 px-1.5 py-0.5 text-xs text-zinc-400">revoked</span>
								{:else if e.expires_at && new Date(e.expires_at) < new Date()}
									<span class="rounded bg-zinc-800 px-1.5 py-0.5 text-xs text-zinc-400">expired</span>
								{:else}
									<span
										class="rounded bg-emerald-950/50 px-1.5 py-0.5 text-xs text-emerald-300"
										>active</span
									>
								{/if}
							</td>
							<td class="px-4 py-2.5 text-right">
								{#if !e.revoked_at}
									<button
										type="button"
										onclick={() => handleRevoke(e.id, e.control_code)}
										disabled={revokingID === e.id}
										class="text-xs text-red-400 underline-offset-4 hover:underline disabled:opacity-50"
									>
										{revokingID === e.id ? 'Revoking…' : 'Revoke'}
									</button>
								{/if}
							</td>
						</tr>
					{/each}
				</tbody>
			</table>
		{/if}
	</div>
</div>
