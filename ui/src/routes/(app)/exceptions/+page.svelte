<script lang="ts">
	import { listExceptions, revokeException, type Exception } from '$lib/api/exceptions';
	import { toasts } from '$lib/stores/toasts.svelte';
	import { Plus } from 'lucide-svelte';
	import Pill from '$lib/components/Pill.svelte';
	import PageHeader from '$lib/components/PageHeader.svelte';
	import SkeletonRows from '$lib/components/SkeletonRows.svelte';
	import EmptyState from '$lib/components/EmptyState.svelte';
	import { ShieldOff } from 'lucide-svelte';

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
	<PageHeader
		kicker="Evidence pipeline"
		title="Exceptions"
		subtitle="Acknowledged gaps. Each exception explains why a failing control is accepted; the failed evidence row stays intact for audit."
	>
		{#snippet actions()}
			<a
				href="/exceptions/new"
				class="flex items-center gap-1.5 rounded-md px-3 py-1.5 text-sm font-medium text-zinc-950"
				style="background-color: var(--accent);"
			>
				<Plus class="h-4 w-4" />
				Grant exception
			</a>
		{/snippet}
	</PageHeader>

	<label class="mt-6 inline-flex items-center gap-2 text-sm text-zinc-400">
		<input type="checkbox" bind:checked={includeRevoked} onchange={refresh} />
		Include revoked
	</label>

	<div class="mt-3 overflow-hidden rounded-md border border-zinc-800">
		{#if loading}
			<SkeletonRows count={5} columns={['w-48', 'w-64', 'w-20', 'w-24', 'w-16']} />
		{:else if exceptions.length === 0}
			<EmptyState
				icon={ShieldOff}
				title={includeRevoked ? 'No exceptions granted yet' : 'No active exceptions'}
				body="An exception acknowledges a failing control with a written reason. The failed evidence row stays intact for audit; future scans flag the gap as accepted until the exception expires or is revoked."
				samples={[
					'Service-account keys rotated by an external pipeline (CC6.3 scope)',
					'Public bucket fronting a static marketing site (CC6.6 scope)',
					'Non-billing-impacting low-criticality CIS findings during migration'
				]}
			>
				{#snippet cta()}
					<a
						href="/exceptions/new"
						class="inline-flex items-center gap-1.5 rounded-md px-3 py-1.5 text-sm font-medium text-zinc-950"
						style="background-color: var(--accent);"
					>
						<Plus class="h-4 w-4" /> Grant an exception
					</a>
				{/snippet}
			</EmptyState>
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
									<Pill kind="muted">revoked</Pill>
								{:else if e.expires_at && new Date(e.expires_at) < new Date()}
									<Pill kind="muted">expired</Pill>
								{:else}
									<Pill kind="success">active</Pill>
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
