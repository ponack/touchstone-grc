<script lang="ts">
	import { goto } from '$app/navigation';
	import { page } from '$app/state';
	import { auth } from '$lib/stores/auth.svelte';
	import {
		deleteTrustIncident,
		getTrustIncident,
		updateTrustIncident,
		type TrustIncident
	} from '$lib/api/trust-incidents';
	import { toasts } from '$lib/stores/toasts.svelte';
	import IncidentForm from '$lib/components/IncidentForm.svelte';
	import { Loader2, Trash2 } from 'lucide-svelte';

	let incident = $state<TrustIncident | null>(null);
	let loading = $state(true);
	let submitting = $state(false);
	let deleting = $state(false);

	const id = $derived(page.params.id!);

	$effect(() => {
		(async () => {
			if (auth.me && !auth.me.is_admin) {
				await goto('/');
				return;
			}
			loading = true;
			try {
				incident = await getTrustIncident(id);
			} catch (e) {
				toasts.error((e as Error).message);
				await goto('/settings/trust-incidents');
			} finally {
				loading = false;
			}
		})();
	});

	async function submit(values: Parameters<typeof updateTrustIncident>[1]) {
		submitting = true;
		try {
			await updateTrustIncident(id, values);
			toasts.success('Incident updated.');
			await goto('/settings/trust-incidents');
		} catch (e) {
			toasts.error((e as Error).message);
			submitting = false;
		}
	}

	async function handleDelete() {
		if (!incident) return;
		if (!confirm(`Delete the incident "${incident.title}"? Audit log retains the action.`)) return;
		deleting = true;
		try {
			await deleteTrustIncident(id);
			toasts.info('Incident deleted.');
			await goto('/settings/trust-incidents');
		} catch (e) {
			toasts.error((e as Error).message);
			deleting = false;
		}
	}
</script>

<svelte:head>
	<title>{incident?.title ?? 'Incident'} · Touchstone GRC</title>
</svelte:head>

<div class="mx-auto max-w-3xl px-8 py-10">
	<a
		href="/settings/trust-incidents"
		class="text-sm text-zinc-500 underline-offset-4 hover:underline"
	>
		← Incidents
	</a>

	{#if loading}
		<div class="mt-8 flex items-center gap-2 text-zinc-500">
			<Loader2 class="h-4 w-4 animate-spin" /> Loading…
		</div>
	{:else if incident}
		<div class="mt-2 flex items-start justify-between gap-6">
			<div class="min-w-0">
				<h1 class="font-serif text-2xl text-zinc-100" style="letter-spacing: -0.01em;">
					{incident.title}
				</h1>
				<p class="mt-1 text-sm text-zinc-400">
					{incident.severity} · {incident.status}
					{#if incident.is_public}
						· published on Trust Center
					{:else}
						· private (internal audit trail)
					{/if}
				</p>
			</div>
			<button
				type="button"
				onclick={handleDelete}
				disabled={deleting}
				class="flex shrink-0 items-center gap-1.5 rounded-md border border-red-900/50 px-3 py-1.5 text-sm text-red-400 hover:bg-red-950/30 disabled:opacity-50"
			>
				<Trash2 class="h-4 w-4" />
				{deleting ? 'Deleting…' : 'Delete'}
			</button>
		</div>

		<div class="mt-8">
			<IncidentForm
				mode="edit"
				initial={incident}
				{submitting}
				onSubmit={submit}
				onCancel={() => goto('/settings/trust-incidents')}
			/>
		</div>
	{/if}
</div>
