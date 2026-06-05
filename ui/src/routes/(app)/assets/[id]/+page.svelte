<script lang="ts">
	import { goto } from '$app/navigation';
	import { page } from '$app/state';
	import { deleteAsset, getAsset, updateAsset, type Asset } from '$lib/api/assets';
	import { listPersonnel, type Person } from '$lib/api/personnel';
	import { toasts } from '$lib/stores/toasts.svelte';
	import AssetForm from '$lib/components/AssetForm.svelte';
	import { Loader2, Trash2 } from 'lucide-svelte';

	let asset = $state<Asset | null>(null);
	let owners = $state<Person[]>([]);
	let loading = $state(true);
	let submitting = $state(false);
	let deleting = $state(false);

	const id = $derived(page.params.id!);

	$effect(() => {
		(async () => {
			loading = true;
			try {
				const [a, people] = await Promise.all([getAsset(id), listPersonnel()]);
				asset = a;
				// Owners list excludes terminated personnel unless they were
				// already the owner — keeps the dropdown short but never hides
				// the existing assignment.
				owners = people.filter((p) => p.status !== 'terminated' || p.id === a.owner_id);
			} catch (e) {
				toasts.error((e as Error).message);
				await goto('/assets');
			} finally {
				loading = false;
			}
		})();
	});

	async function submit(values: Parameters<typeof updateAsset>[1]) {
		submitting = true;
		try {
			await updateAsset(id, values);
			toasts.success('Asset updated.');
			await goto('/assets');
		} catch (e) {
			toasts.error((e as Error).message);
			submitting = false;
		}
	}

	async function handleDelete() {
		if (!asset) return;
		if (!confirm(`Delete ${asset.name}? Audit log retains the action.`)) return;
		deleting = true;
		try {
			await deleteAsset(id);
			toasts.info('Asset deleted.');
			await goto('/assets');
		} catch (e) {
			toasts.error((e as Error).message);
			deleting = false;
		}
	}
</script>

<svelte:head>
	<title>{asset?.name ?? 'Asset'} · Touchstone GRC</title>
</svelte:head>

<div class="mx-auto max-w-2xl px-8 py-10">
	<a href="/assets" class="text-sm text-zinc-500 underline-offset-4 hover:underline">← Assets</a>

	{#if loading}
		<div class="mt-8 flex items-center gap-2 text-zinc-500">
			<Loader2 class="h-4 w-4 animate-spin" /> Loading…
		</div>
	{:else if asset}
		<div class="mt-2 flex items-start justify-between">
			<div>
				<h1 class="text-2xl font-semibold tracking-tight text-zinc-100">{asset.name}</h1>
				<p class="mt-1 text-sm text-zinc-400">
					{asset.asset_type.replace('_', ' ')} · {asset.environment}
					{#if asset.owner_name}
						· owner {asset.owner_name}
					{/if}
				</p>
			</div>
			<button
				type="button"
				onclick={handleDelete}
				disabled={deleting}
				class="flex items-center gap-1.5 rounded-md border border-red-900/50 px-3 py-1.5 text-sm text-red-400 hover:bg-red-950/30 disabled:opacity-50"
			>
				<Trash2 class="h-4 w-4" />
				{deleting ? 'Deleting…' : 'Delete'}
			</button>
		</div>

		<div class="mt-8">
			<AssetForm
				mode="edit"
				initial={asset}
				{owners}
				{submitting}
				onSubmit={submit}
				onCancel={() => goto('/assets')}
			/>
		</div>
	{/if}
</div>
