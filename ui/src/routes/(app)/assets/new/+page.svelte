<script lang="ts">
	import { goto } from '$app/navigation';
	import { createAsset } from '$lib/api/assets';
	import { listPersonnel, type Person } from '$lib/api/personnel';
	import { toasts } from '$lib/stores/toasts.svelte';
	import AssetForm from '$lib/components/AssetForm.svelte';

	let owners = $state<Person[]>([]);
	let submitting = $state(false);

	$effect(() => {
		(async () => {
			try {
				owners = await listPersonnel('active');
			} catch (e) {
				toasts.error((e as Error).message);
			}
		})();
	});

	async function submit(values: Parameters<typeof createAsset>[0]) {
		submitting = true;
		try {
			await createAsset(values);
			toasts.success('Asset added.');
			await goto('/assets');
		} catch (e) {
			toasts.error((e as Error).message);
			submitting = false;
		}
	}
</script>

<svelte:head>
	<title>Add asset · Touchstone GRC</title>
</svelte:head>

<div class="mx-auto max-w-2xl px-8 py-10">
	<a href="/assets" class="text-sm text-zinc-500 underline-offset-4 hover:underline">← Assets</a>
	<h1 class="mt-2 text-2xl font-semibold tracking-tight text-zinc-100">Add asset</h1>
	<p class="mt-1 text-sm text-zinc-400">
		One record per audited system. Owners come from the personnel register — add the person first
		if they're missing.
	</p>

	<div class="mt-8">
		<AssetForm
			mode="create"
			{owners}
			{submitting}
			onSubmit={submit}
			onCancel={() => goto('/assets')}
		/>
	</div>
</div>
