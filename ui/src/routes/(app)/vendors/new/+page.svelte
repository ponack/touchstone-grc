<script lang="ts">
	import { goto } from '$app/navigation';
	import { createVendor } from '$lib/api/vendors';
	import { listPersonnel, type Person } from '$lib/api/personnel';
	import { toasts } from '$lib/stores/toasts.svelte';
	import VendorForm from '$lib/components/VendorForm.svelte';

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

	async function submit(values: Parameters<typeof createVendor>[0]) {
		submitting = true;
		try {
			await createVendor(values);
			toasts.success('Vendor added.');
			await goto('/vendors');
		} catch (e) {
			toasts.error((e as Error).message);
			submitting = false;
		}
	}
</script>

<svelte:head>
	<title>Add vendor · Touchstone GRC</title>
</svelte:head>

<div class="mx-auto max-w-2xl px-8 py-10">
	<a href="/vendors" class="text-sm text-zinc-500 underline-offset-4 hover:underline">← Vendors</a>
	<h1 class="mt-2 text-2xl font-semibold tracking-tight text-zinc-100">Add vendor</h1>
	<p class="mt-1 text-sm text-zinc-400">
		One record per third-party supplier in scope. Owners come from the personnel register — add the
		person first if they're missing.
	</p>

	<div class="mt-8">
		<VendorForm
			mode="create"
			{owners}
			{submitting}
			onSubmit={submit}
			onCancel={() => goto('/vendors')}
		/>
	</div>
</div>
