<script lang="ts">
	import { goto } from '$app/navigation';
	import { page } from '$app/state';
	import { deleteVendor, getVendor, updateVendor, type Vendor } from '$lib/api/vendors';
	import { listPersonnel, type Person } from '$lib/api/personnel';
	import { toasts } from '$lib/stores/toasts.svelte';
	import VendorForm from '$lib/components/VendorForm.svelte';
	import { Loader2, Trash2 } from 'lucide-svelte';

	let vendor = $state<Vendor | null>(null);
	let owners = $state<Person[]>([]);
	let loading = $state(true);
	let submitting = $state(false);
	let deleting = $state(false);

	const id = $derived(page.params.id!);

	$effect(() => {
		(async () => {
			loading = true;
			try {
				const [v, people] = await Promise.all([getVendor(id), listPersonnel()]);
				vendor = v;
				// Owners list excludes terminated personnel unless they were
				// already the owner — keeps the dropdown short but never hides
				// the existing assignment.
				owners = people.filter((p) => p.status !== 'terminated' || p.id === v.owner_id);
			} catch (e) {
				toasts.error((e as Error).message);
				await goto('/vendors');
			} finally {
				loading = false;
			}
		})();
	});

	async function submit(values: Parameters<typeof updateVendor>[1]) {
		submitting = true;
		try {
			await updateVendor(id, values);
			toasts.success('Vendor updated.');
			await goto('/vendors');
		} catch (e) {
			toasts.error((e as Error).message);
			submitting = false;
		}
	}

	async function handleDelete() {
		if (!vendor) return;
		if (!confirm(`Delete ${vendor.name}? Audit log retains the action.`)) return;
		deleting = true;
		try {
			await deleteVendor(id);
			toasts.info('Vendor deleted.');
			await goto('/vendors');
		} catch (e) {
			toasts.error((e as Error).message);
			deleting = false;
		}
	}
</script>

<svelte:head>
	<title>{vendor?.name ?? 'Vendor'} · Touchstone GRC</title>
</svelte:head>

<div class="mx-auto max-w-2xl px-8 py-10">
	<a href="/vendors" class="text-sm text-zinc-500 underline-offset-4 hover:underline">← Vendors</a>

	{#if loading}
		<div class="mt-8 flex items-center gap-2 text-zinc-500">
			<Loader2 class="h-4 w-4 animate-spin" /> Loading…
		</div>
	{:else if vendor}
		<div class="mt-2 flex items-start justify-between">
			<div>
				<h1 class="text-2xl font-semibold tracking-tight text-zinc-100">{vendor.name}</h1>
				<p class="mt-1 text-sm text-zinc-400">
					{vendor.vendor_type} · {vendor.status}
					{#if vendor.owner_name}
						· owner {vendor.owner_name}
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
			<VendorForm
				mode="edit"
				initial={vendor}
				{owners}
				{submitting}
				onSubmit={submit}
				onCancel={() => goto('/vendors')}
			/>
		</div>
	{/if}
</div>
