<script lang="ts">
	import { goto } from '$app/navigation';
	import { page } from '$app/state';
	import { deleteRisk, getRisk, updateRisk, type Risk } from '$lib/api/risks';
	import { listPersonnel, type Person } from '$lib/api/personnel';
	import { listAssets, type Asset } from '$lib/api/assets';
	import { listVendors, type Vendor } from '$lib/api/vendors';
	import { toasts } from '$lib/stores/toasts.svelte';
	import RiskForm from '$lib/components/RiskForm.svelte';
	import { Loader2, Trash2 } from 'lucide-svelte';

	let risk = $state<Risk | null>(null);
	let owners = $state<Person[]>([]);
	let assets = $state<Asset[]>([]);
	let vendors = $state<Vendor[]>([]);
	let loading = $state(true);
	let submitting = $state(false);
	let deleting = $state(false);

	const id = $derived(page.params.id!);

	$effect(() => {
		(async () => {
			loading = true;
			try {
				const [r, p, a, v] = await Promise.all([
					getRisk(id),
					listPersonnel(),
					listAssets(),
					listVendors()
				]);
				risk = r;
				// Drop terminated personnel from the picker unless they
				// were the existing owner — same pattern the asset / vendor
				// edit pages use.
				owners = p.filter((x) => x.status !== 'terminated' || x.id === r.owner_id);
				assets = a.filter(
					(x) => x.status !== 'decommissioned' || x.id === r.related_asset_id
				);
				vendors = v.filter((x) => x.status !== 'terminated' || x.id === r.related_vendor_id);
			} catch (e) {
				toasts.error((e as Error).message);
				await goto('/risks');
			} finally {
				loading = false;
			}
		})();
	});

	async function submit(values: Parameters<typeof updateRisk>[1]) {
		submitting = true;
		try {
			await updateRisk(id, values);
			toasts.success('Risk updated.');
			await goto('/risks');
		} catch (e) {
			toasts.error((e as Error).message);
			submitting = false;
		}
	}

	async function handleDelete() {
		if (!risk) return;
		if (!confirm(`Delete the risk "${risk.title}"? Audit log retains the action.`)) return;
		deleting = true;
		try {
			await deleteRisk(id);
			toasts.info('Risk deleted.');
			await goto('/risks');
		} catch (e) {
			toasts.error((e as Error).message);
			deleting = false;
		}
	}
</script>

<svelte:head>
	<title>{risk?.title ?? 'Risk'} · Touchstone GRC</title>
</svelte:head>

<div class="mx-auto max-w-3xl px-8 py-10">
	<a href="/risks" class="text-sm text-zinc-500 underline-offset-4 hover:underline">← Risks</a>

	{#if loading}
		<div class="mt-8 flex items-center gap-2 text-zinc-500">
			<Loader2 class="h-4 w-4 animate-spin" /> Loading…
		</div>
	{:else if risk}
		<div class="mt-2 flex items-start justify-between gap-6">
			<div class="min-w-0">
				<h1 class="font-serif text-2xl text-zinc-100" style="letter-spacing: -0.01em;">
					{risk.title}
				</h1>
				<p class="mt-1 text-sm text-zinc-400">
					{risk.risk_category.replace('_', '-')} · {risk.status}
					{#if risk.owner_name}
						· owner {risk.owner_name}
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
			<RiskForm
				mode="edit"
				initial={risk}
				{owners}
				{assets}
				{vendors}
				{submitting}
				onSubmit={submit}
				onCancel={() => goto('/risks')}
			/>
		</div>
	{/if}
</div>
