<script lang="ts">
	import { goto } from '$app/navigation';
	import { createRisk } from '$lib/api/risks';
	import { listPersonnel, type Person } from '$lib/api/personnel';
	import { listAssets, type Asset } from '$lib/api/assets';
	import { listVendors, type Vendor } from '$lib/api/vendors';
	import { toasts } from '$lib/stores/toasts.svelte';
	import RiskForm from '$lib/components/RiskForm.svelte';

	let owners = $state<Person[]>([]);
	let assets = $state<Asset[]>([]);
	let vendors = $state<Vendor[]>([]);
	let submitting = $state(false);

	$effect(() => {
		(async () => {
			try {
				const [p, a, v] = await Promise.all([
					listPersonnel('active'),
					listAssets({ status: 'active' }),
					listVendors({ status: 'active' })
				]);
				owners = p;
				assets = a;
				vendors = v;
			} catch (e) {
				toasts.error((e as Error).message);
			}
		})();
	});

	async function submit(values: Parameters<typeof createRisk>[0]) {
		submitting = true;
		try {
			await createRisk(values);
			toasts.success('Risk logged.');
			await goto('/risks');
		} catch (e) {
			toasts.error((e as Error).message);
			submitting = false;
		}
	}
</script>

<svelte:head>
	<title>Log risk · Touchstone GRC</title>
</svelte:head>

<div class="mx-auto max-w-3xl px-8 py-10">
	<a href="/risks" class="text-sm text-zinc-500 underline-offset-4 hover:underline">← Risks</a>
	<h1 class="mt-2 font-serif text-2xl text-zinc-100" style="letter-spacing: -0.01em;">Log risk</h1>
	<p class="mt-1 text-sm text-zinc-400">
		One record per identified risk. Capture inherent + residual L × I and the treatment plan so the
		risk's place in the audit trail is unambiguous.
	</p>

	<div class="mt-8">
		<RiskForm
			mode="create"
			{owners}
			{assets}
			{vendors}
			{submitting}
			onSubmit={submit}
			onCancel={() => goto('/risks')}
		/>
	</div>
</div>
