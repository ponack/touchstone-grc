<script lang="ts">
	import { goto } from '$app/navigation';
	import { auth } from '$lib/stores/auth.svelte';
	import { createTrustIncident } from '$lib/api/trust-incidents';
	import { toasts } from '$lib/stores/toasts.svelte';
	import IncidentForm from '$lib/components/IncidentForm.svelte';

	let submitting = $state(false);

	$effect(() => {
		(async () => {
			if (auth.me && !auth.me.is_admin) {
				await goto('/');
			}
		})();
	});

	async function submit(values: Parameters<typeof createTrustIncident>[0]) {
		submitting = true;
		try {
			await createTrustIncident(values);
			toasts.success('Incident logged.');
			await goto('/settings/trust-incidents');
		} catch (e) {
			toasts.error((e as Error).message);
			submitting = false;
		}
	}
</script>

<svelte:head>
	<title>Log incident · Touchstone GRC</title>
</svelte:head>

<div class="mx-auto max-w-3xl px-8 py-10">
	<a
		href="/settings/trust-incidents"
		class="text-sm text-zinc-500 underline-offset-4 hover:underline"
	>
		← Incidents
	</a>
	<h1 class="mt-2 font-serif text-2xl text-zinc-100" style="letter-spacing: -0.01em;">
		Log incident
	</h1>
	<p class="mt-1 text-sm text-zinc-400">
		Capture the internal record first. Public response + visibility flag below decide what (if
		anything) reaches the customer-facing Trust Center.
	</p>

	<div class="mt-8">
		<IncidentForm
			mode="create"
			{submitting}
			onSubmit={submit}
			onCancel={() => goto('/settings/trust-incidents')}
		/>
	</div>
</div>
