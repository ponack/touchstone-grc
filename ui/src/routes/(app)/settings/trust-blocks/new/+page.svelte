<script lang="ts">
	import { goto } from '$app/navigation';
	import { auth } from '$lib/stores/auth.svelte';
	import { createTrustBlock } from '$lib/api/trust-blocks';
	import { toasts } from '$lib/stores/toasts.svelte';
	import BlockForm from '$lib/components/BlockForm.svelte';

	let submitting = $state(false);

	$effect(() => {
		(async () => {
			if (auth.me && !auth.me.is_admin) {
				await goto('/');
			}
		})();
	});

	async function submit(values: Parameters<typeof createTrustBlock>[0]) {
		submitting = true;
		try {
			await createTrustBlock(values);
			toasts.success('Block added.');
			await goto('/settings/trust-blocks');
		} catch (e) {
			toasts.error((e as Error).message);
			submitting = false;
		}
	}
</script>

<svelte:head>
	<title>Add block · Touchstone GRC</title>
</svelte:head>

<div class="mx-auto max-w-3xl px-8 py-10">
	<a href="/settings/trust-blocks" class="text-sm text-zinc-500 underline-offset-4 hover:underline">
		← Custom blocks
	</a>
	<h1 class="mt-2 font-serif text-2xl text-zinc-100" style="letter-spacing: -0.01em;">
		Add block
	</h1>
	<p class="mt-1 text-sm text-zinc-400">
		New blocks land at the end of the current list. Use the Preview toggle to see the rendered
		Markdown before publishing.
	</p>

	<div class="mt-8">
		<BlockForm
			mode="create"
			{submitting}
			onSubmit={submit}
			onCancel={() => goto('/settings/trust-blocks')}
		/>
	</div>
</div>
