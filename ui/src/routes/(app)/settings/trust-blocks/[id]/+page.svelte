<script lang="ts">
	import { goto } from '$app/navigation';
	import { page } from '$app/state';
	import { auth } from '$lib/stores/auth.svelte';
	import {
		deleteTrustBlock,
		getTrustBlock,
		updateTrustBlock,
		type TrustBlock
	} from '$lib/api/trust-blocks';
	import { toasts } from '$lib/stores/toasts.svelte';
	import BlockForm from '$lib/components/BlockForm.svelte';
	import { Loader2, Trash2 } from 'lucide-svelte';

	let block = $state<TrustBlock | null>(null);
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
				block = await getTrustBlock(id);
			} catch (e) {
				toasts.error((e as Error).message);
				await goto('/settings/trust-blocks');
			} finally {
				loading = false;
			}
		})();
	});

	async function submit(values: Parameters<typeof updateTrustBlock>[1]) {
		submitting = true;
		try {
			await updateTrustBlock(id, values);
			toasts.success('Block updated.');
			await goto('/settings/trust-blocks');
		} catch (e) {
			toasts.error((e as Error).message);
			submitting = false;
		}
	}

	async function handleDelete() {
		if (!block) return;
		if (!confirm(`Delete "${block.heading}"? Audit log retains the action.`)) return;
		deleting = true;
		try {
			await deleteTrustBlock(id);
			toasts.info('Block deleted.');
			await goto('/settings/trust-blocks');
		} catch (e) {
			toasts.error((e as Error).message);
			deleting = false;
		}
	}
</script>

<svelte:head>
	<title>{block?.heading ?? 'Block'} · Touchstone GRC</title>
</svelte:head>

<div class="mx-auto max-w-3xl px-8 py-10">
	<a href="/settings/trust-blocks" class="text-sm text-zinc-500 underline-offset-4 hover:underline">
		← Custom blocks
	</a>

	{#if loading}
		<div class="mt-8 flex items-center gap-2 text-zinc-500">
			<Loader2 class="h-4 w-4 animate-spin" /> Loading…
		</div>
	{:else if block}
		<div class="mt-2 flex items-start justify-between gap-6">
			<div class="min-w-0">
				<h1 class="font-serif text-2xl text-zinc-100" style="letter-spacing: -0.01em;">
					{block.heading}
				</h1>
				<p class="mt-1 text-sm text-zinc-400">
					position {block.position}
					{#if block.is_public}
						· published on Trust Center
					{:else}
						· draft (not public)
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
			<BlockForm
				mode="edit"
				initial={block}
				{submitting}
				onSubmit={submit}
				onCancel={() => goto('/settings/trust-blocks')}
			/>
		</div>
	{/if}
</div>
