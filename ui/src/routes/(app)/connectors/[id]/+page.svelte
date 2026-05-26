<script lang="ts">
	import { goto } from '$app/navigation';
	import { page } from '$app/state';
	import {
		deleteConnector,
		getConnector,
		updateConnector,
		type Connector
	} from '$lib/api/connectors';
	import { toasts } from '$lib/stores/toasts.svelte';
	import { Loader2 } from 'lucide-svelte';

	let connector = $state<Connector | null>(null);
	let loading = $state(true);
	let saving = $state(false);
	let deleting = $state(false);

	let name = $state('');
	let scheduleCron = $state('');
	let isDisabled = $state(false);

	const id = $derived(page.params.id!);

	$effect(() => {
		(async () => {
			try {
				connector = await getConnector(id);
				name = connector.name;
				scheduleCron = connector.schedule_cron ?? '';
				isDisabled = connector.is_disabled;
			} catch (e) {
				toasts.error((e as Error).message);
			} finally {
				loading = false;
			}
		})();
	});

	async function save(e: SubmitEvent) {
		e.preventDefault();
		if (saving) return;
		saving = true;
		try {
			connector = await updateConnector(id, {
				name: name.trim(),
				schedule_cron: scheduleCron.trim() || null,
				is_disabled: isDisabled
			});
			toasts.success('Saved.');
		} catch (err) {
			toasts.error((err as Error).message);
		} finally {
			saving = false;
		}
	}

	async function handleDelete() {
		if (!confirm(`Delete connector "${connector?.name}"? This cannot be undone.`)) return;
		deleting = true;
		try {
			await deleteConnector(id);
			toasts.info('Connector deleted.');
			await goto('/connectors');
		} catch (err) {
			toasts.error((err as Error).message);
			deleting = false;
		}
	}
</script>

<svelte:head>
	<title>{connector?.name ?? 'Connector'} · Touchstone GRC</title>
</svelte:head>

<div class="mx-auto max-w-2xl px-8 py-10">
	<a href="/connectors" class="text-sm text-zinc-500 underline-offset-4 hover:underline"
		>← Connectors</a
	>

	{#if loading}
		<div class="mt-6 flex items-center gap-2 text-zinc-500">
			<Loader2 class="h-4 w-4 animate-spin" /> Loading…
		</div>
	{:else if !connector}
		<p class="mt-6 text-sm text-red-400">Connector not found.</p>
	{:else}
		<h1 class="mt-2 text-2xl font-semibold tracking-tight text-zinc-100">{connector.name}</h1>
		<p class="mt-1 text-sm text-zinc-500">{connector.kind.toUpperCase()} · ID {connector.id}</p>

		<form onsubmit={save} class="mt-8 space-y-5">
			<div>
				<label for="name" class="mb-1 block text-sm text-zinc-300">Name</label>
				<input id="name" type="text" required bind:value={name} class="field-input" />
			</div>

			<div>
				<label for="schedule_cron" class="mb-1 block text-sm text-zinc-300">
					Schedule <span class="text-xs text-zinc-500">(cron, blank = on-demand)</span>
				</label>
				<input id="schedule_cron" type="text" bind:value={scheduleCron} class="field-input" />
			</div>

			<label class="flex items-center gap-2 text-sm text-zinc-300">
				<input type="checkbox" bind:checked={isDisabled} />
				Disabled
			</label>

			<div class="flex items-center justify-between pt-2">
				<button
					type="submit"
					disabled={saving}
					class="flex items-center gap-2 rounded-md px-4 py-1.5 text-sm font-medium text-zinc-950 disabled:opacity-50"
					style="background-color: var(--accent);"
				>
					{#if saving}<Loader2 class="h-4 w-4 animate-spin" />{/if}
					Save changes
				</button>
				<button
					type="button"
					onclick={handleDelete}
					disabled={deleting}
					class="rounded-md border border-red-900 px-3 py-1.5 text-sm text-red-400 hover:bg-red-950/40 disabled:opacity-50"
				>
					Delete
				</button>
			</div>
		</form>

		<details class="mt-10 rounded-md border border-zinc-800 bg-zinc-900/40 p-4 text-sm">
			<summary class="cursor-pointer text-zinc-300">Raw config</summary>
			<pre class="mt-3 overflow-auto text-xs text-zinc-400">{JSON.stringify(
					connector.config,
					null,
					2
				)}</pre>
		</details>
	{/if}
</div>
