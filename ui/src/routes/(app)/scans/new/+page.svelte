<script lang="ts">
	import { goto } from '$app/navigation';
	import { listConnectors, type Connector } from '$lib/api/connectors';
	import { triggerScan } from '$lib/api/scans';
	import { toasts } from '$lib/stores/toasts.svelte';
	import { Loader2 } from 'lucide-svelte';

	let connectors = $state<Connector[]>([]);
	let loading = $state(true);
	let connectorId = $state('');
	let submitting = $state(false);

	$effect(() => {
		(async () => {
			try {
				connectors = (await listConnectors()).filter((c) => !c.is_disabled);
				if (connectors.length > 0) connectorId = connectors[0].id;
			} catch (e) {
				toasts.error((e as Error).message);
			} finally {
				loading = false;
			}
		})();
	});

	async function submit(e: SubmitEvent) {
		e.preventDefault();
		if (submitting || !connectorId) return;
		submitting = true;
		try {
			const scan = await triggerScan(connectorId);
			toasts.success('Scan queued.');
			await goto(`/scans/${scan.id}`);
		} catch (err) {
			toasts.error((err as Error).message);
			submitting = false;
		}
	}
</script>

<svelte:head>
	<title>Run scan · Touchstone GRC</title>
</svelte:head>

<div class="mx-auto max-w-xl px-8 py-10">
	<a href="/scans" class="text-sm text-zinc-500 underline-offset-4 hover:underline">← Scans</a>
	<h1 class="mt-2 text-2xl font-semibold tracking-tight text-zinc-100">Run scan</h1>
	<p class="mt-1 text-sm text-zinc-400">
		Picks up the connector configuration, enumerates resources, and evaluates every enabled control.
	</p>

	{#if loading}
		<div class="mt-8 flex items-center gap-2 text-zinc-500">
			<Loader2 class="h-4 w-4 animate-spin" /> Loading connectors…
		</div>
	{:else if connectors.length === 0}
		<div class="mt-8 rounded-md border border-zinc-800 bg-zinc-900/40 p-5 text-sm">
			<p class="text-zinc-300">No enabled connectors.</p>
			<p class="mt-2 text-zinc-500">
				<a href="/connectors/new" class="underline decoration-dotted underline-offset-4">
					Create one →
				</a>
			</p>
		</div>
	{:else}
		<form onsubmit={submit} class="mt-8 space-y-5">
			<div>
				<label for="connector" class="mb-1 block text-sm text-zinc-300">Connector</label>
				<select id="connector" bind:value={connectorId} class="field-input">
					{#each connectors as c (c.id)}
						<option value={c.id}>{c.name} ({c.kind.toUpperCase()})</option>
					{/each}
				</select>
			</div>

			<div class="flex items-center gap-3 pt-2">
				<button
					type="submit"
					disabled={submitting}
					class="flex items-center gap-2 rounded-md px-4 py-1.5 text-sm font-medium text-zinc-950 disabled:opacity-50"
					style="background-color: var(--accent);"
				>
					{#if submitting}<Loader2 class="h-4 w-4 animate-spin" />{/if}
					Queue scan
				</button>
				<a href="/scans" class="text-sm text-zinc-400 hover:text-zinc-200">Cancel</a>
			</div>
		</form>
	{/if}
</div>
