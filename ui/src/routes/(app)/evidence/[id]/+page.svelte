<script lang="ts">
	import { page } from '$app/state';
	import { getEvidence, type EvidenceDetail } from '$lib/api/evidence';
	import { toasts } from '$lib/stores/toasts.svelte';
	import StatusPill from '$lib/components/StatusPill.svelte';
	import { Loader2 } from 'lucide-svelte';

	let detail = $state<EvidenceDetail | null>(null);
	let loading = $state(true);

	const id = $derived(page.params.id!);

	$effect(() => {
		(async () => {
			try {
				detail = await getEvidence(id);
			} catch (e) {
				toasts.error((e as Error).message);
			} finally {
				loading = false;
			}
		})();
	});
</script>

<svelte:head>
	<title>{detail ? `${detail.control_code} — evidence` : 'Evidence'} · Touchstone GRC</title>
</svelte:head>

<div class="mx-auto max-w-3xl px-8 py-10">
	{#if loading}
		<div class="flex items-center gap-2 text-zinc-500">
			<Loader2 class="h-4 w-4 animate-spin" /> Loading…
		</div>
	{:else if !detail}
		<p class="text-sm text-red-400">Evidence not found.</p>
	{:else}
		<a
			href={`/scans/${detail.scan_id}`}
			class="text-sm text-zinc-500 underline-offset-4 hover:underline">← Scan</a
		>

		<div class="mt-2 flex flex-wrap items-center gap-3">
			<h1 class="text-2xl font-semibold tracking-tight text-zinc-100">{detail.control_code}</h1>
			<StatusPill status={detail.status} />
			<span class="rounded bg-zinc-800 px-1.5 py-0.5 text-xs uppercase text-zinc-400"
				>{detail.framework_code}</span
			>
		</div>
		<p class="mt-1 text-sm text-zinc-300">{detail.control_title}</p>

		{#if detail.details?.message}
			<div class="mt-6 rounded-md border border-zinc-800 bg-zinc-900/40 p-4 text-sm text-zinc-200">
				{detail.details.message}
			</div>
		{/if}

		{#if detail.details?.failures && detail.details.failures.length > 0}
			<h2 class="mt-8 text-sm font-semibold text-zinc-200">
				Failures ({detail.details.failures.length})
			</h2>
			<div class="mt-3 space-y-2">
				{#each detail.details.failures as f (f.resource_id ?? Math.random())}
					<div class="rounded-md border border-red-900/60 bg-red-950/20 p-3 text-sm">
						<div class="font-medium text-red-200">{f.reason ?? 'Violation'}</div>
						{#if f.resource_id}
							<div class="mt-1 break-all text-xs text-red-300/80">
								<span class="text-red-400/60">{f.resource_type ?? 'resource'}:</span>
								{f.resource_id}
							</div>
						{/if}
					</div>
				{/each}
			</div>
		{/if}

		<details class="mt-8 rounded-md border border-zinc-800 bg-zinc-900/40 p-4 text-sm">
			<summary class="cursor-pointer text-zinc-300">Raw OPA decision</summary>
			<pre class="mt-3 overflow-auto text-xs text-zinc-400">{JSON.stringify(
					detail.details,
					null,
					2
				)}</pre>
		</details>

		<p class="mt-6 text-xs text-zinc-500">
			Collected {new Date(detail.collected_at).toLocaleString()}
		</p>
	{/if}
</div>
