<script lang="ts">
	import {
		listFrameworks,
		listOrgFrameworks,
		type Framework,
		type OrgFramework
	} from '$lib/api/frameworks';
	import { toasts } from '$lib/stores/toasts.svelte';
	import { Loader2, CheckCircle2 } from 'lucide-svelte';

	let frameworks = $state<Framework[]>([]);
	let enabled = $state<OrgFramework[]>([]);
	let loading = $state(true);

	const enabledCodes = $derived(new Set(enabled.map((e) => e.code)));

	$effect(() => {
		(async () => {
			try {
				[frameworks, enabled] = await Promise.all([listFrameworks(), listOrgFrameworks()]);
			} catch (e) {
				toasts.error((e as Error).message);
			} finally {
				loading = false;
			}
		})();
	});
</script>

<svelte:head>
	<title>Frameworks · Touchstone GRC</title>
</svelte:head>

<div class="mx-auto max-w-5xl px-8 py-10">
	<h1 class="text-2xl font-semibold tracking-tight text-zinc-100">Frameworks</h1>
	<p class="mt-1 text-sm text-zinc-400">
		Compliance control packs Touchstone ships. Enable the ones you are being audited against;
		Touchstone evaluates every enabled control on every scan.
	</p>

	<div class="mt-8">
		{#if loading}
			<div class="flex items-center gap-2 text-zinc-500">
				<Loader2 class="h-4 w-4 animate-spin" /> Loading…
			</div>
		{:else if frameworks.length === 0}
			<p class="text-sm text-zinc-500">No frameworks shipped with this build.</p>
		{:else}
			<ul class="space-y-3">
				{#each frameworks as f (f.code)}
					{@const isEnabled = enabledCodes.has(f.code)}
					<li>
						<a
							href={`/frameworks/${f.code}`}
							class="flex items-center justify-between rounded-md border border-zinc-800 bg-zinc-900/40 px-5 py-4 hover:border-zinc-700"
						>
							<div>
								<div class="flex items-center gap-2">
									<span class="text-sm font-semibold text-zinc-100">{f.name}</span>
									{#if f.version}
										<span class="text-xs text-zinc-500">v{f.version}</span>
									{/if}
								</div>
								<div class="mt-0.5 text-xs text-zinc-500">{f.code}</div>
							</div>
							{#if isEnabled}
								<span
									class="flex items-center gap-1 rounded bg-emerald-950/50 px-2 py-0.5 text-xs text-emerald-300"
								>
									<CheckCircle2 class="h-3.5 w-3.5" /> enabled
								</span>
							{:else}
								<span class="text-xs text-zinc-500">not enabled</span>
							{/if}
						</a>
					</li>
				{/each}
			</ul>
		{/if}
	</div>
</div>
