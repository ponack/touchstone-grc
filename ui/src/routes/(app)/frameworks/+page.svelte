<script lang="ts">
	import {
		listFrameworks,
		listOrgFrameworks,
		type Framework,
		type OrgFramework
	} from '$lib/api/frameworks';
	import { toasts } from '$lib/stores/toasts.svelte';
	import { Loader2 } from 'lucide-svelte';
	import Pill from '$lib/components/Pill.svelte';
	import PageHeader from '$lib/components/PageHeader.svelte';
	import PageHeaderMetric from '$lib/components/PageHeaderMetric.svelte';

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

	const enabledCount = $derived(enabled.length);
	const totalCount = $derived(frameworks.length);
</script>

<svelte:head>
	<title>Frameworks · Touchstone GRC</title>
</svelte:head>

<div class="mx-auto max-w-5xl px-8 py-10">
	<PageHeader
		kicker="Evidence pipeline"
		title="Frameworks"
		subtitle="Compliance control packs Touchstone ships. Enable the ones you are being audited against; Touchstone evaluates every enabled control on every scan."
	>
		{#snippet metrics()}
			<dl class="grid grid-cols-2 gap-8 sm:max-w-[14rem]">
				<PageHeaderMetric label="Enabled" value={enabledCount} tone="success" />
				<PageHeaderMetric label="Shipped" value={totalCount} />
			</dl>
		{/snippet}
	</PageHeader>

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
								<Pill kind="success">enabled</Pill>
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
