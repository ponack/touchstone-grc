<script lang="ts">
	import { page } from '$app/state';
	import {
		disableFramework,
		enableFramework,
		getFramework,
		listOrgFrameworks,
		type Framework
	} from '$lib/api/frameworks';
	import { toasts } from '$lib/stores/toasts.svelte';
	import { Loader2 } from 'lucide-svelte';

	let framework = $state<Framework | null>(null);
	let enabled = $state(false);
	let loading = $state(true);
	let toggling = $state(false);

	const code = $derived(page.params.code!);

	const severityClass: Record<string, string> = {
		low: 'bg-zinc-800 text-zinc-300',
		medium: 'bg-amber-950/40 text-amber-300',
		high: 'bg-orange-950/40 text-orange-300',
		critical: 'bg-red-950/50 text-red-300'
	};

	$effect(() => {
		(async () => {
			try {
				const [fw, orgFws] = await Promise.all([getFramework(code), listOrgFrameworks()]);
				framework = fw;
				enabled = orgFws.some((o) => o.code === code);
			} catch (e) {
				toasts.error((e as Error).message);
			} finally {
				loading = false;
			}
		})();
	});

	async function toggle() {
		if (toggling) return;
		toggling = true;
		try {
			if (enabled) {
				await disableFramework(code);
				enabled = false;
				toasts.info(`${framework?.name} disabled.`);
			} else {
				await enableFramework(code);
				enabled = true;
				toasts.success(`${framework?.name} enabled.`);
			}
		} catch (e) {
			toasts.error((e as Error).message);
		} finally {
			toggling = false;
		}
	}
</script>

<svelte:head>
	<title>{framework?.name ?? 'Framework'} · Touchstone GRC</title>
</svelte:head>

<div class="mx-auto max-w-4xl px-8 py-10">
	<a href="/frameworks" class="text-sm text-zinc-500 underline-offset-4 hover:underline"
		>← Frameworks</a
	>

	{#if loading}
		<div class="mt-6 flex items-center gap-2 text-zinc-500">
			<Loader2 class="h-4 w-4 animate-spin" /> Loading…
		</div>
	{:else if !framework}
		<p class="mt-6 text-sm text-red-400">Framework not found.</p>
	{:else}
		<div class="mt-2 flex items-start justify-between">
			<div>
				<h1 class="text-2xl font-semibold tracking-tight text-zinc-100">{framework.name}</h1>
				<p class="mt-1 text-xs text-zinc-500">
					{framework.code}{framework.version ? ` · v${framework.version}` : ''}
				</p>
			</div>
			<button
				type="button"
				onclick={toggle}
				disabled={toggling}
				class="rounded-md px-3 py-1.5 text-sm font-medium disabled:opacity-50 {enabled
					? 'border border-zinc-700 text-zinc-200 hover:bg-zinc-800/50'
					: 'text-zinc-950'}"
				style={enabled ? '' : 'background-color: var(--accent);'}
			>
				{toggling ? '…' : enabled ? 'Disable for this org' : 'Enable for this org'}
			</button>
		</div>

		<h2 class="mt-10 text-lg font-semibold text-zinc-100">
			Controls ({framework.controls?.length ?? 0})
		</h2>

		<div class="mt-3 overflow-hidden rounded-md border border-zinc-800">
			<table class="w-full text-sm">
				<thead class="bg-zinc-900/60 text-left text-xs uppercase tracking-wide text-zinc-500">
					<tr>
						<th class="px-4 py-2 font-medium">Code</th>
						<th class="px-4 py-2 font-medium">Title</th>
						<th class="px-4 py-2 font-medium">Severity</th>
					</tr>
				</thead>
				<tbody class="divide-y divide-zinc-800">
					{#each framework.controls ?? [] as c (c.id)}
						<tr class="hover:bg-zinc-900/40">
							<td class="px-4 py-2.5 font-mono text-xs text-zinc-300">{c.code}</td>
							<td class="px-4 py-2.5 text-zinc-200">
								{c.title}
								{#if c.description}
									<div class="mt-1 text-xs text-zinc-500">{c.description}</div>
								{/if}
							</td>
							<td class="px-4 py-2.5">
								<span class="rounded px-1.5 py-0.5 text-xs {severityClass[c.severity]}"
									>{c.severity}</span
								>
							</td>
						</tr>
					{/each}
				</tbody>
			</table>
		</div>
	{/if}
</div>
