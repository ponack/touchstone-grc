<script lang="ts">
	import { goto } from '$app/navigation';
	import { auth } from '$lib/stores/auth.svelte';
	import { toasts } from '$lib/stores/toasts.svelte';
	import {
		listTrustBlocks,
		moveTrustBlock,
		type TrustBlock
	} from '$lib/api/trust-blocks';
	import { Plus, FileText, ChevronUp, ChevronDown } from 'lucide-svelte';
	import PageHeader from '$lib/components/PageHeader.svelte';
	import PageHeaderMetric from '$lib/components/PageHeaderMetric.svelte';
	import Pill from '$lib/components/Pill.svelte';
	import SkeletonRows from '$lib/components/SkeletonRows.svelte';
	import EmptyState from '$lib/components/EmptyState.svelte';

	let blocks = $state<TrustBlock[]>([]);
	let loading = $state(true);
	let movingID = $state<string | null>(null);

	async function refresh() {
		try {
			blocks = await listTrustBlocks();
		} catch (e) {
			toasts.error((e as Error).message);
		}
	}

	$effect(() => {
		(async () => {
			if (auth.me && !auth.me.is_admin) {
				await goto('/');
				return;
			}
			loading = true;
			await refresh();
			loading = false;
		})();
	});

	const publishedCount = $derived(blocks.filter((b) => b.is_public).length);

	async function handleMove(id: string, direction: 'up' | 'down') {
		if (movingID) return;
		movingID = id;
		try {
			await moveTrustBlock(id, direction);
			await refresh();
		} catch (e) {
			toasts.error((e as Error).message);
		} finally {
			movingID = null;
		}
	}

	function fmtUpdated(iso: string): string {
		return new Date(iso).toLocaleDateString();
	}

	function snippet(md: string): string {
		const clean = md.replace(/[#>*`_\-]/g, '').trim();
		return clean.length > 120 ? clean.slice(0, 117).trimEnd() + '…' : clean;
	}
</script>

<svelte:head>
	<title>Trust blocks · Settings · Touchstone GRC</title>
</svelte:head>

<div class="mx-auto max-w-5xl px-8 py-10">
	<a href="/settings" class="text-sm text-zinc-500 underline-offset-4 hover:underline">
		← Settings
	</a>

	<div class="mt-2">
		<PageHeader
			kicker="Phase 8 · Trust Center"
			title="Custom blocks"
			subtitle="Named Markdown sections you can drop onto the public Trust Center. Escape hatch for org-specific copy (data handling, SLA / uptime, incident policy) that doesn't fit the fixed sections."
		>
			{#snippet actions()}
				<a
					href="/settings/trust-blocks/new"
					class="flex items-center gap-1.5 rounded-md px-3 py-1.5 text-sm font-medium text-zinc-950"
					style="background-color: var(--accent);"
				>
					<Plus class="h-4 w-4" />
					Add block
				</a>
			{/snippet}
			{#snippet metrics()}
				<dl class="grid grid-cols-2 gap-8 sm:max-w-xs">
					<PageHeaderMetric label="Total" value={blocks.length} />
					<PageHeaderMetric label="Published" value={publishedCount} tone="success" />
				</dl>
			{/snippet}
		</PageHeader>
	</div>

	<div class="mt-6 overflow-hidden rounded-md border border-zinc-800">
		{#if loading}
			<SkeletonRows count={4} columns={['w-40', 'w-96', 'w-20', 'w-24']} />
		{:else if blocks.length === 0}
			<EmptyState
				icon={FileText}
				title="No custom blocks yet"
				body="Write anything you'd tell a procurement team but don't want to hand-craft an email for. Blocks render as Markdown on the public page."
				samples={[
					'"Data handling" — where customer data lives, encryption at rest / in transit, retention windows',
					'"SLA / uptime" — historical availability + link to your status page',
					`"Incident response" — who's on call, response-time SLOs`,
					'"Sub-processor addendum" — additional context for the subprocessor list above'
				]}
			>
				{#snippet cta()}
					<a
						href="/settings/trust-blocks/new"
						class="inline-flex items-center gap-1.5 rounded-md px-3 py-1.5 text-sm font-medium text-zinc-950"
						style="background-color: var(--accent);"
					>
						<Plus class="h-4 w-4" /> Add the first block
					</a>
				{/snippet}
			</EmptyState>
		{:else}
			<ul class="divide-y divide-zinc-800">
				{#each blocks as b, idx (b.id)}
					<li class="flex items-start gap-4 px-4 py-3">
						<div class="flex flex-col gap-1">
							<button
								type="button"
								onclick={() => handleMove(b.id, 'up')}
								disabled={idx === 0 || movingID !== null}
								class="rounded p-1 text-zinc-500 hover:bg-zinc-900 hover:text-zinc-200 disabled:opacity-30"
								title="Move up"
								aria-label="Move up"
							>
								<ChevronUp class="h-4 w-4" />
							</button>
							<button
								type="button"
								onclick={() => handleMove(b.id, 'down')}
								disabled={idx === blocks.length - 1 || movingID !== null}
								class="rounded p-1 text-zinc-500 hover:bg-zinc-900 hover:text-zinc-200 disabled:opacity-30"
								title="Move down"
								aria-label="Move down"
							>
								<ChevronDown class="h-4 w-4" />
							</button>
						</div>
						<div class="min-w-0 flex-1">
							<a
								href="/settings/trust-blocks/{b.id}"
								class="text-zinc-100 underline-offset-4 hover:underline"
							>
								<span class="font-serif text-base">{b.heading}</span>
							</a>
							<p class="mt-1 line-clamp-2 text-xs text-zinc-500">{snippet(b.body_markdown)}</p>
							<p class="mt-1 text-[0.65rem] uppercase tracking-wide text-zinc-600">
								Updated {fmtUpdated(b.updated_at)} · position {b.position}
							</p>
						</div>
						<div class="shrink-0">
							{#if b.is_public}
								<Pill kind="success">published</Pill>
							{:else}
								<Pill kind="muted">draft</Pill>
							{/if}
						</div>
					</li>
				{/each}
			</ul>
		{/if}
	</div>
</div>
