<script lang="ts">
	import type { ScanStatus } from '$lib/api/scans';
	import type { EvidenceStatus } from '$lib/api/evidence';
	import { Loader2 } from 'lucide-svelte';

	type Kind = ScanStatus | EvidenceStatus;

	let { status }: { status: Kind } = $props();

	const tone: Record<Kind, string> = {
		queued: 'bg-zinc-800 text-zinc-300',
		running: 'bg-blue-950/60 text-blue-200',
		succeeded: 'bg-emerald-950/50 text-emerald-300',
		failed: 'bg-red-950/50 text-red-300',
		canceled: 'bg-zinc-800 text-zinc-400',
		pass: 'bg-emerald-950/50 text-emerald-300',
		fail: 'bg-red-950/50 text-red-300',
		partial: 'bg-amber-950/50 text-amber-300',
		not_applicable: 'bg-zinc-800 text-zinc-400',
		error: 'bg-red-950/50 text-red-300'
	};

	const label: Record<Kind, string> = {
		queued: 'queued',
		running: 'running',
		succeeded: 'succeeded',
		failed: 'failed',
		canceled: 'canceled',
		pass: 'pass',
		fail: 'fail',
		partial: 'partial',
		not_applicable: 'n/a',
		error: 'error'
	};
</script>

<span class="inline-flex items-center gap-1 rounded px-1.5 py-0.5 text-xs font-medium {tone[status]}">
	{#if status === 'running'}
		<Loader2 class="h-3 w-3 animate-spin" />
	{/if}
	{label[status]}
</span>
