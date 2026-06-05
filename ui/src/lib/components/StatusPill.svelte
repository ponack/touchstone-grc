<script lang="ts">
	import type { ScanStatus } from '$lib/api/scans';
	import type { EvidenceStatus } from '$lib/api/evidence';

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

	const dot: Record<Kind, string> = {
		queued: 'bg-zinc-400',
		running: 'bg-blue-400',
		succeeded: 'bg-emerald-400',
		failed: 'bg-red-400',
		canceled: 'bg-zinc-500',
		pass: 'bg-emerald-400',
		fail: 'bg-red-400',
		partial: 'bg-amber-400',
		not_applicable: 'bg-zinc-500',
		error: 'bg-red-400'
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

	const isInFlight = $derived(status === 'queued' || status === 'running');
</script>

<span
	class="inline-flex items-center gap-1.5 rounded px-1.5 py-0.5 text-xs font-medium {tone[status]}"
>
	<span
		class="h-1.5 w-1.5 shrink-0 rounded-full {dot[status]} {isInFlight ? 'pulse-dot' : ''}"
	></span>
	{label[status]}
</span>
