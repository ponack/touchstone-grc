<script lang="ts">
	import { toasts } from '$lib/stores/toasts.svelte';
	import { CheckCircle2, AlertCircle, Info, X } from 'lucide-svelte';

	const iconFor = {
		success: CheckCircle2,
		error: AlertCircle,
		info: Info
	};

	const tone = {
		success: 'border-emerald-700 bg-emerald-950/60 text-emerald-100',
		error: 'border-red-700 bg-red-950/60 text-red-100',
		info: 'border-zinc-700 bg-zinc-900/80 text-zinc-100'
	};
</script>

<div class="pointer-events-none fixed right-4 bottom-4 z-50 flex w-80 flex-col gap-2">
	{#each toasts.all as t (t.id)}
		{@const Icon = iconFor[t.kind]}
		<div
			class="pointer-events-auto flex items-start gap-2 rounded-md border px-3 py-2 text-sm shadow-lg {tone[
				t.kind
			]}"
			role="status"
		>
			<Icon class="mt-0.5 h-4 w-4 shrink-0" />
			<span class="flex-1">{t.message}</span>
			<button
				type="button"
				class="rounded p-0.5 opacity-70 hover:opacity-100"
				aria-label="Dismiss"
				onclick={() => toasts.dismiss(t.id)}
			>
				<X class="h-3.5 w-3.5" />
			</button>
		</div>
	{/each}
</div>
