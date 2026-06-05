<script lang="ts">
	import type { Snippet } from 'svelte';

	export type PillKind = 'success' | 'warn' | 'danger' | 'neutral' | 'muted' | 'info';

	interface Props {
		kind?: PillKind;
		pulse?: boolean;
		uppercase?: boolean;
		children?: Snippet;
	}

	let { kind = 'neutral', pulse = false, uppercase = false, children }: Props = $props();

	// Background + label colour pairing per kind. Kept in sync with
	// the inline patterns these pills replace; the dot picks up the
	// brighter accent for that kind so the affordance is legible
	// against the soft 950/50 background.
	const tone: Record<PillKind, string> = {
		success: 'bg-emerald-950/50 text-emerald-300',
		warn: 'bg-amber-950/50 text-amber-300',
		danger: 'bg-red-950/50 text-red-300',
		neutral: 'bg-zinc-800 text-zinc-300',
		muted: 'bg-zinc-900 text-zinc-500',
		info: 'bg-sky-950/50 text-sky-300'
	};

	const dot: Record<PillKind, string> = {
		success: 'bg-emerald-400',
		warn: 'bg-amber-400',
		danger: 'bg-red-400',
		neutral: 'bg-zinc-400',
		muted: 'bg-zinc-600',
		info: 'bg-sky-400'
	};
</script>

<span
	class="inline-flex items-center gap-1.5 rounded px-1.5 py-0.5 text-xs font-medium {tone[kind]} {uppercase
		? 'uppercase tracking-wide'
		: ''}"
>
	<span class="h-1.5 w-1.5 shrink-0 rounded-full {dot[kind]} {pulse ? 'pulse-dot' : ''}"></span>
	{@render children?.()}
</span>
