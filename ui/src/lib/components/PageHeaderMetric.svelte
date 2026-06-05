<script lang="ts">
	import type { Snippet } from 'svelte';

	interface Props {
		label: string;
		value: string | number;
		/** Optional tone for the value. */
		tone?: 'default' | 'warn' | 'danger' | 'success';
		children?: Snippet;
	}

	let { label, value, tone = 'default', children }: Props = $props();

	const toneClass: Record<NonNullable<Props['tone']>, string> = {
		default: 'text-zinc-100',
		warn: 'text-amber-300',
		danger: 'text-red-300',
		success: 'text-emerald-300'
	};
</script>

<div class="flex flex-col">
	<dt class="text-[0.65rem] font-medium uppercase tracking-[0.22em] text-zinc-500">
		{label}
	</dt>
	<dd class="mt-0.5 font-mono text-lg {toneClass[tone]}">
		{value}
	</dd>
	{#if children}
		<div class="mt-0.5 text-xs text-zinc-500">{@render children()}</div>
	{/if}
</div>
