<script lang="ts">
	import type { Snippet } from 'svelte';
	import type { Icon as LucideIcon } from 'lucide-svelte';

	interface Props {
		/** Lucide icon component rendered in the soft circle. Optional —
		 * a generic Inbox-like symbol if omitted. */
		icon?: typeof LucideIcon;
		/** Headline for the empty surface. */
		title: string;
		/** Single-paragraph explanation. Spell out what a row anchors
		 * (what auditor question it answers) rather than just "no
		 * data". This is the moment a new user is most curious. */
		body: string;
		/** Optional bulleted hint of what kind of rows live here. */
		samples?: string[];
		/** Optional CTA snippet — usually a single link to /<thing>/new. */
		cta?: Snippet;
	}

	let { icon: Icon, title, body, samples, cta }: Props = $props();
</script>

<div class="px-6 py-16 text-center">
	{#if Icon}
		<div
			class="mx-auto flex h-10 w-10 items-center justify-center rounded-full border border-zinc-800"
			style="background-color: var(--accent-muted);"
		>
			<Icon class="h-5 w-5" style="color: var(--accent);" />
		</div>
	{/if}
	<h3 class="{Icon ? 'mt-4' : ''} font-serif text-lg text-zinc-100">{title}</h3>
	<p class="mx-auto mt-2 max-w-md text-sm text-zinc-400">{body}</p>

	{#if samples && samples.length > 0}
		<ul class="mx-auto mt-4 inline-block space-y-1 text-left text-xs text-zinc-500">
			{#each samples as s (s)}
				<li class="flex items-start gap-2">
					<span
						class="mt-1.5 inline-block h-1 w-1 shrink-0 rounded-full"
						style="background-color: var(--accent);"
					></span>
					<span>{s}</span>
				</li>
			{/each}
		</ul>
	{/if}

	{#if cta}
		<div class="mt-5">{@render cta()}</div>
	{/if}
</div>
