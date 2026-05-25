<script lang="ts">
	import { ShieldCheck } from 'lucide-svelte';
</script>

<svelte:head>
	<title>Touchstone</title>
</svelte:head>

<main class="mx-auto max-w-2xl px-6 py-24">
	<div class="flex items-center gap-3">
		<ShieldCheck class="h-8 w-8" style="color: var(--accent)" />
		<h1 class="text-2xl font-semibold tracking-tight">Touchstone</h1>
	</div>

	<p class="mt-6 text-zinc-400">
		Self-hosted compliance evidence collector. Pre-alpha — scaffolding only.
	</p>

	<p class="mt-2 text-sm text-zinc-500">
		By <a
			href="https://www.forgedinfeatherstechnology.com"
			class="underline decoration-dotted underline-offset-4 hover:text-zinc-300"
			rel="noopener"
			style="--tw-text-opacity: 1"
		>Forged in Feathers Technology</a>.
	</p>

	<div class="mt-10 rounded-md border border-zinc-800 bg-zinc-900/40 p-4 text-sm text-zinc-400">
		<div class="font-medium text-zinc-200">Status</div>
		<ul class="mt-2 list-inside list-disc space-y-1">
			<li>Phase 0 — Foundation (in progress)</li>
			<li>Phase 1 — AWS connector + SOC 2 subset (planned)</li>
		</ul>
	</div>
</main>
