<script lang="ts">
	import { auth } from '$lib/stores/auth.svelte';
</script>

<svelte:head>
	<title>Dashboard · Touchstone GRC</title>
</svelte:head>

<div class="mx-auto max-w-4xl px-8 py-10">
	<h1 class="text-2xl font-semibold tracking-tight text-zinc-100">Dashboard</h1>
	<p class="mt-1 text-sm text-zinc-400">Signed in as {auth.me?.email}.</p>

	<div class="mt-8 grid gap-4 sm:grid-cols-2">
		<a
			href="/connectors"
			class="rounded-md border border-zinc-800 bg-zinc-900/40 p-5 hover:border-zinc-700"
		>
			<h2 class="text-sm font-semibold text-zinc-100">Connectors</h2>
			<p class="mt-1 text-xs text-zinc-500">
				Configure read-only integrations with the systems Touchstone audits.
			</p>
		</a>
		<a
			href="/frameworks"
			class="rounded-md border border-zinc-800 bg-zinc-900/40 p-5 hover:border-zinc-700"
		>
			<h2 class="text-sm font-semibold text-zinc-100">Frameworks</h2>
			<p class="mt-1 text-xs text-zinc-500">
				Enable the compliance frameworks your organization is being audited against.
			</p>
		</a>
		<a
			href="/scans"
			class="rounded-md border border-zinc-800 bg-zinc-900/40 p-5 hover:border-zinc-700"
		>
			<h2 class="text-sm font-semibold text-zinc-100">Scans</h2>
			<p class="mt-1 text-xs text-zinc-500">Trigger scans and review their status.</p>
		</a>
		<a
			href="/evidence"
			class="rounded-md border border-zinc-800 bg-zinc-900/40 p-5 hover:border-zinc-700"
		>
			<h2 class="text-sm font-semibold text-zinc-100">Evidence</h2>
			<p class="mt-1 text-xs text-zinc-500">
				Inspect the evidence each scan produced for every enabled control.
			</p>
		</a>
	</div>
</div>
