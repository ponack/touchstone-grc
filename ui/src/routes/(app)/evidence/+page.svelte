<svelte:head>
	<title>Evidence · Touchstone GRC</title>
</svelte:head>

<div class="mx-auto max-w-3xl px-8 py-10">
	<h1 class="text-2xl font-semibold tracking-tight text-zinc-100">Evidence</h1>
	<p class="mt-2 text-sm text-zinc-400">
		Every scan produces one evidence row per enabled control. Evidence is browsed in the context of
		its scan.
	</p>

	<div class="mt-8 rounded-md border border-zinc-800 bg-zinc-900/40 p-5 text-sm">
		<p class="text-zinc-300">
			Open <a href="/scans" class="underline decoration-dotted underline-offset-4">a recent scan</a>
			to inspect the evidence it produced. Each evidence item is independently linkable for sharing with
			auditors.
		</p>
	</div>

	<p class="mt-6 text-xs text-zinc-500">
		Cross-scan views (latest evidence per control, currently-failing controls) ship in a follow-up
		PR.
	</p>
</div>
