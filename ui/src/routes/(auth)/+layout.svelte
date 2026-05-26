<script lang="ts">
	let { children } = $props();
</script>

<div class="flex min-h-screen items-center justify-center px-4 py-12">
	<div class="w-full max-w-sm">
		<div class="mb-8 flex flex-col items-center">
			<img
				src="/logo-primary-dark.png"
				alt="Touchstone GRC"
				class="h-16 w-16"
				width="64"
				height="64"
			/>
			<h1 class="mt-3 text-lg font-semibold tracking-tight text-zinc-100">Touchstone GRC</h1>
		</div>
		{@render children?.()}
	</div>
</div>
