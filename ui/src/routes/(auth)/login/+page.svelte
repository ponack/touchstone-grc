<script lang="ts">
	import { goto } from '$app/navigation';
	import { page } from '$app/state';
	import { getAuthConfig, localLogin, type AuthConfig } from '$lib/api/auth';
	import { auth } from '$lib/stores/auth.svelte';
	import { toasts } from '$lib/stores/toasts.svelte';
	import { Loader2 } from 'lucide-svelte';

	let email = $state('');
	let password = $state('');
	let submitting = $state(false);
	let config = $state<AuthConfig | null>(null);
	let configError = $state<string | null>(null);

	$effect(() => {
		getAuthConfig()
			.then((c) => (config = c))
			.catch((e: Error) => (configError = e.message));
	});

	const nextPath = $derived(page.url.searchParams.get('next') ?? '/');

	async function submit(e: SubmitEvent) {
		e.preventDefault();
		if (submitting) return;
		submitting = true;
		try {
			await localLogin(email, password);
			await auth.refresh();
			toasts.success('Welcome.');
			await goto(nextPath);
		} catch (err) {
			toasts.error((err as Error).message);
		} finally {
			submitting = false;
		}
	}
</script>

<div class="rounded-md border border-zinc-800 bg-zinc-900/40 p-6">
	{#if configError}
		<p class="text-sm text-red-400">{configError}</p>
	{:else if !config}
		<div class="flex items-center justify-center py-6 text-zinc-500">
			<Loader2 class="h-5 w-5 animate-spin" />
		</div>
	{:else if !config.local && !config.oidc}
		<p class="text-sm text-red-400">No authentication methods are configured on this server.</p>
	{:else}
		{#if config.local}
			<form onsubmit={submit} class="space-y-4">
				<div>
					<label for="email" class="mb-1 block text-sm text-zinc-300">Email</label>
					<input
						id="email"
						type="email"
						required
						autocomplete="email"
						bind:value={email}
						class="field-input"
					/>
				</div>
				<div>
					<label for="password" class="mb-1 block text-sm text-zinc-300">Password</label>
					<input
						id="password"
						type="password"
						required
						autocomplete="current-password"
						bind:value={password}
						class="field-input"
					/>
				</div>
				<button
					type="submit"
					disabled={submitting}
					class="flex w-full items-center justify-center gap-2 rounded-md py-2 text-sm font-medium text-zinc-950 disabled:opacity-50"
					style="background-color: var(--accent);"
				>
					{#if submitting}<Loader2 class="h-4 w-4 animate-spin" />{/if}
					Sign in
				</button>
			</form>
		{/if}

		{#if config.oidc}
			{#if config.local}
				<div class="my-5 flex items-center gap-3 text-xs text-zinc-600">
					<div class="h-px flex-1 bg-zinc-800"></div>
					<span>or</span>
					<div class="h-px flex-1 bg-zinc-800"></div>
				</div>
			{/if}
			<a
				href="/auth/oidc/start"
				class="flex w-full items-center justify-center rounded-md border border-zinc-700 py-2 text-sm text-zinc-200 hover:border-zinc-600"
			>
				Sign in with SSO
			</a>
		{/if}
	{/if}
</div>
