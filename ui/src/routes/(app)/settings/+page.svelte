<script lang="ts">
	import { goto } from '$app/navigation';
	import {
		getVersion,
		setUpdateCheckFrequency,
		runUpdateCheck,
		type VersionStatus,
		type UpdateCheckFrequency
	} from '$lib/api/system';
	import { auth } from '$lib/stores/auth.svelte';
	import { toasts } from '$lib/stores/toasts.svelte';
	import { Loader2, ExternalLink, RefreshCw } from 'lucide-svelte';

	let status = $state<VersionStatus | null>(null);
	let loading = $state(true);
	let savingFreq = $state(false);
	let checking = $state(false);

	$effect(() => {
		(async () => {
			// Settings is admin-only. Non-admins land elsewhere rather
			// than seeing a half-populated page (the backend would 403
			// the update-check endpoints anyway).
			if (auth.me && !auth.me.is_admin) {
				await goto('/');
				return;
			}
			try {
				status = await getVersion();
			} catch (e) {
				toasts.error((e as Error).message);
			} finally {
				loading = false;
			}
		})();
	});

	async function handleFrequencyChange(next: UpdateCheckFrequency) {
		if (!status || status.update_check_frequency === next) return;
		savingFreq = true;
		try {
			await setUpdateCheckFrequency(next);
			status = await getVersion();
			toasts.success(`Update check frequency set to ${next}.`);
		} catch (e) {
			toasts.error((e as Error).message);
		} finally {
			savingFreq = false;
		}
	}

	async function handleCheckNow() {
		checking = true;
		try {
			await runUpdateCheck();
			status = await getVersion();
			toasts.success('Checked GitHub for the latest release.');
		} catch (e) {
			toasts.error((e as Error).message);
		} finally {
			checking = false;
		}
	}

	function formatTimestamp(iso: string | null): string {
		if (!iso) return 'never';
		try {
			return new Date(iso).toLocaleString();
		} catch {
			return iso;
		}
	}

	const frequencyOptions: { value: UpdateCheckFrequency; label: string; blurb: string }[] = [
		{ value: 'daily', label: 'Daily', blurb: 'Check every 24 hours.' },
		{ value: 'weekly', label: 'Weekly', blurb: 'Check every 7 days (default).' },
		{ value: 'monthly', label: 'Monthly', blurb: 'Check every 30 days.' },
		{ value: 'off', label: 'Off', blurb: 'Disable automatic checks. You can still check manually.' }
	];
</script>

<svelte:head>
	<title>Settings · Touchstone GRC</title>
</svelte:head>

<div class="mx-auto max-w-3xl px-8 py-10">
	<h1 class="text-2xl font-semibold tracking-tight text-zinc-100">Settings</h1>
	<p class="mt-1 text-sm text-zinc-500">Instance-wide configuration. Admin only.</p>

	{#if loading}
		<div class="mt-10 flex items-center gap-2 text-zinc-500">
			<Loader2 class="h-4 w-4 animate-spin" /> Loading…
		</div>
	{:else if status}
		<section class="mt-8 space-y-3 rounded-md border border-zinc-800 p-5">
			<h2 class="text-sm font-medium text-zinc-200">Version</h2>

			<dl class="grid grid-cols-[160px_1fr] gap-y-3 text-sm">
				<dt class="text-zinc-500">Running</dt>
				<dd class="font-mono text-zinc-100">{status.current}</dd>

				<dt class="text-zinc-500">Latest available</dt>
				<dd class="text-zinc-100">
					{#if status.latest && status.latest_url}
						<a
							href={status.latest_url}
							target="_blank"
							rel="noopener"
							class="inline-flex items-center gap-1.5 font-mono underline-offset-4 hover:underline"
						>
							{status.latest}
							<ExternalLink class="h-3.5 w-3.5" />
						</a>
						{#if status.latest_published_at}
							<span class="ml-2 text-xs text-zinc-500">
								published {formatTimestamp(status.latest_published_at)}
							</span>
						{/if}
					{:else}
						<span class="text-zinc-500">unknown — no successful check yet</span>
					{/if}
				</dd>

				<dt class="text-zinc-500">Last checked</dt>
				<dd class="text-zinc-100">{formatTimestamp(status.last_checked_at)}</dd>
			</dl>

			{#if status.update_available}
				<div
					class="mt-2 rounded-md border border-amber-700/50 bg-amber-900/20 px-3 py-2 text-sm text-amber-200"
				>
					An update is available: <span class="font-mono">{status.latest}</span>.
					Review the release notes before upgrading.
				</div>
			{:else if status.current === 'dev'}
				<div class="mt-2 rounded-md border border-zinc-700 bg-zinc-900 px-3 py-2 text-xs text-zinc-400">
					This build reports <span class="font-mono">dev</span>. Update notifications are
					suppressed for source builds. Released container images carry their tag.
				</div>
			{/if}

			<div class="pt-2">
				<button
					type="button"
					onclick={handleCheckNow}
					disabled={checking}
					class="inline-flex items-center gap-2 rounded-md border border-zinc-700 px-3 py-1.5 text-sm text-zinc-200 hover:bg-zinc-900 disabled:opacity-50"
				>
					{#if checking}
						<Loader2 class="h-4 w-4 animate-spin" />
					{:else}
						<RefreshCw class="h-4 w-4" />
					{/if}
					Check now
				</button>
			</div>
		</section>

		<section class="mt-6 space-y-3 rounded-md border border-zinc-800 p-5">
			<h2 class="text-sm font-medium text-zinc-200">Update check frequency</h2>
			<p class="text-xs text-zinc-500">
				How often the API process polls GitHub for new Touchstone releases.
			</p>

			<fieldset class="space-y-2 pt-1" disabled={savingFreq}>
				{#each frequencyOptions as opt (opt.value)}
					<label class="flex items-start gap-2">
						<input
							type="radio"
							name="frequency"
							value={opt.value}
							checked={status.update_check_frequency === opt.value}
							onchange={() => handleFrequencyChange(opt.value)}
							class="mt-1"
						/>
						<span>
							<span class="block text-sm text-zinc-100">{opt.label}</span>
							<span class="block text-xs text-zinc-500">{opt.blurb}</span>
						</span>
					</label>
				{/each}
			</fieldset>
		</section>
	{:else}
		<div class="mt-10 text-zinc-500">Failed to load settings.</div>
	{/if}
</div>
