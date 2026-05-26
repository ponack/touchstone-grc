<script lang="ts">
	import { goto } from '$app/navigation';
	import { listOrgFrameworks, getFramework, type ControlSummary } from '$lib/api/frameworks';
	import { grantException } from '$lib/api/exceptions';
	import { toasts } from '$lib/stores/toasts.svelte';
	import { Loader2 } from 'lucide-svelte';

	interface ControlOption extends ControlSummary {
		framework_code: string;
		framework_name: string;
	}

	let controls = $state<ControlOption[]>([]);
	let loading = $state(true);
	let controlId = $state('');
	let reason = $state('');
	let resourceKey = $state('');
	let expiresAt = $state('');
	let submitting = $state(false);

	$effect(() => {
		(async () => {
			try {
				const orgFws = await listOrgFrameworks();
				if (orgFws.length === 0) {
					loading = false;
					return;
				}
				const detailed = await Promise.all(orgFws.map((f) => getFramework(f.code)));
				const opts: ControlOption[] = [];
				for (const fw of detailed) {
					for (const c of fw.controls ?? []) {
						opts.push({ ...c, framework_code: fw.code, framework_name: fw.name });
					}
				}
				controls = opts;
				if (opts.length > 0) controlId = opts[0].id;
			} catch (e) {
				toasts.error((e as Error).message);
			} finally {
				loading = false;
			}
		})();
	});

	async function submit(e: SubmitEvent) {
		e.preventDefault();
		if (submitting || !controlId || !reason.trim()) return;
		submitting = true;
		try {
			await grantException({
				control_id: controlId,
				reason: reason.trim(),
				resource_key: resourceKey.trim() || undefined,
				expires_at: expiresAt ? new Date(expiresAt).toISOString() : null
			});
			toasts.success('Exception granted.');
			await goto('/exceptions');
		} catch (err) {
			toasts.error((err as Error).message);
			submitting = false;
		}
	}
</script>

<svelte:head>
	<title>Grant exception · Touchstone GRC</title>
</svelte:head>

<div class="mx-auto max-w-xl px-8 py-10">
	<a href="/exceptions" class="text-sm text-zinc-500 underline-offset-4 hover:underline">
		← Exceptions
	</a>
	<h1 class="mt-2 text-2xl font-semibold tracking-tight text-zinc-100">Grant exception</h1>
	<p class="mt-1 text-sm text-zinc-400">
		Suppress a failing control with an explanation. The failed evidence row is preserved for audit;
		future scans of this control are marked accepted until the exception expires or is revoked.
	</p>

	{#if loading}
		<div class="mt-8 flex items-center gap-2 text-zinc-500">
			<Loader2 class="h-4 w-4 animate-spin" /> Loading controls…
		</div>
	{:else if controls.length === 0}
		<div class="mt-8 rounded-md border border-zinc-800 bg-zinc-900/40 p-5 text-sm">
			<p class="text-zinc-300">No frameworks enabled.</p>
			<p class="mt-2 text-zinc-500">
				<a href="/frameworks" class="underline decoration-dotted underline-offset-4">
					Enable a framework first →
				</a>
			</p>
		</div>
	{:else}
		<form onsubmit={submit} class="mt-8 space-y-5">
			<div>
				<label for="control" class="mb-1 block text-sm text-zinc-300">Control</label>
				<select id="control" bind:value={controlId} class="field-input">
					{#each controls as c (c.id)}
						<option value={c.id}>{c.framework_code} / {c.code} — {c.title}</option>
					{/each}
				</select>
			</div>

			<div>
				<label for="reason" class="mb-1 block text-sm text-zinc-300">Reason</label>
				<textarea
					id="reason"
					required
					rows="3"
					placeholder="e.g. Service account access keys are managed by AWS SSO + age-rotated by an external pipeline; this control's check is not applicable."
					bind:value={reason}
					class="field-input"
				></textarea>
			</div>

			<div>
				<label for="resource_key" class="mb-1 block text-sm text-zinc-300">
					Resource key <span class="text-xs text-zinc-500">(optional — leave blank to suppress every failure for this control)</span>
				</label>
				<input
					id="resource_key"
					type="text"
					placeholder="aws:account:123456789012:user/sa-pipeline"
					bind:value={resourceKey}
					class="field-input"
				/>
			</div>

			<div>
				<label for="expires_at" class="mb-1 block text-sm text-zinc-300">
					Expires <span class="text-xs text-zinc-500">(optional — empty = permanent)</span>
				</label>
				<input id="expires_at" type="date" bind:value={expiresAt} class="field-input" />
			</div>

			<div class="flex items-center gap-3 pt-2">
				<button
					type="submit"
					disabled={submitting}
					class="flex items-center gap-2 rounded-md px-4 py-1.5 text-sm font-medium text-zinc-950 disabled:opacity-50"
					style="background-color: var(--accent);"
				>
					{#if submitting}<Loader2 class="h-4 w-4 animate-spin" />{/if}
					Grant exception
				</button>
				<a href="/exceptions" class="text-sm text-zinc-400 hover:text-zinc-200">Cancel</a>
			</div>
		</form>
	{/if}
</div>
