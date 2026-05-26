<script lang="ts">
	import { goto } from '$app/navigation';
	import { createConnector } from '$lib/api/connectors';
	import { toasts } from '$lib/stores/toasts.svelte';
	import { Loader2 } from 'lucide-svelte';

	let name = $state('');
	let accountId = $state('');
	let regions = $state('us-east-1');
	let authMethod = $state<'role' | 'key'>('role');
	let roleArn = $state('');
	let externalId = $state('');
	let accessKeyId = $state('');
	let secretAccessKey = $state('');
	let scheduleCron = $state('');
	let submitting = $state(false);

	async function submit(e: SubmitEvent) {
		e.preventDefault();
		if (submitting) return;
		submitting = true;
		try {
			const config: Record<string, unknown> = {
				account_id: accountId.trim(),
				regions: regions
					.split(',')
					.map((r) => r.trim())
					.filter((r) => r.length > 0),
				auth_method: authMethod
			};
			if (authMethod === 'role') {
				config.role_arn = roleArn.trim();
				if (externalId.trim()) config.external_id = externalId.trim();
			} else {
				config.access_key_id = accessKeyId.trim();
				config.secret_access_key = secretAccessKey;
			}
			const created = await createConnector({
				kind: 'aws',
				name: name.trim(),
				config,
				schedule_cron: scheduleCron.trim() || null
			});
			toasts.success(`Created ${created.name}.`);
			await goto(`/connectors/${created.id}`);
		} catch (err) {
			toasts.error((err as Error).message);
		} finally {
			submitting = false;
		}
	}
</script>

<svelte:head>
	<title>New connector · Touchstone GRC</title>
</svelte:head>

<div class="mx-auto max-w-2xl px-8 py-10">
	<a href="/connectors" class="text-sm text-zinc-500 underline-offset-4 hover:underline"
		>← Connectors</a
	>
	<h1 class="mt-2 text-2xl font-semibold tracking-tight text-zinc-100">New AWS connector</h1>
	<p class="mt-1 text-sm text-zinc-400">
		Touchstone connects with read-only IAM credentials. Use role assumption when possible — the
		access-key option exists for environments that cannot grant a role.
	</p>

	<form onsubmit={submit} class="mt-8 space-y-5">
		<div>
			<label for="name" class="mb-1 block text-sm text-zinc-300">Name</label>
			<input
				id="name"
				type="text"
				required
				placeholder="Production AWS"
				bind:value={name}
				class="field-input"
			/>
		</div>

		<div>
			<label for="account_id" class="mb-1 block text-sm text-zinc-300">AWS account ID</label>
			<input
				id="account_id"
				type="text"
				required
				inputmode="numeric"
				pattern="[0-9]{'{'}12{'}'}"
				placeholder="123456789012"
				bind:value={accountId}
				class="field-input"
			/>
		</div>

		<div>
			<label for="regions" class="mb-1 block text-sm text-zinc-300">
				Regions <span class="text-xs text-zinc-500">(comma-separated)</span>
			</label>
			<input id="regions" type="text" required bind:value={regions} class="field-input" />
		</div>

		<fieldset class="space-y-3 rounded-md border border-zinc-800 p-4">
			<legend class="px-1 text-sm font-medium text-zinc-300">Authentication</legend>
			<label class="flex items-start gap-2">
				<input type="radio" name="auth_method" value="role" bind:group={authMethod} />
				<span>
					<span class="block text-sm text-zinc-100">Role assumption (recommended)</span>
					<span class="block text-xs text-zinc-500">
						Worker uses ambient credentials to <code>sts:AssumeRole</code> into your role.
					</span>
				</span>
			</label>
			<label class="flex items-start gap-2">
				<input type="radio" name="auth_method" value="key" bind:group={authMethod} />
				<span>
					<span class="block text-sm text-zinc-100">Access key + secret</span>
					<span class="block text-xs text-zinc-500">
						Long-lived IAM key. Encrypted at rest with TOUCHSTONE_SECRET_KEY.
					</span>
				</span>
			</label>
		</fieldset>

		{#if authMethod === 'role'}
			<div>
				<label for="role_arn" class="mb-1 block text-sm text-zinc-300">Role ARN</label>
				<input
					id="role_arn"
					type="text"
					required
					placeholder="arn:aws:iam::123456789012:role/TouchstoneReadOnly"
					bind:value={roleArn}
					class="field-input"
				/>
			</div>
			<div>
				<label for="external_id" class="mb-1 block text-sm text-zinc-300">
					External ID <span class="text-xs text-zinc-500">(optional)</span>
				</label>
				<input
					id="external_id"
					type="text"
					bind:value={externalId}
					class="field-input"
				/>
			</div>
		{:else}
			<div>
				<label for="access_key_id" class="mb-1 block text-sm text-zinc-300">Access key ID</label>
				<input
					id="access_key_id"
					type="text"
					required
					autocomplete="off"
					bind:value={accessKeyId}
					class="field-input"
				/>
			</div>
			<div>
				<label for="secret_access_key" class="mb-1 block text-sm text-zinc-300">Secret access key</label>
				<input
					id="secret_access_key"
					type="password"
					required
					autocomplete="off"
					bind:value={secretAccessKey}
					class="field-input"
				/>
			</div>
		{/if}

		<div>
			<label for="schedule_cron" class="mb-1 block text-sm text-zinc-300">
				Schedule <span class="text-xs text-zinc-500">(cron, optional — leave empty for on-demand)</span>
			</label>
			<input
				id="schedule_cron"
				type="text"
				placeholder="0 6 * * *"
				bind:value={scheduleCron}
				class="field-input"
			/>
		</div>

		<div class="flex items-center gap-3 pt-2">
			<button
				type="submit"
				disabled={submitting}
				class="flex items-center gap-2 rounded-md px-4 py-1.5 text-sm font-medium text-zinc-950 disabled:opacity-50"
				style="background-color: var(--accent);"
			>
				{#if submitting}<Loader2 class="h-4 w-4 animate-spin" />{/if}
				Create connector
			</button>
			<a href="/connectors" class="text-sm text-zinc-400 hover:text-zinc-200">Cancel</a>
		</div>
	</form>
</div>
