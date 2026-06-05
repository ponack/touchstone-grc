<script lang="ts">
	import type {
		Asset,
		AssetClassification,
		AssetCriticality,
		AssetEnvironment,
		AssetStatus,
		AssetType
	} from '$lib/api/assets';
	import type { Person } from '$lib/api/personnel';
	import { Loader2 } from 'lucide-svelte';

	interface Props {
		mode: 'create' | 'edit';
		initial?: Asset;
		owners: Person[];
		submitting: boolean;
		onSubmit: (values: {
			name: string;
			asset_type: AssetType;
			classification: AssetClassification | '' | 'none';
			environment: AssetEnvironment;
			criticality: AssetCriticality;
			status: AssetStatus;
			owner_id: string | null;
			description: string;
			external_ref: string;
			tags: string[];
			notes: string;
		}) => void | Promise<void>;
		onCancel: () => void;
	}

	let { mode, initial, owners, submitting, onSubmit, onCancel }: Props = $props();

	// svelte-ignore state_referenced_locally
	let name = $state(initial?.name ?? '');
	// svelte-ignore state_referenced_locally
	let assetType = $state<AssetType>(initial?.asset_type ?? 'application');
	// svelte-ignore state_referenced_locally
	let classification = $state<AssetClassification | ''>(
		(initial?.classification as AssetClassification | null | undefined) ?? ''
	);
	// svelte-ignore state_referenced_locally
	let environment = $state<AssetEnvironment>(initial?.environment ?? 'production');
	// svelte-ignore state_referenced_locally
	let criticality = $state<AssetCriticality>(initial?.criticality ?? 'medium');
	// svelte-ignore state_referenced_locally
	let status = $state<AssetStatus>(initial?.status ?? 'active');
	// svelte-ignore state_referenced_locally
	let ownerId = $state(initial?.owner_id ?? '');
	// svelte-ignore state_referenced_locally
	let description = $state(initial?.description ?? '');
	// svelte-ignore state_referenced_locally
	let externalRef = $state(initial?.external_ref ?? '');
	// svelte-ignore state_referenced_locally
	let tagsRaw = $state((initial?.tags ?? []).join(', '));
	// svelte-ignore state_referenced_locally
	let notes = $state(initial?.notes ?? '');

	async function handle(e: SubmitEvent) {
		e.preventDefault();
		if (submitting) return;
		const tags = tagsRaw
			.split(',')
			.map((t) => t.trim())
			.filter((t) => t.length > 0);
		// "none" sentinel only matters on edit when the user wants to clear
		// a previously set classification. On create the empty string is
		// just "not set" and the backend stores NULL.
		let classOut: AssetClassification | '' | 'none' = classification;
		if (mode === 'edit' && initial?.classification && !classification) {
			classOut = 'none';
		}
		await onSubmit({
			name: name.trim(),
			asset_type: assetType,
			classification: classOut,
			environment,
			criticality,
			status,
			owner_id: ownerId || null,
			description: description.trim(),
			external_ref: externalRef.trim(),
			tags,
			notes: notes.trim()
		});
	}
</script>

<form onsubmit={handle} class="space-y-5">
	<div class="grid grid-cols-1 gap-5 sm:grid-cols-2">
		<div>
			<label for="name" class="mb-1 block text-sm text-zinc-300">Name</label>
			<input
				id="name"
				type="text"
				required
				bind:value={name}
				class="field-input"
				placeholder="prod-api"
			/>
		</div>
		<div>
			<label for="asset_type" class="mb-1 block text-sm text-zinc-300">Type</label>
			<select id="asset_type" bind:value={assetType} class="field-input">
				<option value="application">Application</option>
				<option value="service">Service</option>
				<option value="database">Database</option>
				<option value="repository">Repository</option>
				<option value="data_store">Data store</option>
				<option value="cloud_account">Cloud account</option>
				<option value="infrastructure">Infrastructure</option>
				<option value="device">Device</option>
				<option value="other">Other</option>
			</select>
		</div>
	</div>

	<div class="grid grid-cols-1 gap-5 sm:grid-cols-3">
		<div>
			<label for="environment" class="mb-1 block text-sm text-zinc-300">Environment</label>
			<select id="environment" bind:value={environment} class="field-input">
				<option value="production">Production</option>
				<option value="staging">Staging</option>
				<option value="development">Development</option>
				<option value="other">Other</option>
			</select>
		</div>
		<div>
			<label for="criticality" class="mb-1 block text-sm text-zinc-300">Criticality</label>
			<select id="criticality" bind:value={criticality} class="field-input">
				<option value="low">Low</option>
				<option value="medium">Medium</option>
				<option value="high">High</option>
				<option value="critical">Critical</option>
			</select>
		</div>
		<div>
			<label for="status" class="mb-1 block text-sm text-zinc-300">Status</label>
			<select id="status" bind:value={status} class="field-input">
				<option value="active">Active</option>
				<option value="planned">Planned</option>
				<option value="decommissioned">Decommissioned</option>
			</select>
		</div>
	</div>

	<div class="grid grid-cols-1 gap-5 sm:grid-cols-2">
		<div>
			<label for="classification" class="mb-1 block text-sm text-zinc-300">
				Classification <span class="text-xs text-zinc-500">(optional)</span>
			</label>
			<select id="classification" bind:value={classification} class="field-input">
				<option value="">— not set —</option>
				<option value="public">Public</option>
				<option value="internal">Internal</option>
				<option value="confidential">Confidential</option>
				<option value="restricted">Restricted</option>
			</select>
		</div>
		<div>
			<label for="owner" class="mb-1 block text-sm text-zinc-300">
				Owner <span class="text-xs text-zinc-500">(personnel record)</span>
			</label>
			<select id="owner" bind:value={ownerId} class="field-input">
				<option value="">— none —</option>
				{#each owners as p (p.id)}
					<option value={p.id}>{p.full_name} · {p.role}</option>
				{/each}
			</select>
		</div>
	</div>

	<div>
		<label for="description" class="mb-1 block text-sm text-zinc-300">
			Description <span class="text-xs text-zinc-500">(optional)</span>
		</label>
		<textarea
			id="description"
			rows="2"
			bind:value={description}
			class="field-input"
			placeholder="What the asset does, why it's in scope."
		></textarea>
	</div>

	<div class="grid grid-cols-1 gap-5 sm:grid-cols-2">
		<div>
			<label for="external_ref" class="mb-1 block text-sm text-zinc-300">
				External reference <span class="text-xs text-zinc-500">(optional)</span>
			</label>
			<input
				id="external_ref"
				type="text"
				bind:value={externalRef}
				class="field-input"
				placeholder="https://github.com/acme/prod-api"
			/>
		</div>
		<div>
			<label for="tags" class="mb-1 block text-sm text-zinc-300">
				Tags <span class="text-xs text-zinc-500">(comma-separated)</span>
			</label>
			<input
				id="tags"
				type="text"
				bind:value={tagsRaw}
				class="field-input"
				placeholder="pci, ephi, tier-1"
			/>
		</div>
	</div>

	<div>
		<label for="notes" class="mb-1 block text-sm text-zinc-300">
			Notes <span class="text-xs text-zinc-500">(optional)</span>
		</label>
		<textarea
			id="notes"
			rows="3"
			bind:value={notes}
			class="field-input"
			placeholder="Change history, audit notes, anything an auditor would want context on."
		></textarea>
	</div>

	<div class="flex items-center gap-3 pt-2">
		<button
			type="submit"
			disabled={submitting}
			class="flex items-center gap-2 rounded-md px-4 py-1.5 text-sm font-medium text-zinc-950 disabled:opacity-50"
			style="background-color: var(--accent);"
		>
			{#if submitting}<Loader2 class="h-4 w-4 animate-spin" />{/if}
			{mode === 'create' ? 'Add asset' : 'Save changes'}
		</button>
		<button
			type="button"
			onclick={onCancel}
			class="text-sm text-zinc-400 hover:text-zinc-200">Cancel</button
		>
	</div>
</form>
