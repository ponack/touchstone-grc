<script lang="ts">
	import type {
		Vendor,
		VendorClassification,
		VendorCriticality,
		VendorStatus,
		VendorType
	} from '$lib/api/vendors';
	import type { Person } from '$lib/api/personnel';
	import { Loader2 } from 'lucide-svelte';

	interface Props {
		mode: 'create' | 'edit';
		initial?: Vendor;
		owners: Person[];
		submitting: boolean;
		onSubmit: (values: {
			name: string;
			vendor_type: VendorType;
			criticality: VendorCriticality;
			status: VendorStatus;
			data_classification: VendorClassification | '' | 'none';
			owner_id: string | null;
			website: string;
			contact_name: string;
			contact_email: string;
			description: string;
			onboarded_date: string | null;
			offboarded_date: string | null;
			assurance_report: string;
			last_review_date: string | null;
			next_review_date: string | null;
			tags: string[];
			notes: string;
		}) => void | Promise<void>;
		onCancel: () => void;
	}

	let { mode, initial, owners, submitting, onSubmit, onCancel }: Props = $props();

	// svelte-ignore state_referenced_locally
	let name = $state(initial?.name ?? '');
	// svelte-ignore state_referenced_locally
	let vendorType = $state<VendorType>(initial?.vendor_type ?? 'saas');
	// svelte-ignore state_referenced_locally
	let criticality = $state<VendorCriticality>(initial?.criticality ?? 'medium');
	// svelte-ignore state_referenced_locally
	let status = $state<VendorStatus>(initial?.status ?? 'active');
	// svelte-ignore state_referenced_locally
	let dataClassification = $state<VendorClassification | ''>(
		(initial?.data_classification as VendorClassification | null | undefined) ?? ''
	);
	// svelte-ignore state_referenced_locally
	let ownerId = $state(initial?.owner_id ?? '');
	// svelte-ignore state_referenced_locally
	let website = $state(initial?.website ?? '');
	// svelte-ignore state_referenced_locally
	let contactName = $state(initial?.contact_name ?? '');
	// svelte-ignore state_referenced_locally
	let contactEmail = $state(initial?.contact_email ?? '');
	// svelte-ignore state_referenced_locally
	let description = $state(initial?.description ?? '');
	// svelte-ignore state_referenced_locally
	let onboardedDate = $state(initial?.onboarded_date?.slice(0, 10) ?? '');
	// svelte-ignore state_referenced_locally
	let offboardedDate = $state(initial?.offboarded_date?.slice(0, 10) ?? '');
	// svelte-ignore state_referenced_locally
	let assuranceReport = $state(initial?.assurance_report ?? '');
	// svelte-ignore state_referenced_locally
	let lastReviewDate = $state(initial?.last_review_date?.slice(0, 10) ?? '');
	// svelte-ignore state_referenced_locally
	let nextReviewDate = $state(initial?.next_review_date?.slice(0, 10) ?? '');
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
		let classOut: VendorClassification | '' | 'none' = dataClassification;
		if (mode === 'edit' && initial?.data_classification && !dataClassification) {
			classOut = 'none';
		}
		await onSubmit({
			name: name.trim(),
			vendor_type: vendorType,
			criticality,
			status,
			data_classification: classOut,
			owner_id: ownerId || null,
			website: website.trim(),
			contact_name: contactName.trim(),
			contact_email: contactEmail.trim(),
			description: description.trim(),
			onboarded_date: onboardedDate || null,
			offboarded_date: offboardedDate || null,
			assurance_report: assuranceReport.trim(),
			last_review_date: lastReviewDate || null,
			next_review_date: nextReviewDate || null,
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
				placeholder="Stripe"
			/>
		</div>
		<div>
			<label for="vendor_type" class="mb-1 block text-sm text-zinc-300">Type</label>
			<select id="vendor_type" bind:value={vendorType} class="field-input">
				<option value="saas">SaaS</option>
				<option value="paas">PaaS</option>
				<option value="iaas">IaaS</option>
				<option value="processor">Processor (handles PII on our behalf)</option>
				<option value="subprocessor">Subprocessor</option>
				<option value="hardware">Hardware</option>
				<option value="professional_services">Professional services</option>
				<option value="other">Other</option>
			</select>
		</div>
	</div>

	<div class="grid grid-cols-1 gap-5 sm:grid-cols-3">
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
				<option value="prospective">Prospective</option>
				<option value="active">Active</option>
				<option value="terminated">Terminated</option>
			</select>
		</div>
		<div>
			<label for="data_classification" class="mb-1 block text-sm text-zinc-300">
				Data class <span class="text-xs text-zinc-500">(optional)</span>
			</label>
			<select id="data_classification" bind:value={dataClassification} class="field-input">
				<option value="">— not set —</option>
				<option value="public">Public</option>
				<option value="internal">Internal</option>
				<option value="confidential">Confidential</option>
				<option value="restricted">Restricted</option>
			</select>
		</div>
	</div>

	<div class="grid grid-cols-1 gap-5 sm:grid-cols-2">
		<div>
			<label for="owner" class="mb-1 block text-sm text-zinc-300">
				Internal owner <span class="text-xs text-zinc-500">(personnel record)</span>
			</label>
			<select id="owner" bind:value={ownerId} class="field-input">
				<option value="">— none —</option>
				{#each owners as p (p.id)}
					<option value={p.id}>{p.full_name} · {p.role}</option>
				{/each}
			</select>
		</div>
		<div>
			<label for="website" class="mb-1 block text-sm text-zinc-300">
				Website <span class="text-xs text-zinc-500">(optional)</span>
			</label>
			<input
				id="website"
				type="text"
				bind:value={website}
				class="field-input"
				placeholder="https://stripe.com"
			/>
		</div>
	</div>

	<div class="grid grid-cols-1 gap-5 sm:grid-cols-2">
		<div>
			<label for="contact_name" class="mb-1 block text-sm text-zinc-300">
				Contact name <span class="text-xs text-zinc-500">(optional)</span>
			</label>
			<input
				id="contact_name"
				type="text"
				bind:value={contactName}
				class="field-input"
				placeholder="Account manager"
			/>
		</div>
		<div>
			<label for="contact_email" class="mb-1 block text-sm text-zinc-300">
				Contact email <span class="text-xs text-zinc-500">(optional)</span>
			</label>
			<input
				id="contact_email"
				type="email"
				bind:value={contactEmail}
				class="field-input"
				placeholder="csm@stripe.com"
			/>
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
			placeholder="What the vendor provides + why they're in scope."
		></textarea>
	</div>

	<div class="grid grid-cols-1 gap-5 sm:grid-cols-2">
		<div>
			<label for="onboarded_date" class="mb-1 block text-sm text-zinc-300">
				Onboarded <span class="text-xs text-zinc-500">(optional)</span>
			</label>
			<input id="onboarded_date" type="date" bind:value={onboardedDate} class="field-input" />
		</div>
		<div>
			<label for="offboarded_date" class="mb-1 block text-sm text-zinc-300">
				Offboarded <span class="text-xs text-zinc-500">(required if terminated)</span>
			</label>
			<input id="offboarded_date" type="date" bind:value={offboardedDate} class="field-input" />
		</div>
	</div>

	<div>
		<label for="assurance_report" class="mb-1 block text-sm text-zinc-300">
			Assurance report <span class="text-xs text-zinc-500">(optional)</span>
		</label>
		<input
			id="assurance_report"
			type="text"
			bind:value={assuranceReport}
			class="field-input"
			placeholder="SOC 2 Type II 2025-Q3"
		/>
	</div>

	<div class="grid grid-cols-1 gap-5 sm:grid-cols-2">
		<div>
			<label for="last_review_date" class="mb-1 block text-sm text-zinc-300">
				Last review <span class="text-xs text-zinc-500">(optional)</span>
			</label>
			<input id="last_review_date" type="date" bind:value={lastReviewDate} class="field-input" />
		</div>
		<div>
			<label for="next_review_date" class="mb-1 block text-sm text-zinc-300">
				Next review <span class="text-xs text-zinc-500">(annual cadence is typical)</span>
			</label>
			<input id="next_review_date" type="date" bind:value={nextReviewDate} class="field-input" />
		</div>
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
			placeholder="pii, payments, tier-1"
		/>
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
			placeholder="Audit notes, contract specifics, DPA status, anything an auditor would want context on."
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
			{mode === 'create' ? 'Add vendor' : 'Save changes'}
		</button>
		<button
			type="button"
			onclick={onCancel}
			class="text-sm text-zinc-400 hover:text-zinc-200">Cancel</button
		>
	</div>
</form>
