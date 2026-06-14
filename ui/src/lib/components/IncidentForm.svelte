<script lang="ts">
	import type {
		IncidentSeverity,
		IncidentStatus,
		TrustIncident
	} from '$lib/api/trust-incidents';
	import { Loader2 } from 'lucide-svelte';
	import FieldsetSection from '$lib/components/FieldsetSection.svelte';

	interface Props {
		mode: 'create' | 'edit';
		initial?: TrustIncident;
		submitting: boolean;
		onSubmit: (values: {
			title: string;
			status: IncidentStatus;
			severity: IncidentSeverity;
			occurred_at: string | null;
			resolved_at: string | null;
			summary: string;
			public_response: string;
			is_public: boolean;
		}) => void | Promise<void>;
		onCancel: () => void;
	}

	let { mode, initial, submitting, onSubmit, onCancel }: Props = $props();

	function isoLocal(iso?: string | null): string {
		if (!iso) return '';
		const d = new Date(iso);
		const tzOffset = d.getTimezoneOffset() * 60_000;
		return new Date(d.getTime() - tzOffset).toISOString().slice(0, 16);
	}

	// svelte-ignore state_referenced_locally
	let title = $state(initial?.title ?? '');
	// svelte-ignore state_referenced_locally
	let status = $state<IncidentStatus>(initial?.status ?? 'ongoing');
	// svelte-ignore state_referenced_locally
	let severity = $state<IncidentSeverity>(initial?.severity ?? 'medium');
	// svelte-ignore state_referenced_locally
	let occurredAt = $state(isoLocal(initial?.occurred_at ?? new Date().toISOString()));
	// svelte-ignore state_referenced_locally
	let resolvedAt = $state(isoLocal(initial?.resolved_at));
	// svelte-ignore state_referenced_locally
	let summary = $state(initial?.summary ?? '');
	// svelte-ignore state_referenced_locally
	let publicResponse = $state(initial?.public_response ?? '');
	// svelte-ignore state_referenced_locally
	let isPublic = $state(initial?.is_public ?? false);

	function toISO(local: string): string | null {
		if (!local) return null;
		return new Date(local).toISOString();
	}

	async function handle(e: SubmitEvent) {
		e.preventDefault();
		if (submitting) return;
		await onSubmit({
			title: title.trim(),
			status,
			severity,
			occurred_at: toISO(occurredAt),
			resolved_at: toISO(resolvedAt),
			summary: summary.trim(),
			public_response: publicResponse.trim(),
			is_public: isPublic
		});
	}
</script>

<form onsubmit={handle} class="space-y-8">
	<FieldsetSection legend="Identity" divider={false}>
		<div>
			<label for="title" class="mb-1 block text-sm text-zinc-300">Title</label>
			<input
				id="title"
				type="text"
				required
				bind:value={title}
				class="field-input"
				placeholder="Brief regional outage — write traffic degraded"
			/>
		</div>
		<div class="grid grid-cols-1 gap-5 sm:grid-cols-2">
			<div>
				<label for="severity" class="mb-1 block text-sm text-zinc-300">Severity</label>
				<select id="severity" bind:value={severity} class="field-input">
					<option value="low">Low</option>
					<option value="medium">Medium</option>
					<option value="high">High</option>
					<option value="critical">Critical</option>
				</select>
			</div>
			<div>
				<label for="status" class="mb-1 block text-sm text-zinc-300">Status</label>
				<select id="status" bind:value={status} class="field-input">
					<option value="ongoing">Ongoing</option>
					<option value="monitoring">Monitoring</option>
					<option value="resolved">Resolved</option>
				</select>
			</div>
		</div>
	</FieldsetSection>

	<FieldsetSection legend="Timeline">
		<div class="grid grid-cols-1 gap-5 sm:grid-cols-2">
			<div>
				<label for="occurred_at" class="mb-1 block text-sm text-zinc-300">Occurred at</label>
				<input
					id="occurred_at"
					type="datetime-local"
					bind:value={occurredAt}
					class="field-input"
				/>
			</div>
			<div>
				<label for="resolved_at" class="mb-1 block text-sm text-zinc-300">
					Resolved at <span class="text-xs text-zinc-500">(required if status = resolved)</span>
				</label>
				<input
					id="resolved_at"
					type="datetime-local"
					bind:value={resolvedAt}
					class="field-input"
				/>
			</div>
		</div>
	</FieldsetSection>

	<FieldsetSection
		legend="Content"
		description="Summary stays internal — kept for SOC 2 CC7.4 review. Public response is what appears on the public Trust Center when this row is marked public."
	>
		<div>
			<label for="summary" class="mb-1 block text-sm text-zinc-300">
				Internal summary <span class="text-xs text-zinc-500">(audit trail)</span>
			</label>
			<textarea
				id="summary"
				rows="4"
				bind:value={summary}
				class="field-input"
				placeholder="Root cause, timeline, blameless review notes — the full internal picture."
			></textarea>
		</div>
		<div>
			<label for="public_response" class="mb-1 block text-sm text-zinc-300">
				Public response <span class="text-xs text-zinc-500">(what customers see)</span>
			</label>
			<textarea
				id="public_response"
				rows="4"
				bind:value={publicResponse}
				class="field-input"
				placeholder="A clear customer-facing message: what happened, the impact, what's been done about it."
			></textarea>
		</div>
	</FieldsetSection>

	<FieldsetSection
		legend="Visibility"
		description="Off by default. Flip on once the public response above is something you'd send to a procurement team. The 'Incident history' section in /settings/trust-center must also be enabled for the row to appear publicly."
	>
		<label class="flex items-start gap-3 text-sm text-zinc-300">
			<input
				type="checkbox"
				bind:checked={isPublic}
				class="mt-0.5 h-4 w-4 rounded border-zinc-700 bg-zinc-900 accent-[var(--accent)]"
			/>
			<span>
				Show this incident on the public Trust Center
				<span class="block text-xs text-zinc-500">
					Internal summary stays private regardless — only the title, status, severity, dates, and
					the public response above are exposed.
				</span>
			</span>
		</label>
	</FieldsetSection>

	<div class="flex items-center gap-3 pt-2">
		<button
			type="submit"
			disabled={submitting}
			class="flex items-center gap-2 rounded-md px-4 py-1.5 text-sm font-medium text-zinc-950 disabled:opacity-50"
			style="background-color: var(--accent);"
		>
			{#if submitting}<Loader2 class="h-4 w-4 animate-spin" />{/if}
			{mode === 'create' ? 'Log incident' : 'Save changes'}
		</button>
		<button
			type="button"
			onclick={onCancel}
			class="text-sm text-zinc-400 hover:text-zinc-200">Cancel</button
		>
	</div>
</form>
