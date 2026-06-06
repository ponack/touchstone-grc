<script lang="ts">
	import type {
		Risk,
		RiskCategory,
		RiskLevel,
		RiskStatus,
		RiskTreatment
	} from '$lib/api/risks';
	import { riskScore } from '$lib/api/risks';
	import type { Person } from '$lib/api/personnel';
	import type { Asset } from '$lib/api/assets';
	import type { Vendor } from '$lib/api/vendors';
	import { Loader2 } from 'lucide-svelte';
	import FieldsetSection from '$lib/components/FieldsetSection.svelte';

	interface Props {
		mode: 'create' | 'edit';
		initial?: Risk;
		owners: Person[];
		assets: Asset[];
		vendors: Vendor[];
		submitting: boolean;
		onSubmit: (values: {
			title: string;
			description: string;
			risk_category: RiskCategory;
			inherent_likelihood: RiskLevel;
			inherent_impact: RiskLevel;
			residual_likelihood: RiskLevel;
			residual_impact: RiskLevel;
			treatment_strategy: RiskTreatment;
			treatment_plan: string;
			status: RiskStatus;
			owner_id: string | null;
			related_asset_id: string | null;
			related_vendor_id: string | null;
			identified_date: string | null;
			last_review_date: string | null;
			next_review_date: string | null;
			closed_date: string | null;
			tags: string[];
			notes: string;
		}) => void | Promise<void>;
		onCancel: () => void;
	}

	let { mode, initial, owners, assets, vendors, submitting, onSubmit, onCancel }: Props = $props();

	// svelte-ignore state_referenced_locally
	let title = $state(initial?.title ?? '');
	// svelte-ignore state_referenced_locally
	let description = $state(initial?.description ?? '');
	// svelte-ignore state_referenced_locally
	let category = $state<RiskCategory>(initial?.risk_category ?? 'security');
	// svelte-ignore state_referenced_locally
	let inherentL = $state<RiskLevel>(initial?.inherent_likelihood ?? 'medium');
	// svelte-ignore state_referenced_locally
	let inherentI = $state<RiskLevel>(initial?.inherent_impact ?? 'medium');
	// svelte-ignore state_referenced_locally
	let residualL = $state<RiskLevel>(initial?.residual_likelihood ?? 'medium');
	// svelte-ignore state_referenced_locally
	let residualI = $state<RiskLevel>(initial?.residual_impact ?? 'medium');
	// svelte-ignore state_referenced_locally
	let treatmentStrategy = $state<RiskTreatment>(initial?.treatment_strategy ?? 'mitigate');
	// svelte-ignore state_referenced_locally
	let treatmentPlan = $state(initial?.treatment_plan ?? '');
	// svelte-ignore state_referenced_locally
	let status = $state<RiskStatus>(initial?.status ?? 'identified');
	// svelte-ignore state_referenced_locally
	let ownerId = $state(initial?.owner_id ?? '');
	// svelte-ignore state_referenced_locally
	let relatedAssetId = $state(initial?.related_asset_id ?? '');
	// svelte-ignore state_referenced_locally
	let relatedVendorId = $state(initial?.related_vendor_id ?? '');
	// svelte-ignore state_referenced_locally
	let identifiedDate = $state(
		initial?.identified_date?.slice(0, 10) ?? new Date().toISOString().slice(0, 10)
	);
	// svelte-ignore state_referenced_locally
	let lastReviewDate = $state(initial?.last_review_date?.slice(0, 10) ?? '');
	// svelte-ignore state_referenced_locally
	let nextReviewDate = $state(initial?.next_review_date?.slice(0, 10) ?? '');
	// svelte-ignore state_referenced_locally
	let closedDate = $state(initial?.closed_date?.slice(0, 10) ?? '');
	// svelte-ignore state_referenced_locally
	let tagsRaw = $state((initial?.tags ?? []).join(', '));
	// svelte-ignore state_referenced_locally
	let notes = $state(initial?.notes ?? '');

	const inherentScore = $derived(riskScore(inherentL, inherentI));
	const residualScore = $derived(riskScore(residualL, residualI));
	const scoreDelta = $derived(inherentScore - residualScore);

	function scoreTone(s: number): string {
		if (s >= 12) return 'text-red-300';
		if (s >= 6) return 'text-amber-300';
		if (s >= 3) return 'text-zinc-200';
		return 'text-emerald-300';
	}

	async function handle(e: SubmitEvent) {
		e.preventDefault();
		if (submitting) return;
		const tags = tagsRaw
			.split(',')
			.map((t) => t.trim())
			.filter((t) => t.length > 0);
		await onSubmit({
			title: title.trim(),
			description: description.trim(),
			risk_category: category,
			inherent_likelihood: inherentL,
			inherent_impact: inherentI,
			residual_likelihood: residualL,
			residual_impact: residualI,
			treatment_strategy: treatmentStrategy,
			treatment_plan: treatmentPlan.trim(),
			status,
			owner_id: ownerId || null,
			related_asset_id: relatedAssetId || null,
			related_vendor_id: relatedVendorId || null,
			identified_date: identifiedDate || null,
			last_review_date: lastReviewDate || null,
			next_review_date: nextReviewDate || null,
			closed_date: closedDate || null,
			tags,
			notes: notes.trim()
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
				placeholder="Stripe API key leaked via misconfigured CI variable"
			/>
		</div>
		<div>
			<label for="description" class="mb-1 block text-sm text-zinc-300">
				Description <span class="text-xs text-zinc-500">(what could happen, how, why)</span>
			</label>
			<textarea
				id="description"
				rows="3"
				bind:value={description}
				class="field-input"
				placeholder="Describe the threat / vulnerability / consequence chain the auditor will trace."
			></textarea>
		</div>
		<div class="grid grid-cols-1 gap-5 sm:grid-cols-2">
			<div>
				<label for="category" class="mb-1 block text-sm text-zinc-300">Category</label>
				<select id="category" bind:value={category} class="field-input">
					<option value="operational">Operational</option>
					<option value="security">Security</option>
					<option value="privacy">Privacy</option>
					<option value="compliance">Compliance</option>
					<option value="financial">Financial</option>
					<option value="reputational">Reputational</option>
					<option value="strategic">Strategic</option>
					<option value="third_party">Third-party</option>
					<option value="other">Other</option>
				</select>
			</div>
			<div>
				<label for="status" class="mb-1 block text-sm text-zinc-300">Status</label>
				<select id="status" bind:value={status} class="field-input">
					<option value="identified">Identified</option>
					<option value="treating">Treating</option>
					<option value="accepted">Accepted</option>
					<option value="closed">Closed</option>
				</select>
			</div>
		</div>
	</FieldsetSection>

	<FieldsetSection
		legend="Assessment"
		description="Inherent = risk before any treatment. Residual = risk after the treatment plan lands. Score = likelihood × impact (1 – 16)."
	>
		<div class="grid grid-cols-1 gap-5 sm:grid-cols-2">
			<div class="rounded-md border border-zinc-800/60 p-4">
				<p class="text-[0.65rem] font-medium uppercase tracking-[0.22em] text-zinc-500">
					Inherent
				</p>
				<div class="mt-3 grid grid-cols-2 gap-3">
					<div>
						<label for="il" class="mb-1 block text-xs text-zinc-400">Likelihood</label>
						<select id="il" bind:value={inherentL} class="field-input">
							<option value="low">Low</option>
							<option value="medium">Medium</option>
							<option value="high">High</option>
							<option value="critical">Critical</option>
						</select>
					</div>
					<div>
						<label for="ii" class="mb-1 block text-xs text-zinc-400">Impact</label>
						<select id="ii" bind:value={inherentI} class="field-input">
							<option value="low">Low</option>
							<option value="medium">Medium</option>
							<option value="high">High</option>
							<option value="critical">Critical</option>
						</select>
					</div>
				</div>
				<p class="mt-3 font-mono text-xs">
					<span class="text-zinc-500">Score</span>
					<span class="ml-2 text-lg {scoreTone(inherentScore)}">{inherentScore}</span>
				</p>
			</div>
			<div class="rounded-md border border-zinc-800/60 p-4">
				<p class="text-[0.65rem] font-medium uppercase tracking-[0.22em] text-zinc-500">
					Residual
				</p>
				<div class="mt-3 grid grid-cols-2 gap-3">
					<div>
						<label for="rl" class="mb-1 block text-xs text-zinc-400">Likelihood</label>
						<select id="rl" bind:value={residualL} class="field-input">
							<option value="low">Low</option>
							<option value="medium">Medium</option>
							<option value="high">High</option>
							<option value="critical">Critical</option>
						</select>
					</div>
					<div>
						<label for="ri" class="mb-1 block text-xs text-zinc-400">Impact</label>
						<select id="ri" bind:value={residualI} class="field-input">
							<option value="low">Low</option>
							<option value="medium">Medium</option>
							<option value="high">High</option>
							<option value="critical">Critical</option>
						</select>
					</div>
				</div>
				<p class="mt-3 font-mono text-xs">
					<span class="text-zinc-500">Score</span>
					<span class="ml-2 text-lg {scoreTone(residualScore)}">{residualScore}</span>
					{#if scoreDelta > 0}
						<span class="ml-2 text-emerald-400">−{scoreDelta} from inherent</span>
					{:else if scoreDelta < 0}
						<span class="ml-2 text-red-400">+{-scoreDelta} from inherent</span>
					{/if}
				</p>
			</div>
		</div>
	</FieldsetSection>

	<FieldsetSection
		legend="Treatment"
		description="Strategy is the high-level call; the plan is what you tell the auditor you'll actually do."
	>
		<div>
			<label for="strategy" class="mb-1 block text-sm text-zinc-300">Treatment strategy</label>
			<select id="strategy" bind:value={treatmentStrategy} class="field-input">
				<option value="mitigate">Mitigate — reduce likelihood or impact</option>
				<option value="accept">Accept — sign-off as-is</option>
				<option value="transfer">Transfer — insurance, third party</option>
				<option value="avoid">Avoid — remove the source</option>
			</select>
		</div>
		<div>
			<label for="plan" class="mb-1 block text-sm text-zinc-300">
				Treatment plan <span class="text-xs text-zinc-500">(optional)</span>
			</label>
			<textarea
				id="plan"
				rows="3"
				bind:value={treatmentPlan}
				class="field-input"
				placeholder="Concrete actions, owners, dates, expected residual impact."
			></textarea>
		</div>
	</FieldsetSection>

	<FieldsetSection legend="Ownership & references">
		<div>
			<label for="owner" class="mb-1 block text-sm text-zinc-300">
				Risk owner <span class="text-xs text-zinc-500">(personnel record)</span>
			</label>
			<select id="owner" bind:value={ownerId} class="field-input">
				<option value="">— none —</option>
				{#each owners as p (p.id)}
					<option value={p.id}>{p.full_name} · {p.role}</option>
				{/each}
			</select>
		</div>
		<div class="grid grid-cols-1 gap-5 sm:grid-cols-2">
			<div>
				<label for="rel_asset" class="mb-1 block text-sm text-zinc-300">
					Related asset <span class="text-xs text-zinc-500">(optional)</span>
				</label>
				<select id="rel_asset" bind:value={relatedAssetId} class="field-input">
					<option value="">— none —</option>
					{#each assets as a (a.id)}
						<option value={a.id}>{a.name}</option>
					{/each}
				</select>
			</div>
			<div>
				<label for="rel_vendor" class="mb-1 block text-sm text-zinc-300">
					Related vendor <span class="text-xs text-zinc-500">(optional)</span>
				</label>
				<select id="rel_vendor" bind:value={relatedVendorId} class="field-input">
					<option value="">— none —</option>
					{#each vendors as v (v.id)}
						<option value={v.id}>{v.name}</option>
					{/each}
				</select>
			</div>
		</div>
	</FieldsetSection>

	<FieldsetSection
		legend="Review cadence"
		description="Identified date anchors the timeline; next review is what the auditor will ask about."
	>
		<div class="grid grid-cols-1 gap-5 sm:grid-cols-2">
			<div>
				<label for="identified" class="mb-1 block text-sm text-zinc-300">Identified</label>
				<input id="identified" type="date" bind:value={identifiedDate} class="field-input" />
			</div>
			<div>
				<label for="closed" class="mb-1 block text-sm text-zinc-300">
					Closed <span class="text-xs text-zinc-500">(required if status = closed)</span>
				</label>
				<input id="closed" type="date" bind:value={closedDate} class="field-input" />
			</div>
		</div>
		<div class="grid grid-cols-1 gap-5 sm:grid-cols-2">
			<div>
				<label for="last_rev" class="mb-1 block text-sm text-zinc-300">
					Last review <span class="text-xs text-zinc-500">(optional)</span>
				</label>
				<input id="last_rev" type="date" bind:value={lastReviewDate} class="field-input" />
			</div>
			<div>
				<label for="next_rev" class="mb-1 block text-sm text-zinc-300">
					Next review <span class="text-xs text-zinc-500">(quarterly is typical)</span>
				</label>
				<input id="next_rev" type="date" bind:value={nextReviewDate} class="field-input" />
			</div>
		</div>
	</FieldsetSection>

	<FieldsetSection legend="Tags & notes">
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
				Free-form context <span class="text-xs text-zinc-500">(optional)</span>
			</label>
			<textarea
				id="notes"
				rows="3"
				bind:value={notes}
				class="field-input"
				placeholder="Incident history, related controls, anything an auditor would want context on."
			></textarea>
		</div>
	</FieldsetSection>

	<div class="flex items-center gap-3 pt-2">
		<button
			type="submit"
			disabled={submitting}
			class="flex items-center gap-2 rounded-md px-4 py-1.5 text-sm font-medium text-zinc-950 disabled:opacity-50"
			style="background-color: var(--accent);"
		>
			{#if submitting}<Loader2 class="h-4 w-4 animate-spin" />{/if}
			{mode === 'create' ? 'Log risk' : 'Save changes'}
		</button>
		<button
			type="button"
			onclick={onCancel}
			class="text-sm text-zinc-400 hover:text-zinc-200">Cancel</button
		>
	</div>
</form>
