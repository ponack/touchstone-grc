<script lang="ts">
	import type { TrustBlock } from '$lib/api/trust-blocks';
	import { Loader2 } from 'lucide-svelte';
	import { marked } from 'marked';
	import FieldsetSection from '$lib/components/FieldsetSection.svelte';

	interface Props {
		mode: 'create' | 'edit';
		initial?: TrustBlock;
		submitting: boolean;
		onSubmit: (values: {
			heading: string;
			body_markdown: string;
			is_public: boolean;
		}) => void | Promise<void>;
		onCancel: () => void;
	}

	let { mode, initial, submitting, onSubmit, onCancel }: Props = $props();

	// svelte-ignore state_referenced_locally
	let heading = $state(initial?.heading ?? '');
	// svelte-ignore state_referenced_locally
	let bodyMarkdown = $state(initial?.body_markdown ?? '');
	// svelte-ignore state_referenced_locally
	let isPublic = $state(initial?.is_public ?? false);
	let showPreview = $state(false);

	// Simple client-side markdown render. marked handles the parse;
	// we don't sanitize here because the admin is the author and the
	// same admin controls the tagline / display_name fields that
	// already carry raw text to the public page.
	const previewHTML = $derived(bodyMarkdown ? marked.parse(bodyMarkdown) : '');

	async function handle(e: SubmitEvent) {
		e.preventDefault();
		if (submitting) return;
		await onSubmit({
			heading: heading.trim(),
			body_markdown: bodyMarkdown.trim(),
			is_public: isPublic
		});
	}
</script>

<form onsubmit={handle} class="space-y-8">
	<FieldsetSection legend="Content" divider={false}>
		<div>
			<label for="heading" class="mb-1 block text-sm text-zinc-300">Heading</label>
			<input
				id="heading"
				type="text"
				required
				bind:value={heading}
				class="field-input"
				placeholder="Data handling"
			/>
		</div>
		<div>
			<div class="mb-1 flex items-center justify-between">
				<label for="body_markdown" class="text-sm text-zinc-300">
					Body <span class="text-xs text-zinc-500">(Markdown — headings, lists, links, code)</span>
				</label>
				<button
					type="button"
					onclick={() => (showPreview = !showPreview)}
					class="text-xs text-zinc-400 underline-offset-4 hover:text-zinc-200 hover:underline"
				>
					{showPreview ? 'Edit' : 'Preview'}
				</button>
			</div>
			{#if showPreview}
				<div
					class="prose prose-invert prose-sm max-w-none rounded-md border border-zinc-800 bg-zinc-950/40 p-4"
				>
					{@html previewHTML}
				</div>
			{:else}
				<textarea
					id="body_markdown"
					rows="12"
					required
					bind:value={bodyMarkdown}
					class="field-input font-mono text-xs"
					placeholder={`## Where we store customer data\n\nCustomer data is stored in AWS **us-east-1** with encryption at rest (AES-256) and in transit (TLS 1.2+).\n\n- Backups run every 24 hours\n- Retained for 30 days\n- Access is logged to a dedicated audit trail`}
				></textarea>
			{/if}
		</div>
	</FieldsetSection>

	<FieldsetSection
		legend="Visibility"
		description="Off by default so you can iterate on the copy without exposing it. The 'Custom blocks' section in /settings/trust-center must also be enabled for the block to appear publicly."
	>
		<label class="flex items-start gap-3 text-sm text-zinc-300">
			<input
				type="checkbox"
				bind:checked={isPublic}
				class="mt-0.5 h-4 w-4 rounded border-zinc-700 bg-zinc-900 accent-[var(--accent)]"
			/>
			<span>
				Show this block on the public Trust Center
				<span class="block text-xs text-zinc-500">
					Renders the Markdown as HTML on the public page.
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
			{mode === 'create' ? 'Add block' : 'Save changes'}
		</button>
		<button
			type="button"
			onclick={onCancel}
			class="text-sm text-zinc-400 hover:text-zinc-200">Cancel</button
		>
	</div>
</form>
