<script lang="ts">
	import { goto } from '$app/navigation';
	import { auth } from '$lib/stores/auth.svelte';
	import { toasts } from '$lib/stores/toasts.svelte';
	import { getTrustCenter, updateTrustCenter, type TrustCenter } from '$lib/api/trust-center';
	import { Loader2, ExternalLink, Globe2, Save } from 'lucide-svelte';
	import PageHeader from '$lib/components/PageHeader.svelte';
	import FieldsetSection from '$lib/components/FieldsetSection.svelte';
	import Pill from '$lib/components/Pill.svelte';

	let trust = $state<TrustCenter | null>(null);
	let loading = $state(true);
	let saving = $state(false);

	let slug = $state('');
	let isPublic = $state(false);
	let displayName = $state('');
	let tagline = $state('');
	let primaryColor = $state('');
	let logoURL = $state('');
	let contactEmail = $state('');
	let contactURL = $state('');
	let showFrameworks = $state(true);
	let showSubprocessors = $state(true);
	let showContact = $state(true);

	function loadInto(tc: TrustCenter) {
		trust = tc;
		slug = tc.slug;
		isPublic = tc.is_public;
		displayName = tc.display_name ?? '';
		tagline = tc.tagline ?? '';
		primaryColor = tc.primary_color ?? '';
		logoURL = tc.logo_url ?? '';
		contactEmail = tc.contact_email ?? '';
		contactURL = tc.contact_url ?? '';
		showFrameworks = tc.show_frameworks;
		showSubprocessors = tc.show_subprocessors;
		showContact = tc.show_contact;
	}

	$effect(() => {
		(async () => {
			if (auth.me && !auth.me.is_admin) {
				// Trust Center editing is admin-only — non-admins
				// land elsewhere rather than seeing a half-populated
				// form (the backend would 403 the PATCH anyway).
				await goto('/');
				return;
			}
			try {
				const tc = await getTrustCenter();
				loadInto(tc);
			} catch (e) {
				toasts.error((e as Error).message);
			} finally {
				loading = false;
			}
		})();
	});

	const publicURL = $derived(
		typeof window !== 'undefined' && slug
			? `${window.location.origin}/trust/${slug}`
			: `/trust/${slug}`
	);

	async function handleSave(e: SubmitEvent) {
		e.preventDefault();
		if (saving) return;
		saving = true;
		try {
			const next = await updateTrustCenter({
				slug: slug.trim() || undefined,
				is_public: isPublic,
				display_name: displayName.trim(),
				tagline: tagline.trim(),
				primary_color: primaryColor.trim(),
				logo_url: logoURL.trim(),
				contact_email: contactEmail.trim(),
				contact_url: contactURL.trim(),
				show_frameworks: showFrameworks,
				show_subprocessors: showSubprocessors,
				show_contact: showContact
			});
			loadInto(next);
			toasts.success('Trust Center saved.');
		} catch (e) {
			toasts.error((e as Error).message);
		} finally {
			saving = false;
		}
	}
</script>

<svelte:head>
	<title>Trust Center · Settings · Touchstone GRC</title>
</svelte:head>

<div class="mx-auto max-w-3xl px-8 py-10">
	<a href="/settings" class="text-sm text-zinc-500 underline-offset-4 hover:underline">
		← Settings
	</a>

	<div class="mt-2">
		<PageHeader
			kicker="Phase 8 · Public surface"
			title="Trust Center"
			subtitle="The public security-posture page prospective customers visit during evaluation. Toggle it on once the content is ready; the URL becomes reachable to anyone, no login required."
		>
			{#snippet actions()}
				{#if trust?.is_public}
					<a
						href={publicURL}
						target="_blank"
						rel="noopener noreferrer"
						class="flex items-center gap-1.5 rounded-md border border-zinc-700 px-3 py-1.5 text-sm text-zinc-200 hover:border-zinc-600"
					>
						<Globe2 class="h-4 w-4" />
						View live <ExternalLink class="h-3.5 w-3.5" />
					</a>
				{/if}
			{/snippet}
			{#snippet metrics()}
				<div class="flex items-center gap-3 text-xs">
					<span class="text-zinc-500">Status:</span>
					{#if trust?.is_public}
						<Pill kind="success" pulse>public</Pill>
					{:else}
						<Pill kind="muted">private</Pill>
					{/if}
					<span class="text-zinc-500">Public URL:</span>
					<a
						href={publicURL}
						target="_blank"
						rel="noopener noreferrer"
						class="font-mono text-xs underline-offset-4 hover:underline"
						style="color: var(--accent);"
					>
						{publicURL}
					</a>
				</div>
			{/snippet}
		</PageHeader>
	</div>

	{#if loading}
		<div class="mt-8 flex items-center gap-2 text-zinc-500">
			<Loader2 class="h-4 w-4 animate-spin" /> Loading…
		</div>
	{:else if trust}
		<form onsubmit={handleSave} class="mt-8 space-y-8">
			<FieldsetSection
				legend="Publication"
				description="Flip the switch only after the content below reads the way you want it to. Auditors and procurement teams will share the URL."
				divider={false}
			>
				<label class="flex items-start gap-3 text-sm text-zinc-200">
					<input
						type="checkbox"
						bind:checked={isPublic}
						class="mt-0.5 h-4 w-4 rounded border-zinc-700 bg-zinc-900 accent-[var(--accent)]"
					/>
					<span>
						Publish the Trust Center at <code class="font-mono text-xs">{publicURL}</code>
						<span class="block text-xs text-zinc-500">
							When off, the page returns 404 to anyone visiting it. Existing live URLs stop
							responding immediately.
						</span>
					</span>
				</label>

				<div>
					<label for="slug" class="mb-1 block text-sm text-zinc-300">
						Slug <span class="text-xs text-zinc-500">(lowercase, kebab-case, 1–60 chars)</span>
					</label>
					<input
						id="slug"
						type="text"
						required
						bind:value={slug}
						class="field-input font-mono"
						placeholder="acme-corp"
					/>
				</div>
			</FieldsetSection>

			<FieldsetSection legend="Branding">
				<div class="grid grid-cols-1 gap-5 sm:grid-cols-2">
					<div>
						<label for="display_name" class="mb-1 block text-sm text-zinc-300">
							Display name <span class="text-xs text-zinc-500">(falls back to org slug)</span>
						</label>
						<input
							id="display_name"
							type="text"
							bind:value={displayName}
							class="field-input"
							placeholder="ACME Corporation"
						/>
					</div>
					<div>
						<label for="primary_color" class="mb-1 block text-sm text-zinc-300">
							Primary color <span class="text-xs text-zinc-500">(hex, e.g. #2DD4BF)</span>
						</label>
						<input
							id="primary_color"
							type="text"
							bind:value={primaryColor}
							class="field-input font-mono"
							placeholder="#2DD4BF"
						/>
					</div>
				</div>

				<div>
					<label for="tagline" class="mb-1 block text-sm text-zinc-300">
						Tagline <span class="text-xs text-zinc-500">(one short line under the title)</span>
					</label>
					<input
						id="tagline"
						type="text"
						bind:value={tagline}
						class="field-input"
						placeholder="The security and compliance posture of ACME Corp at a glance."
					/>
				</div>

				<div>
					<label for="logo_url" class="mb-1 block text-sm text-zinc-300">
						Logo URL <span class="text-xs text-zinc-500">(optional)</span>
					</label>
					<input
						id="logo_url"
						type="url"
						bind:value={logoURL}
						class="field-input"
						placeholder="https://acme.example/logo.svg"
					/>
				</div>
			</FieldsetSection>

			<FieldsetSection
				legend="Sections"
				description="Hide entire sections without losing the underlying data — useful during renegotiations or before a new framework finishes onboarding."
			>
				<label class="flex items-start gap-3 text-sm text-zinc-200">
					<input
						type="checkbox"
						bind:checked={showFrameworks}
						class="mt-0.5 h-4 w-4 rounded border-zinc-700 bg-zinc-900 accent-[var(--accent)]"
					/>
					<span>
						Compliance frameworks
						<span class="block text-xs text-zinc-500">
							Lists every framework enabled on your org (SOC 2 / CIS / PCI / HIPAA / ISO 27001).
						</span>
					</span>
				</label>
				<label class="flex items-start gap-3 text-sm text-zinc-200">
					<input
						type="checkbox"
						bind:checked={showSubprocessors}
						class="mt-0.5 h-4 w-4 rounded border-zinc-700 bg-zinc-900 accent-[var(--accent)]"
					/>
					<span>
						Subprocessors
						<span class="block text-xs text-zinc-500">
							Lists active vendors you've marked "List on Trust Center" on the vendor edit page.
						</span>
					</span>
				</label>
				<label class="flex items-start gap-3 text-sm text-zinc-200">
					<input
						type="checkbox"
						bind:checked={showContact}
						class="mt-0.5 h-4 w-4 rounded border-zinc-700 bg-zinc-900 accent-[var(--accent)]"
					/>
					<span>
						Contact CTA
						<span class="block text-xs text-zinc-500">
							Surfaces the contact email / "request access" link below. Shown only when either is
							set.
						</span>
					</span>
				</label>
			</FieldsetSection>

			<FieldsetSection
				legend="Contact"
				description="Procurement teams use this to request your latest SOC 2 / ISO 27001 report or send a questionnaire (SIG / CAIQ / DDQ)."
			>
				<div class="grid grid-cols-1 gap-5 sm:grid-cols-2">
					<div>
						<label for="contact_email" class="mb-1 block text-sm text-zinc-300">
							Contact email <span class="text-xs text-zinc-500">(optional)</span>
						</label>
						<input
							id="contact_email"
							type="email"
							bind:value={contactEmail}
							class="field-input"
							placeholder="trust@acme.example"
						/>
					</div>
					<div>
						<label for="contact_url" class="mb-1 block text-sm text-zinc-300">
							Contact URL <span class="text-xs text-zinc-500">(optional)</span>
						</label>
						<input
							id="contact_url"
							type="url"
							bind:value={contactURL}
							class="field-input"
							placeholder="https://acme.example/security/request"
						/>
					</div>
				</div>
			</FieldsetSection>

			<div class="flex items-center gap-3 pt-2">
				<button
					type="submit"
					disabled={saving}
					class="flex items-center gap-2 rounded-md px-4 py-1.5 text-sm font-medium text-zinc-950 disabled:opacity-50"
					style="background-color: var(--accent);"
				>
					{#if saving}<Loader2 class="h-4 w-4 animate-spin" />{:else}<Save class="h-4 w-4" />{/if}
					Save Trust Center
				</button>
			</div>
		</form>
	{/if}
</div>
