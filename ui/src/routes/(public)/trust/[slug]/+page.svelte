<script lang="ts">
	import { page } from '$app/state';
	import {
		getPublicTrust,
		PublicTrustNotFound,
		type PublicTrustCenter
	} from '$lib/api/trust-public';
	import { Loader2, ShieldCheck, Mail, ExternalLink, BadgeCheck } from 'lucide-svelte';

	let trust = $state<PublicTrustCenter | null>(null);
	let loading = $state(true);
	let notFound = $state(false);
	let errorMessage = $state<string | null>(null);

	const slug = $derived(page.params.slug!);

	$effect(() => {
		(async () => {
			loading = true;
			notFound = false;
			errorMessage = null;
			try {
				trust = await getPublicTrust(slug);
			} catch (e) {
				if (e instanceof PublicTrustNotFound) {
					notFound = true;
				} else {
					errorMessage = (e as Error).message;
				}
			} finally {
				loading = false;
			}
		})();
	});

	// Resolve the org's chosen primary colour as a CSS variable so
	// every accent on the page picks it up. Falls back to the default
	// Forge teal if the org hasn't set one.
	const accentStyle = $derived(
		trust?.primary_color
			? `--public-accent: ${trust.primary_color};`
			: '--public-accent: #2DD4BF;'
	);

	function fmtUpdated(iso: string): string {
		const d = new Date(iso);
		return d.toLocaleDateString(undefined, { year: 'numeric', month: 'long', day: 'numeric' });
	}
</script>

<svelte:head>
	<title>{trust ? `${trust.display_name} · Trust Center` : 'Trust Center'}</title>
	{#if trust?.tagline}
		<meta name="description" content={trust.tagline} />
	{/if}
</svelte:head>

<div class="min-h-screen text-zinc-100" style={accentStyle + ' background-color: #0b1218;'}>
	<!-- Atmosphere: radial gradient in the chosen accent + faint
	     noise overlay to match the app's forged-metal aesthetic. -->
	<div
		class="pointer-events-none fixed inset-0 z-0"
		style="background: radial-gradient(ellipse at 20% -5%, color-mix(in oklab, var(--public-accent) 18%, transparent), transparent 55%), radial-gradient(ellipse at 85% 100%, color-mix(in oklab, var(--public-accent) 12%, transparent), transparent 60%);"
	></div>
	<div
		class="pointer-events-none fixed inset-0 z-0 opacity-[0.025]"
		style="background-image: url('/noise.svg'); background-size: 180px 180px; mix-blend-mode: overlay;"
	></div>

	<div class="relative z-10 mx-auto max-w-3xl px-6 py-16 sm:px-10 sm:py-24">
		{#if loading}
			<div class="flex items-center justify-center py-24 text-zinc-500">
				<Loader2 class="h-6 w-6 animate-spin" />
			</div>
		{:else if notFound}
			<div class="rounded-md border border-zinc-800 bg-zinc-900/50 p-10 text-center">
				<h1 class="font-serif text-2xl text-zinc-100">No trust center here</h1>
				<p class="mt-2 text-sm text-zinc-400">
					This page either doesn't exist or hasn't been made public yet.
				</p>
			</div>
		{:else if errorMessage}
			<div class="rounded-md border border-red-900/50 bg-red-950/20 p-6 text-sm text-red-300">
				Couldn't load this trust center: {errorMessage}
			</div>
		{:else if trust}
			<!-- Header -->
			<header class="border-b border-zinc-800/70 pb-10">
				{#if trust.logo_url}
					<img
						src={trust.logo_url}
						alt="{trust.display_name} logo"
						class="mb-6 h-10 w-auto"
					/>
				{/if}
				<p
					class="text-[0.65rem] font-medium uppercase tracking-[0.22em]"
					style="color: var(--public-accent);"
				>
					Trust Center
				</p>
				<h1
					class="mt-1 font-serif text-4xl text-zinc-100 sm:text-5xl"
					style="letter-spacing: -0.015em;"
				>
					{trust.display_name}
				</h1>
				{#if trust.tagline}
					<p class="mt-4 max-w-xl text-base text-zinc-300">{trust.tagline}</p>
				{/if}
				<p class="mt-6 text-xs text-zinc-500">
					Last updated <time datetime={trust.updated_at}>{fmtUpdated(trust.updated_at)}</time>
				</p>
			</header>

			<!-- Frameworks -->
			{#if trust.show_frameworks && trust.frameworks && trust.frameworks.length > 0}
				<section class="mt-12">
					<div class="flex items-center gap-2">
						<ShieldCheck class="h-4 w-4" style="color: var(--public-accent);" />
						<h2 class="text-[0.65rem] font-medium uppercase tracking-[0.22em] text-zinc-400">
							Compliance frameworks
						</h2>
					</div>
					<p class="mt-2 text-sm text-zinc-400">
						These are the control packs we evaluate against on every scan.
					</p>
					<ul class="mt-6 grid grid-cols-1 gap-3 sm:grid-cols-2">
						{#each trust.frameworks as f (f.code)}
							<li
								class="flex items-start gap-3 rounded-md border border-zinc-800 bg-zinc-900/40 p-4"
							>
								<BadgeCheck
									class="mt-0.5 h-5 w-5 shrink-0"
									style="color: var(--public-accent);"
								/>
								<div>
									<p class="font-serif text-base text-zinc-100">{f.name}</p>
									<p class="mt-0.5 font-mono text-xs text-zinc-500">
										{f.code}{#if f.version}&nbsp;·&nbsp;{f.version}{/if}
									</p>
								</div>
							</li>
						{/each}
					</ul>
				</section>
			{/if}

			<!-- Subprocessors -->
			{#if trust.show_subprocessors && trust.subprocessors && trust.subprocessors.length > 0}
				<section class="mt-12">
					<h2 class="text-[0.65rem] font-medium uppercase tracking-[0.22em] text-zinc-400">
						Subprocessors
					</h2>
					<p class="mt-2 text-sm text-zinc-400">
						Third-party services that may process customer data on our behalf.
					</p>
					<ul class="mt-6 divide-y divide-zinc-800/70 rounded-md border border-zinc-800">
						{#each trust.subprocessors as s (s.name)}
							<li class="flex flex-wrap items-baseline justify-between gap-3 px-4 py-3">
								<div class="min-w-0">
									{#if s.website}
										<a
											href={s.website}
											target="_blank"
											rel="noopener noreferrer"
											class="inline-flex items-center gap-1 text-zinc-100 underline-offset-4 hover:underline"
										>
											{s.name}
											<ExternalLink class="h-3 w-3 text-zinc-500" />
										</a>
									{:else}
										<span class="text-zinc-100">{s.name}</span>
									{/if}
									<p class="mt-0.5 text-xs text-zinc-500">{s.vendor_type.replace('_', ' ')}</p>
								</div>
								{#if s.assurance_report}
									<span class="font-mono text-xs text-zinc-400">{s.assurance_report}</span>
								{/if}
							</li>
						{/each}
					</ul>
				</section>
			{/if}

			<!-- Contact -->
			{#if trust.show_contact && (trust.contact_email || trust.contact_url)}
				<section
					class="mt-12 rounded-md border border-zinc-800 bg-zinc-900/40 p-6"
					style="border-color: color-mix(in oklab, var(--public-accent) 30%, transparent);"
				>
					<h2 class="font-serif text-xl text-zinc-100">Security questionnaires & audit reports</h2>
					<p class="mt-2 text-sm text-zinc-400">
						Procurement teams can request our latest SOC 2 / ISO 27001 report or send a
						questionnaire (SIG / CAIQ / DDQ) for response.
					</p>
					<div class="mt-5 flex flex-wrap gap-3 text-sm">
						{#if trust.contact_email}
							<a
								href="mailto:{trust.contact_email}"
								class="inline-flex items-center gap-1.5 rounded-md px-3 py-1.5 font-medium text-zinc-950"
								style="background-color: var(--public-accent);"
							>
								<Mail class="h-4 w-4" />
								{trust.contact_email}
							</a>
						{/if}
						{#if trust.contact_url}
							<a
								href={trust.contact_url}
								target="_blank"
								rel="noopener noreferrer"
								class="inline-flex items-center gap-1.5 rounded-md border border-zinc-700 px-3 py-1.5 text-zinc-200 hover:border-zinc-600"
							>
								Request access
								<ExternalLink class="h-3.5 w-3.5" />
							</a>
						{/if}
					</div>
				</section>
			{/if}

			<footer class="mt-16 border-t border-zinc-800/70 pt-6 text-xs text-zinc-600">
				Published with
				<a
					href="https://github.com/ponack/touchstone-grc"
					target="_blank"
					rel="noopener noreferrer"
					class="underline-offset-4 hover:underline"
					style="color: var(--public-accent);">Touchstone GRC</a
				>.
			</footer>
		{/if}
	</div>
</div>
