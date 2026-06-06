<script lang="ts">
	import { listScans, type Scan } from '$lib/api/scans';
	import { listLatest, type LatestEvidence } from '$lib/api/evidence';
	import {
		listFrameworks,
		listOrgFrameworks,
		type Framework,
		type OrgFramework
	} from '$lib/api/frameworks';
	import { listVendors, type Vendor } from '$lib/api/vendors';
	import { listExceptions, type Exception } from '$lib/api/exceptions';
	import { listPersonnel, type Person } from '$lib/api/personnel';
	import { listAssets, type Asset } from '$lib/api/assets';
	import { listRisks, riskScore, type Risk } from '$lib/api/risks';
	import { toasts } from '$lib/stores/toasts.svelte';
	import StatusPill from '$lib/components/StatusPill.svelte';
	import Pill from '$lib/components/Pill.svelte';
	import PageHeader from '$lib/components/PageHeader.svelte';
	import SkeletonRows from '$lib/components/SkeletonRows.svelte';
	import { AlertTriangle, ArrowUpRight, Clock, ShieldAlert } from 'lucide-svelte';

	let latestScan = $state<Scan | null>(null);
	let evidence = $state<LatestEvidence[]>([]);
	let frameworks = $state<Framework[]>([]);
	let orgFrameworks = $state<OrgFramework[]>([]);
	let overdueVendors = $state<Vendor[]>([]);
	let exceptions = $state<Exception[]>([]);
	let personnel = $state<Person[]>([]);
	let assets = $state<Asset[]>([]);
	let allVendors = $state<Vendor[]>([]);
	let risks = $state<Risk[]>([]);
	let loading = $state(true);

	$effect(() => {
		(async () => {
			try {
				const [
					scansResp,
					evidenceResp,
					frameworksResp,
					orgFrameworksResp,
					overdueResp,
					exceptionsResp,
					personnelResp,
					assetsResp,
					vendorsResp,
					risksResp
				] = await Promise.all([
					listScans({ limit: 1 }),
					listLatest(),
					listFrameworks(),
					listOrgFrameworks(),
					listVendors({ review_due: true }),
					listExceptions(false),
					listPersonnel(),
					listAssets(),
					listVendors(),
					listRisks()
				]);
				latestScan = scansResp[0] ?? null;
				evidence = evidenceResp;
				frameworks = frameworksResp;
				orgFrameworks = orgFrameworksResp;
				overdueVendors = overdueResp;
				exceptions = exceptionsResp;
				personnel = personnelResp;
				assets = assetsResp;
				allVendors = vendorsResp;
				risks = risksResp;
			} catch (e) {
				toasts.error((e as Error).message);
			} finally {
				loading = false;
			}
		})();
	});

	const evidenceCounts = $derived.by(() => {
		const c = { total: 0, pass: 0, fail: 0, partial: 0, not_applicable: 0, error: 0 };
		for (const e of evidence) {
			c.total++;
			c[e.status]++;
		}
		return c;
	});

	const passRatio = $derived(
		evidenceCounts.total === 0
			? 0
			: Math.round(
					((evidenceCounts.pass + evidenceCounts.not_applicable) / evidenceCounts.total) * 100
				)
	);

	const failingControls = $derived(
		evidence
			.filter((e) => e.status === 'fail')
			.slice(0, 5)
	);

	const enabledFrameworkCount = $derived(orgFrameworks.length);

	// Cross-link insight: terminated personnel who are still listed as
	// asset / vendor owner. This is the kind of finding an auditor
	// notices first — surface it in plain sight.
	const orphanedOwnerships = $derived.by(() => {
		const terminated = new Set(
			personnel.filter((p) => p.status === 'terminated').map((p) => p.id)
		);
		const rows: { type: 'asset' | 'vendor'; id: string; name: string; ownerName: string }[] = [];
		for (const a of assets) {
			if (a.owner_id && terminated.has(a.owner_id)) {
				rows.push({
					type: 'asset',
					id: a.id,
					name: a.name,
					ownerName: a.owner_name ?? '(unknown)'
				});
			}
		}
		for (const v of allVendors) {
			if (v.owner_id && terminated.has(v.owner_id)) {
				rows.push({
					type: 'vendor',
					id: v.id,
					name: v.name,
					ownerName: v.owner_name ?? '(unknown)'
				});
			}
		}
		return rows;
	});

	const activeAssetCount = $derived(assets.filter((a) => a.status === 'active').length);
	const activeVendorCount = $derived(allVendors.filter((v) => v.status === 'active').length);
	const activePersonnelCount = $derived(personnel.filter((p) => p.status === 'active').length);

	// Open risks = identified or treating. Critical residual = residual
	// score >= 12 (e.g. high × critical). Top-of-list is the worst few.
	const openRisks = $derived(
		risks.filter((r) => r.status === 'identified' || r.status === 'treating')
	);
	const criticalRisks = $derived(
		openRisks
			.map((r) => ({ r, score: riskScore(r.residual_likelihood, r.residual_impact) }))
			.filter((x) => x.score >= 12)
			.sort((a, b) => b.score - a.score)
	);
	const activeRiskCount = $derived(openRisks.length);
	const totalRiskCount = $derived(risks.length);

	function fmtRelative(iso?: string | null): string {
		if (!iso) return '—';
		const d = new Date(iso);
		const diff = (Date.now() - d.getTime()) / 1000;
		if (diff < 60) return 'just now';
		if (diff < 3600) return `${Math.floor(diff / 60)}m ago`;
		if (diff < 86400) return `${Math.floor(diff / 3600)}h ago`;
		return `${Math.floor(diff / 86400)}d ago`;
	}
</script>

<svelte:head>
	<title>Dashboard · Touchstone GRC</title>
</svelte:head>

<div class="mx-auto max-w-6xl px-8 py-10">
	<PageHeader
		kicker="Current state"
		title="Dashboard"
		subtitle="The shortest path between this page and an auditor finding their answer. Operational signal — not navigation."
	/>

	{#if loading}
		<div class="mt-8 grid gap-4 sm:grid-cols-3">
			{#each Array(3) as _, i (i)}
				<div class="h-32 animate-pulse rounded-md border border-zinc-800 bg-zinc-900/30"></div>
			{/each}
		</div>
		<div class="mt-8 rounded-md border border-zinc-800">
			<SkeletonRows count={5} columns={['w-40', 'w-64', 'w-16', 'w-16']} />
		</div>
	{:else}
		<!-- Hero: latest scan + compliance posture -->
		<section class="mt-8 grid gap-4 sm:grid-cols-3">
			<div class="rounded-md border border-zinc-800 bg-zinc-900/40 p-5">
				<p class="text-[0.65rem] font-medium uppercase tracking-[0.22em] text-zinc-500">
					Compliance posture
				</p>
				<div class="mt-2 flex items-baseline gap-2">
					<span class="font-serif text-3xl text-zinc-100">{passRatio}<span class="text-zinc-500">%</span></span>
					<span class="text-xs text-zinc-500">pass + N/A · {evidenceCounts.total} controls</span>
				</div>
				<div class="mt-3 flex gap-1.5 text-xs">
					<Pill kind="success">{evidenceCounts.pass} pass</Pill>
					<Pill kind="danger">{evidenceCounts.fail} fail</Pill>
					{#if evidenceCounts.partial > 0}
						<Pill kind="warn">{evidenceCounts.partial} partial</Pill>
					{/if}
				</div>
			</div>

			<div class="rounded-md border border-zinc-800 bg-zinc-900/40 p-5">
				<p class="text-[0.65rem] font-medium uppercase tracking-[0.22em] text-zinc-500">
					Latest scan
				</p>
				{#if latestScan}
					<div class="mt-2 flex items-center gap-2 text-zinc-100">
						<StatusPill status={latestScan.status} />
						<span class="text-xs text-zinc-500">{fmtRelative(latestScan.created_at)}</span>
					</div>
					<a
						href="/scans"
						class="mt-3 inline-flex items-center gap-1 text-xs underline-offset-4 hover:underline"
						style="color: var(--accent);"
					>
						Open scan history <ArrowUpRight class="h-3 w-3" />
					</a>
				{:else}
					<p class="mt-2 text-sm text-zinc-400">No scans yet.</p>
					<a
						href="/scans/new"
						class="mt-3 inline-flex items-center gap-1 text-xs underline-offset-4 hover:underline"
						style="color: var(--accent);"
					>
						Run the first scan <ArrowUpRight class="h-3 w-3" />
					</a>
				{/if}
			</div>

			<div class="rounded-md border border-zinc-800 bg-zinc-900/40 p-5">
				<p class="text-[0.65rem] font-medium uppercase tracking-[0.22em] text-zinc-500">
					Pack coverage
				</p>
				<div class="mt-2 flex items-baseline gap-2">
					<span class="font-serif text-3xl text-zinc-100">{enabledFrameworkCount}</span>
					<span class="text-xs text-zinc-500">of {frameworks.length} packs enabled</span>
				</div>
				<a
					href="/frameworks"
					class="mt-3 inline-flex items-center gap-1 text-xs underline-offset-4 hover:underline"
					style="color: var(--accent);"
				>
					Pack catalog <ArrowUpRight class="h-3 w-3" />
				</a>
			</div>
		</section>

		<!-- What needs attention -->
		<section class="mt-10">
			<h2 class="font-serif text-xl text-zinc-100">What needs attention</h2>
			<p class="mt-1 text-sm text-zinc-500">
				Findings the auditor will surface first — visible here so you see them before they do.
			</p>

			<div class="mt-4 grid gap-4 lg:grid-cols-2">
				<!-- Failing controls -->
				<div class="rounded-md border border-zinc-800 bg-zinc-900/40 p-5">
					<div class="flex items-center justify-between">
						<div class="flex items-center gap-2">
							<ShieldAlert class="h-4 w-4 text-red-400" />
							<h3 class="text-sm font-semibold text-zinc-100">Failing controls</h3>
						</div>
						<Pill kind="danger">{evidenceCounts.fail}</Pill>
					</div>
					{#if failingControls.length === 0}
						<p class="mt-3 text-sm text-zinc-500">
							No failing controls in the latest evidence rollup.
						</p>
					{:else}
						<ul class="mt-3 space-y-2 text-sm">
							{#each failingControls as e (e.id)}
								<li class="flex items-baseline justify-between gap-3">
									<a
										href="/evidence/{e.id}"
										class="min-w-0 truncate text-zinc-100 underline-offset-4 hover:underline"
									>
										<span class="font-mono text-xs text-zinc-500">{e.framework_code}</span>
										<span class="ml-1 font-mono text-xs">{e.control_code}</span>
										<span class="ml-2 text-zinc-300">{e.control_title}</span>
									</a>
								</li>
							{/each}
						</ul>
						{#if evidenceCounts.fail > failingControls.length}
							<a
								href="/evidence?filter=fail"
								class="mt-3 inline-flex items-center gap-1 text-xs underline-offset-4 hover:underline"
								style="color: var(--accent);"
							>
								View all {evidenceCounts.fail} failing controls <ArrowUpRight class="h-3 w-3" />
							</a>
						{/if}
					{/if}
				</div>

				<!-- Vendor reviews -->
				<div class="rounded-md border border-zinc-800 bg-zinc-900/40 p-5">
					<div class="flex items-center justify-between">
						<div class="flex items-center gap-2">
							<Clock class="h-4 w-4 text-amber-400" />
							<h3 class="text-sm font-semibold text-zinc-100">Vendor reviews due</h3>
						</div>
						<Pill kind="warn">{overdueVendors.length}</Pill>
					</div>
					{#if overdueVendors.length === 0}
						<p class="mt-3 text-sm text-zinc-500">Every vendor has a current review on file.</p>
					{:else}
						<ul class="mt-3 space-y-2 text-sm">
							{#each overdueVendors.slice(0, 5) as v (v.id)}
								<li class="flex items-baseline justify-between gap-3">
									<a
										href="/vendors/{v.id}"
										class="min-w-0 truncate text-zinc-100 underline-offset-4 hover:underline"
									>
										{v.name}
										<span class="ml-2 text-xs text-zinc-500">
											{v.next_review_date
												? `due ${new Date(v.next_review_date).toLocaleDateString()}`
												: 'no review scheduled'}
										</span>
									</a>
								</li>
							{/each}
						</ul>
						{#if overdueVendors.length > 5}
							<a
								href="/vendors?review_due=true"
								class="mt-3 inline-flex items-center gap-1 text-xs underline-offset-4 hover:underline"
								style="color: var(--accent);"
							>
								View all {overdueVendors.length} <ArrowUpRight class="h-3 w-3" />
							</a>
						{/if}
					{/if}
				</div>

				<!-- Critical residual risks -->
				{#if criticalRisks.length > 0}
					<div
						class="rounded-md border border-red-900/40 bg-red-950/10 p-5 lg:col-span-2"
					>
						<div class="flex items-center justify-between">
							<div class="flex items-center gap-2">
								<AlertTriangle class="h-4 w-4 text-red-400" />
								<h3 class="text-sm font-semibold text-zinc-100">
									Open risks with residual score ≥ 12
								</h3>
							</div>
							<Pill kind="danger" pulse>{criticalRisks.length}</Pill>
						</div>
						<p class="mt-2 text-xs text-zinc-400">
							These are the risks the auditor will ask about first — open and still rated as high
							exposure after the treatment plan.
						</p>
						<ul class="mt-3 space-y-2 text-sm">
							{#each criticalRisks.slice(0, 5) as item (item.r.id)}
								<li class="flex items-baseline justify-between gap-3">
									<a
										href="/risks/{item.r.id}"
										class="min-w-0 truncate text-zinc-100 underline-offset-4 hover:underline"
									>
										<span class="text-zinc-300">{item.r.title}</span>
										{#if item.r.owner_name}
											<span class="ml-2 text-xs text-zinc-500">· owner {item.r.owner_name}</span>
										{/if}
									</a>
									<Pill kind="danger">{item.score}</Pill>
								</li>
							{/each}
						</ul>
						{#if criticalRisks.length > 5}
							<a
								href="/risks?status=identified"
								class="mt-3 inline-flex items-center gap-1 text-xs underline-offset-4 hover:underline"
								style="color: var(--accent);"
							>
								View all {criticalRisks.length} <ArrowUpRight class="h-3 w-3" />
							</a>
						{/if}
					</div>
				{/if}

				<!-- Orphaned ownership cross-link -->
				{#if orphanedOwnerships.length > 0}
					<div
						class="rounded-md border border-red-900/40 bg-red-950/10 p-5 lg:col-span-2"
					>
						<div class="flex items-center justify-between">
							<div class="flex items-center gap-2">
								<AlertTriangle class="h-4 w-4 text-red-400" />
								<h3 class="text-sm font-semibold text-zinc-100">
									Terminated personnel still own records
								</h3>
							</div>
							<Pill kind="danger" pulse>{orphanedOwnerships.length}</Pill>
						</div>
						<p class="mt-2 text-xs text-zinc-400">
							Auditor-grade finding — assets and vendors that point at a terminated personnel row
							as their owner. Reassign before the next review window closes.
						</p>
						<ul class="mt-3 space-y-1.5 text-sm">
							{#each orphanedOwnerships.slice(0, 6) as row (row.type + row.id)}
								<li class="flex items-baseline gap-3">
									<Pill kind="muted">{row.type}</Pill>
									<a
										href="/{row.type}s/{row.id}"
										class="font-medium text-zinc-100 underline-offset-4 hover:underline"
									>
										{row.name}
									</a>
									<span class="text-xs text-zinc-500">→ owned by {row.ownerName}</span>
								</li>
							{/each}
						</ul>
					</div>
				{/if}

				<!-- Active exceptions -->
				{#if exceptions.length > 0}
					<div class="rounded-md border border-zinc-800 bg-zinc-900/40 p-5 lg:col-span-2">
						<div class="flex items-center justify-between">
							<h3 class="text-sm font-semibold text-zinc-100">Active exceptions</h3>
							<Pill kind="warn">{exceptions.length}</Pill>
						</div>
						<p class="mt-2 text-xs text-zinc-500">
							Acknowledged gaps — auditors will ask about the rationale on every one.
						</p>
						<a
							href="/exceptions"
							class="mt-3 inline-flex items-center gap-1 text-xs underline-offset-4 hover:underline"
							style="color: var(--accent);"
						>
							Review exception ledger <ArrowUpRight class="h-3 w-3" />
						</a>
					</div>
				{/if}
			</div>
		</section>

		<!-- Register footprint -->
		<section class="mt-10">
			<h2 class="font-serif text-xl text-zinc-100">Register footprint</h2>
			<p class="mt-1 text-sm text-zinc-500">
				Phase 7 GRC inventory at a glance. Click into any register for the full ledger.
			</p>

			<div class="mt-4 grid gap-4 sm:grid-cols-2 lg:grid-cols-4">
				<a
					href="/personnel"
					class="rounded-md border border-zinc-800 bg-zinc-900/40 p-5 hover:border-zinc-700"
				>
					<p class="text-[0.65rem] font-medium uppercase tracking-[0.22em] text-zinc-500">
						Personnel
					</p>
					<div class="mt-2 flex items-baseline gap-2">
						<span class="font-serif text-2xl text-zinc-100">{activePersonnelCount}</span>
						<span class="text-xs text-zinc-500">active of {personnel.length}</span>
					</div>
				</a>
				<a
					href="/assets"
					class="rounded-md border border-zinc-800 bg-zinc-900/40 p-5 hover:border-zinc-700"
				>
					<p class="text-[0.65rem] font-medium uppercase tracking-[0.22em] text-zinc-500">
						Assets
					</p>
					<div class="mt-2 flex items-baseline gap-2">
						<span class="font-serif text-2xl text-zinc-100">{activeAssetCount}</span>
						<span class="text-xs text-zinc-500">active of {assets.length}</span>
					</div>
				</a>
				<a
					href="/vendors"
					class="rounded-md border border-zinc-800 bg-zinc-900/40 p-5 hover:border-zinc-700"
				>
					<p class="text-[0.65rem] font-medium uppercase tracking-[0.22em] text-zinc-500">
						Vendors
					</p>
					<div class="mt-2 flex items-baseline gap-2">
						<span class="font-serif text-2xl text-zinc-100">{activeVendorCount}</span>
						<span class="text-xs text-zinc-500">active of {allVendors.length}</span>
					</div>
				</a>
				<a
					href="/risks"
					class="rounded-md border border-zinc-800 bg-zinc-900/40 p-5 hover:border-zinc-700"
				>
					<p class="text-[0.65rem] font-medium uppercase tracking-[0.22em] text-zinc-500">
						Risks
					</p>
					<div class="mt-2 flex items-baseline gap-2">
						<span class="font-serif text-2xl text-zinc-100">{activeRiskCount}</span>
						<span class="text-xs text-zinc-500">open of {totalRiskCount}</span>
					</div>
				</a>
			</div>
		</section>
	{/if}
</div>
