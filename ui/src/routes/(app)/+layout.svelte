<script lang="ts">
	import { goto } from '$app/navigation';
	import { page } from '$app/state';
	import { auth } from '$lib/stores/auth.svelte';
	import { toasts } from '$lib/stores/toasts.svelte';
	import {
		LayoutDashboard,
		Cable,
		ScanLine,
		FileCheck,
		BookOpen,
		ShieldOff,
		LogOut
	} from 'lucide-svelte';

	let { children } = $props();
	let ready = $state(false);

	$effect(() => {
		(async () => {
			const me = await auth.refresh();
			if (!me) {
				await goto(`/login?next=${encodeURIComponent(page.url.pathname)}`);
				return;
			}
			ready = true;
		})();
	});

	async function handleLogout() {
		try {
			await auth.logout();
			toasts.info('Signed out.');
		} finally {
			await goto('/login');
		}
	}

	const navItems = [
		{ href: '/', label: 'Dashboard', icon: LayoutDashboard, exact: true },
		{ href: '/connectors', label: 'Connectors', icon: Cable },
		{ href: '/scans', label: 'Scans', icon: ScanLine },
		{ href: '/evidence', label: 'Evidence', icon: FileCheck },
		{ href: '/frameworks', label: 'Frameworks', icon: BookOpen },
		{ href: '/exceptions', label: 'Exceptions', icon: ShieldOff }
	];

	function isActive(href: string, exact = false): boolean {
		const path = page.url.pathname;
		return exact ? path === href : path === href || path.startsWith(href + '/');
	}
</script>

{#if !ready}
	<div class="flex min-h-screen items-center justify-center text-zinc-500">Loading…</div>
{:else}
	<div class="flex min-h-screen">
		<aside class="flex w-60 flex-col border-r border-zinc-800 bg-zinc-950/60">
			<div class="flex items-center gap-2 px-4 py-5">
				<img src="/logomark-dark.png" alt="" class="h-7 w-7" width="28" height="28" />
				<span class="text-sm font-semibold tracking-tight text-zinc-100">Touchstone GRC</span>
			</div>

			<nav class="flex-1 px-2 py-2">
				<ul class="space-y-1">
					{#each navItems as item (item.href)}
						{@const active = isActive(item.href, item.exact)}
						<li>
							<a
								href={item.href}
								class="flex items-center gap-2.5 rounded-md px-2.5 py-1.5 text-sm {active
									? 'text-zinc-100'
									: 'text-zinc-400 hover:text-zinc-200'}"
								style={active ? 'background-color: var(--accent-muted);' : ''}
							>
								<item.icon class="h-4 w-4" />
								{item.label}
							</a>
						</li>
					{/each}
				</ul>
			</nav>

			<div class="border-t border-zinc-800 px-3 py-3">
				<div class="mb-2 px-1 text-xs text-zinc-500">
					{auth.me?.email}
				</div>
				<button
					type="button"
					onclick={handleLogout}
					class="flex w-full items-center gap-2 rounded-md px-2 py-1.5 text-sm text-zinc-400 hover:text-zinc-200"
				>
					<LogOut class="h-4 w-4" />
					Sign out
				</button>
			</div>
		</aside>

		<main class="flex-1 overflow-auto">
			{@render children?.()}
		</main>
	</div>
{/if}
