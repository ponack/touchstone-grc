<script lang="ts">
	import { goto } from '$app/navigation';
	import { page } from '$app/state';
	import {
		deletePerson,
		getPerson,
		listPersonnel,
		updatePerson,
		type Person
	} from '$lib/api/personnel';
	import { toasts } from '$lib/stores/toasts.svelte';
	import PersonForm from '$lib/components/PersonForm.svelte';
	import { Loader2, Trash2 } from 'lucide-svelte';

	let person = $state<Person | null>(null);
	let others = $state<Person[]>([]);
	let loading = $state(true);
	let submitting = $state(false);
	let deleting = $state(false);

	const id = $derived(page.params.id!);

	$effect(() => {
		(async () => {
			loading = true;
			try {
				const [p, list] = await Promise.all([getPerson(id), listPersonnel()]);
				person = p;
				others = list.filter((o) => o.id !== p.id);
			} catch (e) {
				toasts.error((e as Error).message);
				await goto('/personnel');
			} finally {
				loading = false;
			}
		})();
	});

	async function submit(values: {
		full_name: string;
		email: string;
		role: string;
		department: string;
		manager_id: string | null;
		start_date: string;
		end_date: string | null;
		status: 'active' | 'on_leave' | 'terminated';
		notes: string;
	}) {
		submitting = true;
		try {
			await updatePerson(id, {
				full_name: values.full_name,
				email: values.email,
				role: values.role,
				department: values.department,
				manager_id: values.manager_id,
				start_date: values.start_date,
				end_date: values.end_date,
				status: values.status,
				notes: values.notes
			});
			toasts.success('Personnel record updated.');
			await goto('/personnel');
		} catch (e) {
			toasts.error((e as Error).message);
			submitting = false;
		}
	}

	async function handleDelete() {
		if (!person) return;
		if (!confirm(`Delete ${person.full_name}? This removes the row entirely — the audit log retains the action.`)) return;
		deleting = true;
		try {
			await deletePerson(id);
			toasts.info('Personnel record deleted.');
			await goto('/personnel');
		} catch (e) {
			toasts.error((e as Error).message);
			deleting = false;
		}
	}
</script>

<svelte:head>
	<title>{person?.full_name ?? 'Personnel'} · Touchstone GRC</title>
</svelte:head>

<div class="mx-auto max-w-2xl px-8 py-10">
	<a href="/personnel" class="text-sm text-zinc-500 underline-offset-4 hover:underline">
		← Personnel
	</a>

	{#if loading}
		<div class="mt-8 flex items-center gap-2 text-zinc-500">
			<Loader2 class="h-4 w-4 animate-spin" /> Loading…
		</div>
	{:else if person}
		<div class="mt-2 flex items-start justify-between">
			<div>
				<h1 class="text-2xl font-semibold tracking-tight text-zinc-100">{person.full_name}</h1>
				<p class="mt-1 text-sm text-zinc-400">{person.role} · {person.email}</p>
			</div>
			<button
				type="button"
				onclick={handleDelete}
				disabled={deleting}
				class="flex items-center gap-1.5 rounded-md border border-red-900/50 px-3 py-1.5 text-sm text-red-400 hover:bg-red-950/30 disabled:opacity-50"
			>
				<Trash2 class="h-4 w-4" />
				{deleting ? 'Deleting…' : 'Delete'}
			</button>
		</div>

		<div class="mt-8">
			<PersonForm
				mode="edit"
				initial={person}
				{others}
				{submitting}
				onSubmit={submit}
				onCancel={() => goto('/personnel')}
			/>
		</div>
	{/if}
</div>
