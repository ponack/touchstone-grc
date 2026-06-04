<script lang="ts">
	import { goto } from '$app/navigation';
	import { createPerson, listPersonnel, type Person } from '$lib/api/personnel';
	import { toasts } from '$lib/stores/toasts.svelte';
	import PersonForm from '$lib/components/PersonForm.svelte';

	let others = $state<Person[]>([]);
	let submitting = $state(false);

	$effect(() => {
		(async () => {
			try {
				others = await listPersonnel();
			} catch (e) {
				toasts.error((e as Error).message);
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
			await createPerson({
				full_name: values.full_name,
				email: values.email,
				role: values.role,
				department: values.department || undefined,
				manager_id: values.manager_id,
				start_date: values.start_date,
				end_date: values.end_date,
				status: values.status,
				notes: values.notes || undefined
			});
			toasts.success('Personnel record added.');
			await goto('/personnel');
		} catch (e) {
			toasts.error((e as Error).message);
			submitting = false;
		}
	}
</script>

<svelte:head>
	<title>Add personnel · Touchstone GRC</title>
</svelte:head>

<div class="mx-auto max-w-2xl px-8 py-10">
	<a href="/personnel" class="text-sm text-zinc-500 underline-offset-4 hover:underline">
		← Personnel
	</a>
	<h1 class="mt-2 text-2xl font-semibold tracking-tight text-zinc-100">Add personnel</h1>
	<p class="mt-1 text-sm text-zinc-400">
		One record per workforce member. Start / end dates anchor the access-review window.
	</p>

	<div class="mt-8">
		<PersonForm
			mode="create"
			{others}
			{submitting}
			onSubmit={submit}
			onCancel={() => goto('/personnel')}
		/>
	</div>
</div>
