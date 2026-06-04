<script lang="ts">
	import type { Person, PersonStatus } from '$lib/api/personnel';
	import { Loader2 } from 'lucide-svelte';

	interface Props {
		mode: 'create' | 'edit';
		initial?: Person;
		others: Person[];
		submitting: boolean;
		onSubmit: (values: {
			full_name: string;
			email: string;
			role: string;
			department: string;
			manager_id: string | null;
			start_date: string;
			end_date: string | null;
			status: PersonStatus;
			notes: string;
		}) => void | Promise<void>;
		onCancel: () => void;
	}

	let { mode, initial, others, submitting, onSubmit, onCancel }: Props = $props();

	// The form is mounted once per record (the edit page waits for
	// `initial` before rendering us), so seeding state from `initial`
	// on creation is intentional — the local-reference warning is a
	// false positive for this usage.
	// svelte-ignore state_referenced_locally
	let fullName = $state(initial?.full_name ?? '');
	// svelte-ignore state_referenced_locally
	let email = $state(initial?.email ?? '');
	// svelte-ignore state_referenced_locally
	let role = $state(initial?.role ?? '');
	// svelte-ignore state_referenced_locally
	let department = $state(initial?.department ?? '');
	// svelte-ignore state_referenced_locally
	let managerId = $state(initial?.manager_id ?? '');
	// svelte-ignore state_referenced_locally
	let startDate = $state(initial?.start_date?.slice(0, 10) ?? '');
	// svelte-ignore state_referenced_locally
	let endDate = $state(initial?.end_date?.slice(0, 10) ?? '');
	// svelte-ignore state_referenced_locally
	let status = $state<PersonStatus>(initial?.status ?? 'active');
	// svelte-ignore state_referenced_locally
	let notes = $state(initial?.notes ?? '');

	async function handle(e: SubmitEvent) {
		e.preventDefault();
		if (submitting) return;
		await onSubmit({
			full_name: fullName.trim(),
			email: email.trim(),
			role: role.trim(),
			department: department.trim(),
			manager_id: managerId || null,
			start_date: startDate,
			end_date: endDate || null,
			status,
			notes: notes.trim()
		});
	}

	const eligibleManagers = $derived(others.filter((p) => p.id !== initial?.id));
</script>

<form onsubmit={handle} class="space-y-5">
	<div class="grid grid-cols-1 gap-5 sm:grid-cols-2">
		<div>
			<label for="full_name" class="mb-1 block text-sm text-zinc-300">Full name</label>
			<input
				id="full_name"
				type="text"
				required
				bind:value={fullName}
				class="field-input"
				placeholder="Alice Example"
			/>
		</div>
		<div>
			<label for="email" class="mb-1 block text-sm text-zinc-300">Email</label>
			<input
				id="email"
				type="email"
				required
				bind:value={email}
				class="field-input"
				placeholder="alice@example.com"
			/>
		</div>
	</div>

	<div class="grid grid-cols-1 gap-5 sm:grid-cols-2">
		<div>
			<label for="role" class="mb-1 block text-sm text-zinc-300">Role</label>
			<input
				id="role"
				type="text"
				required
				bind:value={role}
				class="field-input"
				placeholder="Senior Engineer"
			/>
		</div>
		<div>
			<label for="department" class="mb-1 block text-sm text-zinc-300">
				Department <span class="text-xs text-zinc-500">(optional)</span>
			</label>
			<input
				id="department"
				type="text"
				bind:value={department}
				class="field-input"
				placeholder="Platform"
			/>
		</div>
	</div>

	<div>
		<label for="manager" class="mb-1 block text-sm text-zinc-300">
			Manager <span class="text-xs text-zinc-500">(optional)</span>
		</label>
		<select id="manager" bind:value={managerId} class="field-input">
			<option value="">— none —</option>
			{#each eligibleManagers as p (p.id)}
				<option value={p.id}>{p.full_name} · {p.role}</option>
			{/each}
		</select>
	</div>

	<div class="grid grid-cols-1 gap-5 sm:grid-cols-3">
		<div>
			<label for="start_date" class="mb-1 block text-sm text-zinc-300">Start date</label>
			<input id="start_date" type="date" required bind:value={startDate} class="field-input" />
		</div>
		<div>
			<label for="end_date" class="mb-1 block text-sm text-zinc-300">
				End date <span class="text-xs text-zinc-500">(required if terminated)</span>
			</label>
			<input id="end_date" type="date" bind:value={endDate} class="field-input" />
		</div>
		<div>
			<label for="status" class="mb-1 block text-sm text-zinc-300">Status</label>
			<select id="status" bind:value={status} class="field-input">
				<option value="active">Active</option>
				<option value="on_leave">On leave</option>
				<option value="terminated">Terminated</option>
			</select>
		</div>
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
			placeholder="Access scope, change history, anything an auditor would want context on."
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
			{mode === 'create' ? 'Add member' : 'Save changes'}
		</button>
		<button
			type="button"
			onclick={onCancel}
			class="text-sm text-zinc-400 hover:text-zinc-200"
		>
			Cancel
		</button>
	</div>
</form>
