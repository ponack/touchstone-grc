import { request } from './base';

export type PersonStatus = 'active' | 'on_leave' | 'terminated';

export interface Person {
	id: string;
	full_name: string;
	email: string;
	role: string;
	department?: string | null;
	manager_id?: string | null;
	start_date: string;
	end_date?: string | null;
	status: PersonStatus;
	notes?: string | null;
	created_at: string;
	updated_at: string;
}

export interface PersonInput {
	full_name: string;
	email: string;
	role: string;
	department?: string;
	manager_id?: string | null;
	start_date?: string | null;
	end_date?: string | null;
	status?: PersonStatus;
	notes?: string;
}

export async function listPersonnel(status?: PersonStatus): Promise<Person[]> {
	const qs = status ? `?status=${status}` : '';
	const { personnel } = await request<{ personnel: Person[] }>(`/personnel${qs}`);
	return personnel;
}

export async function getPerson(id: string): Promise<Person> {
	return request<Person>(`/personnel/${id}`);
}

export async function createPerson(input: PersonInput): Promise<Person> {
	return request<Person>('/personnel', {
		method: 'POST',
		body: JSON.stringify(input)
	});
}

export async function updatePerson(id: string, input: Partial<PersonInput>): Promise<Person> {
	return request<Person>(`/personnel/${id}`, {
		method: 'PATCH',
		body: JSON.stringify(input)
	});
}

export async function deletePerson(id: string): Promise<void> {
	await request<null>(`/personnel/${id}`, { method: 'DELETE' });
}
