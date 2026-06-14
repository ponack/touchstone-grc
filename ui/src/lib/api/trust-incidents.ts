import { request } from './base';

export type IncidentStatus = 'ongoing' | 'monitoring' | 'resolved';

export type IncidentSeverity = 'low' | 'medium' | 'high' | 'critical';

export interface TrustIncident {
	id: string;
	title: string;
	status: IncidentStatus;
	severity: IncidentSeverity;
	occurred_at: string;
	resolved_at?: string | null;
	summary?: string | null;
	public_response?: string | null;
	is_public: boolean;
	created_at: string;
	updated_at: string;
}

export interface TrustIncidentInput {
	title: string;
	status?: IncidentStatus;
	severity?: IncidentSeverity;
	occurred_at?: string | null;
	resolved_at?: string | null;
	summary?: string;
	public_response?: string;
	is_public?: boolean;
}

export async function listTrustIncidents(filter?: {
	status?: IncidentStatus;
}): Promise<TrustIncident[]> {
	const qs = filter?.status ? `?status=${filter.status}` : '';
	const { incidents } = await request<{ incidents: TrustIncident[] }>(`/trust-incidents${qs}`);
	return incidents;
}

export async function getTrustIncident(id: string): Promise<TrustIncident> {
	return request<TrustIncident>(`/trust-incidents/${id}`);
}

export async function createTrustIncident(input: TrustIncidentInput): Promise<TrustIncident> {
	return request<TrustIncident>('/trust-incidents', {
		method: 'POST',
		body: JSON.stringify(input)
	});
}

export async function updateTrustIncident(
	id: string,
	input: Partial<TrustIncidentInput>
): Promise<TrustIncident> {
	return request<TrustIncident>(`/trust-incidents/${id}`, {
		method: 'PATCH',
		body: JSON.stringify(input)
	});
}

export async function deleteTrustIncident(id: string): Promise<void> {
	await request<null>(`/trust-incidents/${id}`, { method: 'DELETE' });
}
