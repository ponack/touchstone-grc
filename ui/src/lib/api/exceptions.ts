import { request } from './base';

export interface Exception {
	id: string;
	control_id: string;
	control_code: string;
	control_title: string;
	resource_key?: string | null;
	reason: string;
	granted_by: string;
	granted_at: string;
	expires_at?: string | null;
	revoked_at?: string | null;
	revoked_by?: string | null;
}

export interface GrantExceptionInput {
	control_id: string;
	reason: string;
	resource_key?: string;
	expires_at?: string | null;
}

export async function listExceptions(includeRevoked = false): Promise<Exception[]> {
	const qs = includeRevoked ? '?include_revoked=true' : '';
	const { exceptions } = await request<{ exceptions: Exception[] }>(`/exceptions${qs}`);
	return exceptions;
}

export async function grantException(input: GrantExceptionInput): Promise<Exception> {
	return request<Exception>('/exceptions', {
		method: 'POST',
		body: JSON.stringify(input)
	});
}

export async function revokeException(id: string): Promise<Exception> {
	return request<Exception>(`/exceptions/${id}/revoke`, { method: 'POST' });
}
