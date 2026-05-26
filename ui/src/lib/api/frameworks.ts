import { request } from './base';

export interface ControlSummary {
	id: string;
	code: string;
	title: string;
	description?: string;
	severity: 'low' | 'medium' | 'high' | 'critical';
	policy_path: string;
}

export interface Framework {
	id: string;
	code: string;
	name: string;
	version?: string;
	controls?: ControlSummary[];
}

export interface OrgFramework {
	code: string;
	name: string;
	enabled_at: string;
}

export async function listFrameworks(): Promise<Framework[]> {
	const { frameworks } = await request<{ frameworks: Framework[] }>('/frameworks');
	return frameworks;
}

export async function getFramework(code: string): Promise<Framework> {
	return request<Framework>(`/frameworks/${code}`);
}

export async function listOrgFrameworks(): Promise<OrgFramework[]> {
	const { frameworks } = await request<{ frameworks: OrgFramework[] }>('/orgs/me/frameworks');
	return frameworks;
}

export async function enableFramework(code: string): Promise<void> {
	await request<null>(`/orgs/me/frameworks/${code}`, { method: 'POST' });
}

export async function disableFramework(code: string): Promise<void> {
	await request<null>(`/orgs/me/frameworks/${code}`, { method: 'DELETE' });
}
