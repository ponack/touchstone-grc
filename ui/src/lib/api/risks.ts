import { request } from './base';

export type RiskCategory =
	| 'operational'
	| 'security'
	| 'privacy'
	| 'compliance'
	| 'financial'
	| 'reputational'
	| 'strategic'
	| 'third_party'
	| 'other';

export type RiskLevel = 'low' | 'medium' | 'high' | 'critical';

export type RiskTreatment = 'accept' | 'mitigate' | 'transfer' | 'avoid';

export type RiskStatus = 'identified' | 'treating' | 'accepted' | 'closed';

export interface Risk {
	id: string;
	title: string;
	description?: string | null;
	risk_category: RiskCategory;
	inherent_likelihood: RiskLevel;
	inherent_impact: RiskLevel;
	residual_likelihood: RiskLevel;
	residual_impact: RiskLevel;
	treatment_strategy: RiskTreatment;
	treatment_plan?: string | null;
	status: RiskStatus;
	owner_id?: string | null;
	owner_name?: string | null;
	related_asset_id?: string | null;
	related_asset_name?: string | null;
	related_vendor_id?: string | null;
	related_vendor_name?: string | null;
	identified_date: string;
	last_review_date?: string | null;
	next_review_date?: string | null;
	closed_date?: string | null;
	tags: string[];
	notes?: string | null;
	created_at: string;
	updated_at: string;
}

export interface RiskInput {
	title: string;
	description?: string;
	risk_category?: RiskCategory;
	inherent_likelihood?: RiskLevel;
	inherent_impact?: RiskLevel;
	residual_likelihood?: RiskLevel;
	residual_impact?: RiskLevel;
	treatment_strategy?: RiskTreatment;
	treatment_plan?: string;
	status?: RiskStatus;
	owner_id?: string | null;
	related_asset_id?: string | null;
	related_vendor_id?: string | null;
	identified_date?: string | null;
	last_review_date?: string | null;
	next_review_date?: string | null;
	closed_date?: string | null;
	tags?: string[];
	notes?: string;
}

// Numeric score derived client-side from the four-tier scale. Stays
// consistent with the backend's "compute, don't store" choice.
export function scoreOf(level: RiskLevel): number {
	switch (level) {
		case 'low':
			return 1;
		case 'medium':
			return 2;
		case 'high':
			return 3;
		case 'critical':
			return 4;
	}
}

export function riskScore(l: RiskLevel, i: RiskLevel): number {
	return scoreOf(l) * scoreOf(i);
}

export async function listRisks(filters?: {
	category?: RiskCategory;
	status?: RiskStatus;
	review_due?: boolean;
}): Promise<Risk[]> {
	const params = new URLSearchParams();
	if (filters?.category) params.set('category', filters.category);
	if (filters?.status) params.set('status', filters.status);
	if (filters?.review_due) params.set('review_due', 'true');
	const qs = params.toString();
	const { risks } = await request<{ risks: Risk[] }>(`/risks${qs ? `?${qs}` : ''}`);
	return risks;
}

export async function getRisk(id: string): Promise<Risk> {
	return request<Risk>(`/risks/${id}`);
}

export async function createRisk(input: RiskInput): Promise<Risk> {
	return request<Risk>('/risks', {
		method: 'POST',
		body: JSON.stringify(input)
	});
}

export async function updateRisk(id: string, input: Partial<RiskInput>): Promise<Risk> {
	return request<Risk>(`/risks/${id}`, {
		method: 'PATCH',
		body: JSON.stringify(input)
	});
}

export async function deleteRisk(id: string): Promise<void> {
	await request<null>(`/risks/${id}`, { method: 'DELETE' });
}
