import { request } from './base';

export type EvidenceStatus = 'pass' | 'fail' | 'partial' | 'not_applicable' | 'error';

export interface EvidenceSummary {
	id: string;
	control_id: string;
	control_code: string;
	control_title: string;
	status: EvidenceStatus;
	collected_at: string;
}

export interface EvidenceFailure {
	resource_type?: string;
	resource_id?: string;
	reason?: string;
	[k: string]: unknown;
}

export interface EvidenceDetail {
	id: string;
	scan_id: string;
	control_id: string;
	control_code: string;
	control_title: string;
	framework_code: string;
	status: EvidenceStatus;
	details: {
		status?: EvidenceStatus;
		message?: string;
		failures?: EvidenceFailure[];
	};
	artifact_key?: string | null;
	collected_at: string;
}

export async function listForScan(scanId: string): Promise<EvidenceSummary[]> {
	const { evidence } = await request<{ evidence: EvidenceSummary[] }>(`/scans/${scanId}/evidence`);
	return evidence;
}

export async function getEvidence(id: string): Promise<EvidenceDetail> {
	return request<EvidenceDetail>(`/evidence/${id}`);
}
