import { request } from './base';

export type ScanStatus = 'queued' | 'running' | 'succeeded' | 'failed' | 'canceled';
export type ScanTrigger = 'scheduled' | 'manual' | 'api';

export interface Scan {
	id: string;
	connector_id: string;
	status: ScanStatus;
	trigger: ScanTrigger;
	triggered_by?: string | null;
	artifact_key?: string | null;
	error_message?: string | null;
	resources_count: number;
	started_at?: string | null;
	finished_at?: string | null;
	created_at: string;
}

export async function listScans(opts: { connectorId?: string; limit?: number } = {}): Promise<Scan[]> {
	const params = new URLSearchParams();
	if (opts.connectorId) params.set('connector_id', opts.connectorId);
	if (opts.limit) params.set('limit', String(opts.limit));
	const qs = params.toString();
	const { scans } = await request<{ scans: Scan[] }>(`/scans${qs ? '?' + qs : ''}`);
	return scans;
}

export async function getScan(id: string): Promise<Scan> {
	return request<Scan>(`/scans/${id}`);
}

export async function triggerScan(connectorId: string): Promise<Scan> {
	return request<Scan>('/scans', {
		method: 'POST',
		body: JSON.stringify({ connector_id: connectorId })
	});
}
