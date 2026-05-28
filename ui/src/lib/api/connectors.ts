import { request } from './base';

export type ConnectorKind = 'aws' | 'azure' | 'github';

export interface Connector {
	id: string;
	kind: ConnectorKind;
	name: string;
	config: Record<string, unknown>;
	schedule_cron?: string | null;
	is_disabled: boolean;
	last_scan_at?: string | null;
	created_at: string;
	updated_at: string;
}

export interface CreateConnectorInput {
	kind: ConnectorKind;
	name: string;
	config: Record<string, unknown>;
	schedule_cron?: string | null;
}

export interface UpdateConnectorInput {
	name?: string;
	config?: Record<string, unknown>;
	schedule_cron?: string | null;
	is_disabled?: boolean;
}

export async function listKinds(): Promise<ConnectorKind[]> {
	const { kinds } = await request<{ kinds: ConnectorKind[] }>('/connectors/kinds');
	return kinds;
}

export async function listConnectors(): Promise<Connector[]> {
	const { connectors } = await request<{ connectors: Connector[] }>('/connectors');
	return connectors;
}

export async function getConnector(id: string): Promise<Connector> {
	return request<Connector>(`/connectors/${id}`);
}

export async function createConnector(input: CreateConnectorInput): Promise<Connector> {
	return request<Connector>('/connectors', {
		method: 'POST',
		body: JSON.stringify(input)
	});
}

export async function updateConnector(id: string, input: UpdateConnectorInput): Promise<Connector> {
	return request<Connector>(`/connectors/${id}`, {
		method: 'PATCH',
		body: JSON.stringify(input)
	});
}

export async function deleteConnector(id: string): Promise<void> {
	await request<null>(`/connectors/${id}`, { method: 'DELETE' });
}
