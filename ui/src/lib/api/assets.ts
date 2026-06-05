import { request } from './base';

export type AssetType =
	| 'application'
	| 'service'
	| 'database'
	| 'repository'
	| 'data_store'
	| 'cloud_account'
	| 'infrastructure'
	| 'device'
	| 'other';

export type AssetClassification = 'public' | 'internal' | 'confidential' | 'restricted';

export type AssetEnvironment = 'production' | 'staging' | 'development' | 'other';

export type AssetCriticality = 'low' | 'medium' | 'high' | 'critical';

export type AssetStatus = 'active' | 'planned' | 'decommissioned';

export interface Asset {
	id: string;
	name: string;
	asset_type: AssetType;
	classification?: AssetClassification | null;
	environment: AssetEnvironment;
	criticality: AssetCriticality;
	status: AssetStatus;
	owner_id?: string | null;
	owner_name?: string | null;
	description?: string | null;
	external_ref?: string | null;
	tags: string[];
	notes?: string | null;
	created_at: string;
	updated_at: string;
}

export interface AssetInput {
	name: string;
	asset_type: AssetType;
	// "none" is the sentinel to clear an existing classification on PATCH
	classification?: AssetClassification | 'none' | '';
	environment?: AssetEnvironment;
	criticality?: AssetCriticality;
	status?: AssetStatus;
	owner_id?: string | null;
	description?: string;
	external_ref?: string;
	tags?: string[];
	notes?: string;
}

export async function listAssets(filters?: {
	asset_type?: AssetType;
	status?: AssetStatus;
}): Promise<Asset[]> {
	const params = new URLSearchParams();
	if (filters?.asset_type) params.set('asset_type', filters.asset_type);
	if (filters?.status) params.set('status', filters.status);
	const qs = params.toString();
	const { assets } = await request<{ assets: Asset[] }>(`/assets${qs ? `?${qs}` : ''}`);
	return assets;
}

export async function getAsset(id: string): Promise<Asset> {
	return request<Asset>(`/assets/${id}`);
}

export async function createAsset(input: AssetInput): Promise<Asset> {
	return request<Asset>('/assets', {
		method: 'POST',
		body: JSON.stringify(input)
	});
}

export async function updateAsset(id: string, input: Partial<AssetInput>): Promise<Asset> {
	return request<Asset>(`/assets/${id}`, {
		method: 'PATCH',
		body: JSON.stringify(input)
	});
}

export async function deleteAsset(id: string): Promise<void> {
	await request<null>(`/assets/${id}`, { method: 'DELETE' });
}
