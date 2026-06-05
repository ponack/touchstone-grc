import { request } from './base';

export type VendorType =
	| 'saas'
	| 'paas'
	| 'iaas'
	| 'processor'
	| 'subprocessor'
	| 'hardware'
	| 'professional_services'
	| 'other';

export type VendorCriticality = 'low' | 'medium' | 'high' | 'critical';

export type VendorStatus = 'prospective' | 'active' | 'terminated';

export type VendorClassification = 'public' | 'internal' | 'confidential' | 'restricted';

export interface Vendor {
	id: string;
	name: string;
	vendor_type: VendorType;
	criticality: VendorCriticality;
	status: VendorStatus;
	data_classification?: VendorClassification | null;
	owner_id?: string | null;
	owner_name?: string | null;
	website?: string | null;
	contact_name?: string | null;
	contact_email?: string | null;
	description?: string | null;
	onboarded_date?: string | null;
	offboarded_date?: string | null;
	assurance_report?: string | null;
	last_review_date?: string | null;
	next_review_date?: string | null;
	tags: string[];
	notes?: string | null;
	created_at: string;
	updated_at: string;
}

export interface VendorInput {
	name: string;
	vendor_type: VendorType;
	criticality?: VendorCriticality;
	status?: VendorStatus;
	// "none" is the sentinel to clear an existing classification on PATCH
	data_classification?: VendorClassification | 'none' | '';
	owner_id?: string | null;
	website?: string;
	contact_name?: string;
	contact_email?: string;
	description?: string;
	onboarded_date?: string | null;
	offboarded_date?: string | null;
	assurance_report?: string;
	last_review_date?: string | null;
	next_review_date?: string | null;
	tags?: string[];
	notes?: string;
}

export async function listVendors(filters?: {
	vendor_type?: VendorType;
	status?: VendorStatus;
	review_due?: boolean;
}): Promise<Vendor[]> {
	const params = new URLSearchParams();
	if (filters?.vendor_type) params.set('vendor_type', filters.vendor_type);
	if (filters?.status) params.set('status', filters.status);
	if (filters?.review_due) params.set('review_due', 'true');
	const qs = params.toString();
	const { vendors } = await request<{ vendors: Vendor[] }>(`/vendors${qs ? `?${qs}` : ''}`);
	return vendors;
}

export async function getVendor(id: string): Promise<Vendor> {
	return request<Vendor>(`/vendors/${id}`);
}

export async function createVendor(input: VendorInput): Promise<Vendor> {
	return request<Vendor>('/vendors', {
		method: 'POST',
		body: JSON.stringify(input)
	});
}

export async function updateVendor(id: string, input: Partial<VendorInput>): Promise<Vendor> {
	return request<Vendor>(`/vendors/${id}`, {
		method: 'PATCH',
		body: JSON.stringify(input)
	});
}

export async function deleteVendor(id: string): Promise<void> {
	await request<null>(`/vendors/${id}`, { method: 'DELETE' });
}
