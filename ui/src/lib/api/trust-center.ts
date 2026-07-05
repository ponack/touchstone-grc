import { request } from './base';

export interface TrustCenter {
	org_id: string;
	org_slug: string;
	slug: string;
	is_public: boolean;
	display_name?: string | null;
	tagline?: string | null;
	primary_color?: string | null;
	logo_url?: string | null;
	contact_email?: string | null;
	contact_url?: string | null;
	show_frameworks: boolean;
	show_subprocessors: boolean;
	show_incidents: boolean;
	show_blocks: boolean;
	show_contact: boolean;
	updated_at: string;
}

export interface TrustCenterInput {
	slug?: string;
	is_public?: boolean;
	display_name?: string;
	tagline?: string;
	primary_color?: string;
	logo_url?: string;
	contact_email?: string;
	contact_url?: string;
	show_frameworks?: boolean;
	show_subprocessors?: boolean;
	show_incidents?: boolean;
	show_blocks?: boolean;
	show_contact?: boolean;
}

export async function getTrustCenter(): Promise<TrustCenter> {
	return request<TrustCenter>('/trust-center');
}

export async function updateTrustCenter(input: TrustCenterInput): Promise<TrustCenter> {
	return request<TrustCenter>('/trust-center', {
		method: 'PATCH',
		body: JSON.stringify(input)
	});
}
