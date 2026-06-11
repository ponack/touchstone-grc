// Unauthenticated client for the public Trust Center endpoint.
// Distinct from $lib/api/base — no credentials, no auto-redirect to
// /login on 401. A 404 here just means "no public trust center
// at this slug" (which intentionally covers both "slug doesn't
// exist" and "exists but is_public=false").

export interface PublicFramework {
	code: string;
	name: string;
	version?: string;
}

export interface PublicSubprocessor {
	name: string;
	vendor_type: string;
	assurance_report?: string;
	website?: string;
}

export interface PublicTrustCenter {
	slug: string;
	display_name: string;
	tagline?: string | null;
	primary_color?: string | null;
	logo_url?: string | null;
	contact_email?: string | null;
	contact_url?: string | null;
	show_frameworks: boolean;
	show_subprocessors: boolean;
	show_contact: boolean;
	updated_at: string;
	frameworks?: PublicFramework[];
	subprocessors?: PublicSubprocessor[];
}

export class PublicTrustNotFound extends Error {
	constructor() {
		super('Trust center not found');
	}
}

export async function getPublicTrust(slug: string): Promise<PublicTrustCenter> {
	const res = await fetch(`/public/trust/${encodeURIComponent(slug)}`);
	if (res.status === 404) throw new PublicTrustNotFound();
	if (!res.ok) {
		const body = await res.json().catch(() => ({ message: res.statusText }));
		throw new Error((body as { message?: string }).message ?? `Request failed (${res.status})`);
	}
	return res.json() as Promise<PublicTrustCenter>;
}
