import { request } from './base';

export type UpdateCheckFrequency = 'off' | 'daily' | 'weekly' | 'monthly';

export interface VersionStatus {
	current: string;
	latest: string | null;
	latest_url: string | null;
	latest_published_at: string | null;
	last_checked_at: string | null;
	update_available: boolean;
	update_check_frequency: UpdateCheckFrequency;
}

export interface UpdateCheckSettings {
	frequency: UpdateCheckFrequency;
	last_checked_at: string | null;
}

export async function getVersion(): Promise<VersionStatus> {
	return request<VersionStatus>('/version');
}

export async function getUpdateCheckSettings(): Promise<UpdateCheckSettings> {
	return request<UpdateCheckSettings>('/settings/update-check');
}

export async function setUpdateCheckFrequency(
	frequency: UpdateCheckFrequency
): Promise<UpdateCheckSettings> {
	return request<UpdateCheckSettings>('/settings/update-check', {
		method: 'PUT',
		body: JSON.stringify({ frequency })
	});
}

export async function runUpdateCheck(): Promise<UpdateCheckSettings> {
	return request<UpdateCheckSettings>('/settings/update-check/run', {
		method: 'POST'
	});
}
