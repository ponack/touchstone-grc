// Auth endpoints. Login flow is cookie-based: server sets a SameSite
// session cookie that the browser sends on every subsequent request.

export interface AuthConfig {
	oidc: boolean;
	local: boolean;
}

export interface Me {
	user_id: string;
	org_id: string;
	email: string;
	name: string;
}

export async function getAuthConfig(): Promise<AuthConfig> {
	const res = await fetch('/auth/config', { credentials: 'include' });
	if (!res.ok) throw new Error('Failed to load auth config');
	return res.json();
}

export async function localLogin(email: string, password: string): Promise<void> {
	const res = await fetch('/auth/login', {
		method: 'POST',
		credentials: 'include',
		headers: { 'Content-Type': 'application/json' },
		body: JSON.stringify({ email, password })
	});
	if (!res.ok) {
		const body = await res.json().catch(() => ({ message: 'Login failed' }));
		throw new Error((body as { message?: string }).message ?? 'Login failed');
	}
}

export async function logout(): Promise<void> {
	await fetch('/auth/logout', { method: 'POST', credentials: 'include' });
}

export async function getMe(): Promise<Me> {
	const res = await fetch('/api/v1/me', { credentials: 'include' });
	if (!res.ok) throw new Error('Not authenticated');
	return res.json();
}
