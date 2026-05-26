// Thin client wrapper around fetch. Touchstone uses an HttpOnly
// session cookie (set by POST /auth/login), so requests just need
// credentials: 'include' — no Authorization header to manage.

import { goto } from '$app/navigation';

const BASE = '/api/v1';

export class ApiError extends Error {
	constructor(
		public status: number,
		public body: unknown,
		message: string
	) {
		super(message);
	}
}

export async function request<T>(path: string, init: RequestInit = {}): Promise<T> {
	const headers: Record<string, string> = {
		'Content-Type': 'application/json',
		...(init.headers as Record<string, string>)
	};

	const res = await fetch(BASE + path, {
		...init,
		headers,
		credentials: 'include'
	});

	if (res.status === 401) {
		// Don't try to keep state — just send the user to login. After login
		// they land back at the current page via the `next` query param.
		if (typeof window !== 'undefined' && !window.location.pathname.startsWith('/login')) {
			await goto(`/login?next=${encodeURIComponent(window.location.pathname)}`);
		}
		throw new ApiError(401, null, 'Unauthorized');
	}

	if (!res.ok) {
		const body = await res.json().catch(() => ({ error: res.statusText }));
		const msg = (body as { message?: string; error?: string }).message
			?? (body as { error?: string }).error
			?? `Request failed (${res.status})`;
		throw new ApiError(res.status, body, msg);
	}

	if (res.status === 204) return null as T;
	return res.json() as Promise<T>;
}
