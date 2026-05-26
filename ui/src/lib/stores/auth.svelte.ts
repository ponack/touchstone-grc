// Auth state — the actual session lives in an HttpOnly cookie the
// browser manages for us. This store caches the current Me payload
// in memory + localStorage so the UI can render nav/user info without
// re-fetching on every navigation.

import { getMe, logout as apiLogout, type Me } from '$lib/api/auth';

const STORAGE_KEY = 'touchstone_me';

function loadStored(): Me | null {
	if (typeof localStorage === 'undefined') return null;
	try {
		const raw = localStorage.getItem(STORAGE_KEY);
		return raw ? (JSON.parse(raw) as Me) : null;
	} catch {
		return null;
	}
}

function persist(me: Me | null) {
	if (typeof localStorage === 'undefined') return;
	if (me) localStorage.setItem(STORAGE_KEY, JSON.stringify(me));
	else localStorage.removeItem(STORAGE_KEY);
}

function createAuthStore() {
	let me = $state<Me | null>(loadStored());
	let loading = $state(false);

	return {
		get me() {
			return me;
		},
		get isAuthenticated() {
			return me !== null;
		},
		get loading() {
			return loading;
		},
		set(next: Me) {
			me = next;
			persist(me);
		},
		clear() {
			me = null;
			persist(null);
		},
		async refresh(): Promise<Me | null> {
			loading = true;
			try {
				const fresh = await getMe();
				me = fresh;
				persist(me);
				return me;
			} catch {
				me = null;
				persist(null);
				return null;
			} finally {
				loading = false;
			}
		},
		async logout() {
			await apiLogout();
			me = null;
			persist(null);
		}
	};
}

export const auth = createAuthStore();
