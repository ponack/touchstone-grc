export type ToastKind = 'success' | 'error' | 'info';

export interface Toast {
	id: number;
	kind: ToastKind;
	message: string;
}

let nextID = 1;
const DEFAULT_TTL_MS = 4000;

function createToastStore() {
	let toasts = $state<Toast[]>([]);

	function push(kind: ToastKind, message: string, ttlMs = DEFAULT_TTL_MS) {
		const id = nextID++;
		toasts = [...toasts, { id, kind, message }];
		if (ttlMs > 0) {
			setTimeout(() => dismiss(id), ttlMs);
		}
	}

	function dismiss(id: number) {
		toasts = toasts.filter((t) => t.id !== id);
	}

	return {
		get all() {
			return toasts;
		},
		success: (msg: string) => push('success', msg),
		error: (msg: string) => push('error', msg, 6000),
		info: (msg: string) => push('info', msg),
		dismiss
	};
}

export const toasts = createToastStore();
