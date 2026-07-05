import { request } from './base';

export interface TrustBlock {
	id: string;
	heading: string;
	body_markdown: string;
	position: number;
	is_public: boolean;
	created_at: string;
	updated_at: string;
}

export interface TrustBlockInput {
	heading: string;
	body_markdown: string;
	position?: number;
	is_public?: boolean;
}

export async function listTrustBlocks(): Promise<TrustBlock[]> {
	const { blocks } = await request<{ blocks: TrustBlock[] }>('/trust-blocks');
	return blocks;
}

export async function getTrustBlock(id: string): Promise<TrustBlock> {
	return request<TrustBlock>(`/trust-blocks/${id}`);
}

export async function createTrustBlock(input: TrustBlockInput): Promise<TrustBlock> {
	return request<TrustBlock>('/trust-blocks', {
		method: 'POST',
		body: JSON.stringify(input)
	});
}

export async function updateTrustBlock(
	id: string,
	input: Partial<TrustBlockInput>
): Promise<TrustBlock> {
	return request<TrustBlock>(`/trust-blocks/${id}`, {
		method: 'PATCH',
		body: JSON.stringify(input)
	});
}

export async function moveTrustBlock(
	id: string,
	direction: 'up' | 'down'
): Promise<TrustBlock> {
	return request<TrustBlock>(`/trust-blocks/${id}/move`, {
		method: 'POST',
		body: JSON.stringify({ direction })
	});
}

export async function deleteTrustBlock(id: string): Promise<void> {
	await request<null>(`/trust-blocks/${id}`, { method: 'DELETE' });
}
