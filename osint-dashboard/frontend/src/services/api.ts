import type { AnalyzeResponse, StoredResult } from '../types/osint';

const API_BASE_URL = import.meta.env.VITE_API_BASE_URL ?? 'http://127.0.0.1:8000';

export async function analyzeQuery(query: string): Promise<AnalyzeResponse> {
  const response = await fetch(`${API_BASE_URL}/analyze`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ query }),
  });

  if (!response.ok) {
    const errorBody = await response.json().catch(() => ({}));
    throw new Error(errorBody.detail ?? 'Failed to analyze target.');
  }

  return response.json() as Promise<AnalyzeResponse>;
}

export async function getResultById(id: string): Promise<StoredResult> {
  const response = await fetch(`${API_BASE_URL}/results/${id}`);

  if (!response.ok) {
    const errorBody = await response.json().catch(() => ({}));
    throw new Error(errorBody.detail ?? 'Failed to fetch results.');
  }

  return response.json() as Promise<StoredResult>;
}
