import { supabase } from './supabaseClient';
import type { ApiResponse, ApiSuccessResponse } from '../types';

const API_BASE_URL = (import.meta.env.VITE_API_BASE_URL || '/api').replace(/\/+$/, '');

export class ApiClientError extends Error {
  readonly status: number;
  readonly code: string;
  readonly details: unknown;

  constructor(message: string, status: number, code: string, details?: unknown) {
    super(message);
    this.name = 'ApiClientError';
    this.status = status;
    this.code = code;
    this.details = details;
  }
}

async function getAccessToken(): Promise<string | null> {
  const { data } = await supabase.auth.getSession();
  return data.session?.access_token ?? null;
}

function buildUrl(path: string): string {
  const normalized = path.startsWith('/') ? path : `/${path}`;
  return `${API_BASE_URL}${normalized}`;
}

async function request<T>(path: string, method: 'GET' | 'POST', body?: unknown): Promise<T> {
  const token = await getAccessToken().catch(() => null);
  const headers: Record<string, string> = { Accept: 'application/json' };
  if (token !== null) {
    headers.Authorization = `Bearer ${token}`;
  }
  if (body !== undefined) {
    headers['Content-Type'] = 'application/json';
  }

  let response: Response;
  try {
    response = await fetch(buildUrl(path), {
      method,
      headers,
      body: body === undefined ? undefined : JSON.stringify(body),
    });
  } catch (error) {
    throw new ApiClientError('Network request failed', 0, 'NETWORK_ERROR', error);
  }

  const payload = (await response.json().catch(() => null)) as ApiResponse<T> | null;

  if (payload === null) {
    return undefined as T;
  }
  if (!response.ok || payload.success === false) {
    if (payload.success === false) {
      throw new ApiClientError(payload.message, response.status, payload.error.code, payload.error.details);
    }
    throw new ApiClientError(`Request failed with status ${response.status}`, response.status, 'HTTP_ERROR');
  }
  return (payload as ApiSuccessResponse<T>).data;
}

export const apiClient = {
  get: <T>(path: string): Promise<T> => request<T>(path, 'GET'),
  post: <T>(path: string, body?: unknown): Promise<T> => request<T>(path, 'POST', body),
};
