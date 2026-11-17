// The one place that calls fetch. It adds the CSRF header, sets a time limit,
// and changes error responses into ApiError (docs/API.md, sections 2 and 3).

import type { ApiErrorBody } from './types';

export const API_BASE = '/api/v1';
export const DEFAULT_TIMEOUT_MS = 15_000;

export type FetchFn = (input: string, init: RequestInit) => Promise<Response>;

export type QueryValue = string | number | boolean | null | undefined;
export type Query = Record<string, QueryValue>;

export interface ClientOptions {
  fetch: FetchFn;
  /** Returns the CSRF token of the session, or null. */
  getCsrfToken: () => string | null;
  /** Called on 401 `unauthorized`: the session is not valid. */
  onUnauthorized?: (err: ApiError) => void;
  /** Called on 429 with the wait time in seconds. */
  onRateLimited?: (retryAfterSeconds: number, err: ApiError) => void;
  baseUrl?: string;
  timeoutMs?: number;
}

export class ApiError extends Error {
  readonly status: number;
  readonly code: string;
  readonly details: { field: string; message: string }[];
  readonly retryAfterSeconds: number | null;

  constructor(
    status: number,
    code: string,
    message: string,
    details: { field: string; message: string }[] = [],
    retryAfterSeconds: number | null = null,
  ) {
    super(message);
    this.name = 'ApiError';
    this.status = status;
    this.code = code;
    this.details = details;
    this.retryAfterSeconds = retryAfterSeconds;
  }
}

/** Builds "?a=1&b=x". It skips null and undefined values. */
export function buildQuery(query: Query | undefined): string {
  if (!query) return '';
  const params = new URLSearchParams();
  for (const [key, value] of Object.entries(query)) {
    if (value === null || value === undefined) continue;
    params.append(key, String(value));
  }
  const text = params.toString();
  return text ? `?${text}` : '';
}

/**
 * Reads a Retry-After value: delay seconds or an HTTP date.
 * Returns whole seconds (at least 1), or null if the value is bad.
 */
export function parseRetryAfter(value: string | null, nowMs: number): number | null {
  if (value === null) return null;
  const trimmed = value.trim();
  if (/^\d+$/.test(trimmed)) return Math.max(1, Number.parseInt(trimmed, 10));
  const dateMs = Date.parse(trimmed);
  if (Number.isNaN(dateMs)) return null;
  return Math.max(1, Math.ceil((dateMs - nowMs) / 1000));
}

function isErrorBody(value: unknown): value is ApiErrorBody {
  if (typeof value !== 'object' || value === null) return false;
  const v = value as Record<string, unknown>;
  return typeof v.code === 'string' && typeof v.message === 'string';
}

async function readJson(response: Response): Promise<unknown> {
  const text = await response.text();
  if (!text) return null;
  try {
    return JSON.parse(text) as unknown;
  } catch {
    return undefined;
  }
}

export interface RequestOptions {
  query?: Query;
  body?: unknown;
}

export interface Client {
  request<T>(method: string, path: string, options?: RequestOptions): Promise<T>;
  get<T>(path: string, query?: Query): Promise<T>;
  post<T>(path: string, body?: unknown): Promise<T>;
  put<T>(path: string, body: unknown): Promise<T>;
  patch<T>(path: string, body: unknown): Promise<T>;
  del(path: string): Promise<void>;
}

export function createClient(options: ClientOptions): Client {
  const baseUrl = options.baseUrl ?? API_BASE;
  const timeoutMs = options.timeoutMs ?? DEFAULT_TIMEOUT_MS;

  async function request<T>(method: string, path: string, req: RequestOptions = {}): Promise<T> {
    const headers: Record<string, string> = { Accept: 'application/json' };
    if (req.body !== undefined) headers['Content-Type'] = 'application/json';
    if (method !== 'GET' && method !== 'HEAD') {
      const token = options.getCsrfToken();
      if (token) headers['X-CSRF-Token'] = token;
    }

    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), timeoutMs);
    let response: Response;
    try {
      response = await options.fetch(baseUrl + path + buildQuery(req.query), {
        method,
        headers,
        body: req.body === undefined ? undefined : JSON.stringify(req.body),
        credentials: 'same-origin',
        cache: 'no-store',
        signal: controller.signal,
      });
    } catch (cause) {
      if (controller.signal.aborted) {
        throw new ApiError(0, 'timeout', `No answer from the server in ${timeoutMs / 1000} s.`);
      }
      const text = cause instanceof Error ? cause.message : String(cause);
      throw new ApiError(0, 'network', `Cannot connect to the server: ${text}`);
    } finally {
      clearTimeout(timer);
    }

    const data = await readJson(response);
    if (response.ok) return data as T;

    const body = isErrorBody(data)
      ? data
      : { code: `http_${response.status}`, message: `The server returned HTTP ${response.status}.` };
    let retryAfter: number | null = null;
    if (response.status === 429) {
      retryAfter =
        parseRetryAfter(response.headers.get('Retry-After'), Date.now()) ??
        (typeof body.retry_after_seconds === 'number' ? body.retry_after_seconds : null) ??
        60;
    }
    const err = new ApiError(response.status, body.code, body.message, body.details ?? [], retryAfter);
    if (response.status === 401 && err.code === 'unauthorized') options.onUnauthorized?.(err);
    if (response.status === 429 && retryAfter !== null) options.onRateLimited?.(retryAfter, err);
    throw err;
  }

  return {
    request,
    get: (path, query) => request('GET', path, { query }),
    post: (path, body) => request('POST', path, { body }),
    put: (path, body) => request('PUT', path, { body }),
    patch: (path, body) => request('PATCH', path, { body }),
    del: (path) => request<void>('DELETE', path),
  };
}
