import { describe, expect, it, vi } from 'vitest';
import { ApiError, buildQuery, createClient, parseRetryAfter, type FetchFn } from './client';

function jsonResponse(status: number, body: unknown, headers: Record<string, string> = {}): Response {
  return new Response(body === undefined ? null : JSON.stringify(body), {
    status,
    headers: { 'Content-Type': 'application/json', ...headers },
  });
}

function setup(response: Response | (() => Promise<Response>), csrf: string | null = 'tok-1') {
  const calls: { url: string; init: RequestInit }[] = [];
  const fetchFn: FetchFn = async (url, init) => {
    calls.push({ url, init });
    return typeof response === 'function' ? response() : response.clone();
  };
  const onUnauthorized = vi.fn();
  const onRateLimited = vi.fn();
  const client = createClient({ fetch: fetchFn, getCsrfToken: () => csrf, onUnauthorized, onRateLimited });
  return { client, calls, onUnauthorized, onRateLimited };
}

function header(init: RequestInit, name: string): string | undefined {
  return (init.headers as Record<string, string>)[name];
}

describe('buildQuery', () => {
  it('skips null and undefined values', () => {
    expect(buildQuery({ range: '24h', client: undefined, q: null, limit: 10 })).toBe('?range=24h&limit=10');
  });
  it('returns an empty string for no values', () => {
    expect(buildQuery({})).toBe('');
    expect(buildQuery(undefined)).toBe('');
  });
  it('encodes values', () => {
    expect(buildQuery({ key: '02:00:00:00:00:01' })).toBe('?key=02%3A00%3A00%3A00%3A00%3A01');
  });
});

describe('parseRetryAfter', () => {
  it('reads delay seconds', () => {
    expect(parseRetryAfter('30', 0)).toBe(30);
    expect(parseRetryAfter(' 0 ', 0)).toBe(1);
  });
  it('reads an HTTP date', () => {
    const now = Date.parse('2026-11-17T08:00:00Z');
    expect(parseRetryAfter('Tue, 17 Nov 2026 08:01:30 GMT', now)).toBe(90);
  });
  it('returns null for a bad value', () => {
    expect(parseRetryAfter('soon', 0)).toBeNull();
    expect(parseRetryAfter(null, 0)).toBeNull();
  });
});

describe('createClient', () => {
  it('sends GET without a CSRF header and with the base path', async () => {
    const { client, calls } = setup(jsonResponse(200, { ok: 1 }));
    const data = await client.get<{ ok: number }>('/stats/summary', { range: '7d' });
    expect(data).toEqual({ ok: 1 });
    expect(calls[0]?.url).toBe('/api/v1/stats/summary?range=7d');
    expect(calls[0]?.init.method).toBe('GET');
    expect(header(calls[0]!.init, 'X-CSRF-Token')).toBeUndefined();
    expect(calls[0]?.init.credentials).toBe('same-origin');
  });

  it.each(['POST', 'PUT', 'PATCH', 'DELETE'])('sends the CSRF header on %s', async (method) => {
    const { client, calls } = setup(jsonResponse(200, {}));
    await client.request(method, '/lists/1', method === 'DELETE' ? {} : { body: { enabled: false } });
    expect(header(calls[0]!.init, 'X-CSRF-Token')).toBe('tok-1');
  });

  it('sends a JSON body with a content type', async () => {
    const { client, calls } = setup(jsonResponse(201, { id: 3 }));
    await client.post('/groups', { name: 'Kids' });
    expect(calls[0]?.init.body).toBe('{"name":"Kids"}');
    expect(header(calls[0]!.init, 'Content-Type')).toBe('application/json');
  });

  it('sends no CSRF header when there is no token (login)', async () => {
    const { client, calls } = setup(jsonResponse(200, {}), null);
    await client.post('/auth/login', { password: 'x' });
    expect(header(calls[0]!.init, 'X-CSRF-Token')).toBeUndefined();
  });

  it('accepts 204 with no body', async () => {
    const { client } = setup(new Response(null, { status: 204 }));
    await expect(client.del('/rules/1')).resolves.toBeNull();
  });

  it('throws ApiError with the server code and details', async () => {
    const body = {
      code: 'validation_failed',
      message: 'The request has invalid fields.',
      details: [{ field: 'url', message: 'Use an http or https URL.' }],
    };
    const { client } = setup(jsonResponse(422, body));
    const err = await client.post('/lists', { url: 'ftp://x' }).catch((e: unknown) => e);
    expect(err).toBeInstanceOf(ApiError);
    const e = err as ApiError;
    expect(e.status).toBe(422);
    expect(e.code).toBe('validation_failed');
    expect(e.details).toEqual(body.details);
  });

  it('calls onUnauthorized on 401 unauthorized', async () => {
    const { client, onUnauthorized } = setup(jsonResponse(401, { code: 'unauthorized', message: 'Log in.' }));
    await expect(client.get('/lists')).rejects.toMatchObject({ status: 401, code: 'unauthorized' });
    expect(onUnauthorized).toHaveBeenCalledTimes(1);
  });

  it('does not call onUnauthorized for a failed login', async () => {
    const { client, onUnauthorized } = setup(
      jsonResponse(401, { code: 'invalid_credentials', message: 'Wrong password.' }),
    );
    await expect(client.post('/auth/login', {})).rejects.toMatchObject({ code: 'invalid_credentials' });
    expect(onUnauthorized).not.toHaveBeenCalled();
  });

  it('reads the wait time on 429 from Retry-After', async () => {
    const { client, onRateLimited } = setup(
      jsonResponse(429, { code: 'rate_limited', message: 'Wait.', retry_after_seconds: 5 }, { 'Retry-After': '42' }),
    );
    const err = (await client.post('/auth/login', {}).catch((e: unknown) => e)) as ApiError;
    expect(err.retryAfterSeconds).toBe(42);
    expect(onRateLimited).toHaveBeenCalledWith(42, err);
  });

  it('uses retry_after_seconds on 429 when the header is missing', async () => {
    const { client } = setup(jsonResponse(429, { code: 'rate_limited', message: 'Wait.', retry_after_seconds: 7 }));
    await expect(client.post('/auth/login', {})).rejects.toMatchObject({ retryAfterSeconds: 7 });
  });

  it('makes an error from a body that is not JSON', async () => {
    const { client } = setup(new Response('<html>bad gateway</html>', { status: 502 }));
    await expect(client.get('/system')).rejects.toMatchObject({ status: 502, code: 'http_502' });
  });

  it('makes a network error when fetch fails', async () => {
    const { client } = setup(() => Promise.reject(new TypeError('Failed to fetch')));
    await expect(client.get('/system')).rejects.toMatchObject({ status: 0, code: 'network' });
  });

  it('stops a request after the time limit', async () => {
    vi.useFakeTimers();
    try {
      const fetchFn: FetchFn = (_url, init) =>
        new Promise((_resolve, reject) => {
          init.signal?.addEventListener('abort', () => reject(new DOMException('aborted', 'AbortError')));
        });
      const client = createClient({ fetch: fetchFn, getCsrfToken: () => null, timeoutMs: 1000 });
      const pending = client.get('/system').catch((e: unknown) => e);
      await vi.advanceTimersByTimeAsync(1001);
      await expect(pending).resolves.toMatchObject({ code: 'timeout' });
    } finally {
      vi.useRealTimers();
    }
  });
});
