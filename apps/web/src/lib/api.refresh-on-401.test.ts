import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { connectorsApi } from './api';
import { AUTH_REFRESH_KEY, AUTH_TOKEN_KEY, sessionHooks } from './auth-session';

/**
 * The console's own page calls (request() in api.ts) must get the same "expired token -> refresh -> retry" behaviour as authFetch, not just calls made straight
 * through authFetch. Before this was fixed, request() put an Authorization header on every call itself, which made authFetch treat the call as one with the
 * caller's own credentials and never refresh: the login simply died when the 30-minute access token expired.
 */
const json = (status: number, body: unknown = {}) =>
  new Response(JSON.stringify(body), { status, headers: { 'Content-Type': 'application/json' } });

let calls: { url: string; auth: string | null }[];

beforeEach(() => {
  window.localStorage.clear();
  vi.spyOn(sessionHooks, 'redirectToLogin').mockImplementation(() => {});
  calls = [];
});
afterEach(() => {
  vi.unstubAllGlobals();
  vi.restoreAllMocks();
});

describe('a page call made through request()', () => {
  it('refreshes an expired access token and retries, instead of failing with 401', async () => {
    window.localStorage.setItem(AUTH_TOKEN_KEY, 'expired');
    window.localStorage.setItem(AUTH_REFRESH_KEY, 'refresh-1');
    vi.stubGlobal('fetch', async (input: RequestInfo | URL, init?: RequestInit) => {
      const url = typeof input === 'string' ? input : input instanceof URL ? input.href : input.url;
      const auth = new Headers(init?.headers).get('Authorization');
      calls.push({ url, auth });
      if (url.endsWith('/api/v1/auth/refresh')) return json(200, { access_token: 'fresh', refresh_token: 'refresh-2', token_type: 'bearer' });
      if (url.endsWith('/api/v1/auth/me')) return auth === 'Bearer fresh' ? json(200, {}) : json(401);
      if (url.includes('/api/v1/connectors')) return auth === 'Bearer fresh' ? json(200, []) : json(401);
      return json(404);
    });

    const result = await connectorsApi.list();

    expect(result.total).toBe(0);
    expect(window.localStorage.getItem(AUTH_TOKEN_KEY)).toBe('fresh');
    expect(calls.filter((c) => c.url.includes('/api/v1/connectors')).map((c) => c.auth)).toEqual(['Bearer expired', 'Bearer fresh']);
  });
});
