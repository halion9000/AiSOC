import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import {
  AUTH_REFRESH_KEY,
  AUTH_TOKEN_KEY,
  AUTH_USER_KEY,
  authFetch,
  sessionHooks,
} from './auth-session';

type Handler = (url: string, init: RequestInit | undefined) => Response | Promise<Response> | 'network-error';
let calls: { url: string; auth: string | null; method: string }[];
let redirect: ReturnType<typeof vi.spyOn>;

function install(handler: Handler) {
  calls = [];
  vi.stubGlobal('fetch', async (input: RequestInfo | URL, init?: RequestInit) => {
    const url = typeof input === 'string' ? input : input instanceof URL ? input.href : input.url;
    const headers = new Headers(init?.headers);
    calls.push({ url, auth: headers.get('Authorization'), method: init?.method ?? 'GET' });
    const out = await handler(url, init);
    if (out === 'network-error') throw new TypeError('network down');
    return out;
  });
}
const json = (status: number, body: unknown = {}) =>
  new Response(JSON.stringify(body), { status, headers: { 'Content-Type': 'application/json' } });
const tokens = (a: string, r: string) => ({ access_token: a, refresh_token: r, token_type: 'bearer' });
const onlyPath = (p: string) => calls.filter((c) => c.url === p);

beforeEach(() => {
  window.localStorage.clear();
  redirect = vi.spyOn(sessionHooks, 'redirectToLogin').mockImplementation(() => {});
  window.history.replaceState({}, '', '/cases?tab=open');
});
afterEach(() => {
  vi.unstubAllGlobals();
  vi.restoreAllMocks();
});

describe('authFetch: attaching the token', () => {
  it('adds Bearer to same-origin /api requests', async () => {
    window.localStorage.setItem(AUTH_TOKEN_KEY, 'tok1');
    install(() => json(200));
    await authFetch('/api/v1/cases');
    expect(calls[0].auth).toBe('Bearer tok1');
  });
  it("never overrides a caller's own Authorization", async () => {
    window.localStorage.setItem(AUTH_TOKEN_KEY, 'tok1');
    install(() => json(200));
    await authFetch('/api/v1/cases', { headers: { Authorization: 'Bearer mine' } });
    expect(calls[0].auth).toBe('Bearer mine');
  });
  it('sends nothing when there is no token (development)', async () => {
    install(() => json(200));
    await authFetch('/api/v1/cases');
    expect(calls[0].auth).toBeNull();
  });
  it('with no token the call is passed through completely untouched (development unchanged)', async () => {
    let seen: RequestInit | undefined;
    install((_url, init) => { seen = init; return json(200); });
    const init: RequestInit = { method: 'POST', headers: { 'Content-Type': 'application/json' }, credentials: 'include', body: '{}' };
    await authFetch('/api/v1/marketplace/install', init);
    expect(seen).toBe(init); // the very same object, not a rebuilt copy
  });
  it('never sends the token to another origin or a non-API path', async () => {
    window.localStorage.setItem(AUTH_TOKEN_KEY, 'tok1');
    install(() => json(200));
    await authFetch('https://evil.example/api/v1/cases');
    await authFetch('/_next/static/chunk.js');
    expect(calls.every((c) => c.auth === null)).toBe(true);
  });
});

describe('authFetch: a 401', () => {
  it('refreshed session: refreshes once, retries once with the NEW token, returns the retry', async () => {
    window.localStorage.setItem(AUTH_TOKEN_KEY, 'old');
    window.localStorage.setItem(AUTH_REFRESH_KEY, 'r1');
    let cases = 0;
    install((url) => {
      if (url === '/api/v1/auth/refresh') return json(200, tokens('new', 'r2'));
      if (url === '/api/v1/auth/me') return json(200);
      return ++cases === 1 ? json(401) : json(200, { ok: true });
    });
    const res = await authFetch('/api/v1/cases');
    expect(res.status).toBe(200);
    expect(onlyPath('/api/v1/auth/refresh')).toHaveLength(1);
    expect(onlyPath('/api/v1/cases').map((c) => c.auth)).toEqual(['Bearer old', 'Bearer new']);
    expect(window.localStorage.getItem(AUTH_TOKEN_KEY)).toBe('new');
    expect(window.localStorage.getItem(AUTH_REFRESH_KEY)).toBe('r2');
    expect(redirect).not.toHaveBeenCalled();
  });

  it('five requests expire at the same moment: ONE refresh, all five succeed', async () => {
    window.localStorage.setItem(AUTH_TOKEN_KEY, 'old');
    window.localStorage.setItem(AUTH_REFRESH_KEY, 'r1');
    install(async (url, init) => {
      if (url === '/api/v1/auth/refresh') { await new Promise((r) => setTimeout(r, 20)); return json(200, tokens('new', 'r2')); }
      if (url === '/api/v1/auth/me') return json(200);
      return new Headers(init?.headers).get('Authorization') === 'Bearer new' ? json(200) : json(401);
    });
    const all = await Promise.all([1, 2, 3, 4, 5].map((i) => authFetch(`/api/v1/things/${i}`)));
    expect(all.map((r) => r.status)).toEqual([200, 200, 200, 200, 200]);
    expect(onlyPath('/api/v1/auth/refresh')).toHaveLength(1);
  });

  it('dead session (refresh token rejected, /auth/me says 401): clears the session and goes to login with ?next', async () => {
    window.localStorage.setItem(AUTH_TOKEN_KEY, 'old');
    window.localStorage.setItem(AUTH_REFRESH_KEY, 'r1');
    window.localStorage.setItem(AUTH_USER_KEY, '{"id":"u"}');
    install((url) => json(401));
    const res = await authFetch('/api/v1/cases');
    expect(res.status).toBe(401);
    expect(window.localStorage.getItem(AUTH_TOKEN_KEY)).toBeNull();
    expect(window.localStorage.getItem(AUTH_REFRESH_KEY)).toBeNull();
    expect(window.localStorage.getItem(AUTH_USER_KEY)).toBeNull();
    expect(redirect).toHaveBeenCalledTimes(1);
    expect(redirect).toHaveBeenCalledWith('/cases?tab=open');
  });

  it('never logged in (production, no token): one /auth/me check, then login', async () => {
    install(() => json(401));
    await authFetch('/api/v1/cases');
    expect(onlyPath('/api/v1/auth/refresh')).toHaveLength(0);
    expect(redirect).toHaveBeenCalledTimes(1);
  });

  it('an UNRELATED 401 (upstream passthrough) does not log you out', async () => {
    window.localStorage.setItem(AUTH_TOKEN_KEY, 'good');
    window.localStorage.setItem(AUTH_REFRESH_KEY, 'r1');
    install((url) => {
      if (url === '/api/v1/auth/refresh') return json(200, tokens('good2', 'r2'));
      if (url === '/api/v1/auth/me') return json(200); // the session itself is fine
      return json(401, { detail: 'vendor rejected your API key' });
    });
    const res = await authFetch('/api/v1/connectors/test', { method: 'POST', body: '{}' });
    expect(res.status).toBe(401);
    expect(redirect).not.toHaveBeenCalled();
    expect(window.localStorage.getItem(AUTH_TOKEN_KEY)).not.toBeNull();
  });

  it('development: a 401 with no login and /auth/me not 401 is left completely alone', async () => {
    install((url) => (url === '/api/v1/auth/me' ? json(404) : json(401)));
    const res = await authFetch('/api/v1/connectors/test', { method: 'POST', body: '{}' });
    expect(res.status).toBe(401);
    expect(redirect).not.toHaveBeenCalled();
  });

  it('a network failure while checking does not log you out', async () => {
    window.localStorage.setItem(AUTH_TOKEN_KEY, 'old');
    window.localStorage.setItem(AUTH_REFRESH_KEY, 'r1');
    install((url) => (url === '/api/v1/cases' ? json(401) : 'network-error'));
    const res = await authFetch('/api/v1/cases');
    expect(res.status).toBe(401);
    expect(redirect).not.toHaveBeenCalled();
    expect(window.localStorage.getItem(AUTH_REFRESH_KEY)).toBe('r1');
  });

  it('a refresh endpoint 5xx does not log you out', async () => {
    window.localStorage.setItem(AUTH_REFRESH_KEY, 'r1');
    install((url) => (url === '/api/v1/auth/refresh' ? json(503) : json(401)));
    await authFetch('/api/v1/cases');
    expect(redirect).not.toHaveBeenCalled();
    expect(window.localStorage.getItem(AUTH_REFRESH_KEY)).toBe('r1');
  });

  it('login failures and refresh calls never trigger the session machinery', async () => {
    install(() => json(401));
    await authFetch('/api/v1/auth/login', { method: 'POST', body: '{}' });
    await authFetch('/api/v1/auth/refresh', { method: 'POST', body: '{}' });
    expect(calls).toHaveLength(2);
    expect(redirect).not.toHaveBeenCalled();
  });

  it('403 (permission) is not a session problem', async () => {
    install(() => json(403));
    const res = await authFetch('/api/v1/rbac/roles');
    expect(res.status).toBe(403);
    expect(calls).toHaveLength(1);
  });

  it('no redirect loop: already on /login, or on the mobile responder', async () => {
    for (const where of ['/login', '/responder/cases']) {
      window.history.replaceState({}, '', where);
      install(() => json(401));
      await authFetch('/api/v1/cases');
    }
    expect(redirect).not.toHaveBeenCalled();
  });

  it("a caller-supplied Authorization is never retried or replaced", async () => {
    install(() => json(401));
    await authFetch('/api/v1/cases', { headers: { Authorization: 'Bearer mine' } });
    expect(calls).toHaveLength(1);
  });
});
