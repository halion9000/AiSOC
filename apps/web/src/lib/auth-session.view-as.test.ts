/**
 * authFetch asks the API for the tenant being viewed (X-View-As-Tenant), on every same-origin API call except the account-level ones, and stops asking when the API refuses.
 * The switcher used to send a header the API never read, so an operator "viewing" a customer saw their own data; this is the console's half of the fix.
 */
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { AUTH_REFRESH_KEY, AUTH_TOKEN_KEY, authFetch, sessionHooks } from './auth-session';
import { ACTIVE_TENANT_KEY, USER_STORAGE_KEY } from './tenant-view';

let calls: { url: string; view: string | null; auth: string | null }[];
let reload: ReturnType<typeof vi.spyOn>;

type Handler = (url: string, init: RequestInit | undefined) => Response | Promise<Response>;
function install(handler: Handler) {
  calls = [];
  vi.stubGlobal('fetch', async (input: RequestInfo | URL, init?: RequestInit) => {
    const url = typeof input === 'string' ? input : input instanceof URL ? input.href : input.url;
    const headers = new Headers(init?.headers);
    calls.push({ url, view: headers.get('X-View-As-Tenant'), auth: headers.get('Authorization') });
    return handler(url, init);
  });
}
const json = (status: number, body: unknown = {}, headers: Record<string, string> = {}) =>
  new Response(JSON.stringify(body), { status, headers: { 'Content-Type': 'application/json', ...headers } });
const refused = (status: number, error: string) => json(status, { detail: 'refused' }, { 'X-View-As-Error': error });

const viewing = (tenant = 'c1') => {
  window.localStorage.setItem(USER_STORAGE_KEY, JSON.stringify({ id: 'u1', tenant_id: 'home' }));
  window.localStorage.setItem(ACTIVE_TENANT_KEY, tenant);
};

beforeEach(() => {
  window.localStorage.clear();
  window.localStorage.setItem(AUTH_TOKEN_KEY, 'tok1');
  reload = vi.spyOn(sessionHooks, 'reload').mockImplementation(() => {});
  vi.spyOn(sessionHooks, 'redirectToLogin').mockImplementation(() => {});
  window.history.replaceState({}, '', '/alerts');
});
afterEach(() => {
  vi.unstubAllGlobals();
  vi.restoreAllMocks();
});

describe('asking for the viewed tenant', () => {
  it('sends the header on an ordinary API call while viewing', async () => {
    viewing('c1');
    install(() => json(200));
    await authFetch('/api/v1/alerts');
    expect(calls[0].view).toBe('c1');
    expect(calls[0].auth).toBe('Bearer tok1');
  });

  it('sends nothing when no tenant is being viewed', async () => {
    window.localStorage.setItem(USER_STORAGE_KEY, JSON.stringify({ id: 'u1', tenant_id: 'home' }));
    install(() => json(200));
    await authFetch('/api/v1/alerts');
    expect(calls[0].view).toBeNull();
  });

  it("sends nothing when the stored choice is the person's own tenant", async () => {
    viewing('home');
    install(() => json(200));
    await authFetch('/api/v1/alerts');
    expect(calls[0].view).toBeNull();
  });

  it.each(['/api/v1/auth/me', '/api/v1/auth/logout', '/api/v1/push/subscribe', '/api/v1/passkeys/credentials', '/api/v1/tenants/viewable'])(
    'sends nothing on the account-level route %s',
    async (path) => {
      viewing('c1');
      install(() => json(200));
      await authFetch(path);
      expect(calls[0].view).toBeNull();
    },
  );

  it('sends it on writes too (the server refuses them, and says so)', async () => {
    viewing('c1');
    install(() => json(200));
    await authFetch('/api/v1/tenants/me/users', { method: 'POST', body: '{}' });
    expect(calls[0].view).toBe('c1');
  });

  it('sends it even when there is no token (development)', async () => {
    window.localStorage.removeItem(AUTH_TOKEN_KEY);
    viewing('c1');
    install(() => json(200));
    await authFetch('/api/v1/alerts');
    expect(calls[0].view).toBe('c1');
    expect(calls[0].auth).toBeNull();
  });

  it("never overrides a caller's own X-View-As-Tenant", async () => {
    viewing('c1');
    install(() => json(200));
    await authFetch('/api/v1/alerts', { headers: { 'X-View-As-Tenant': 'mine' } });
    expect(calls[0].view).toBe('mine');
  });

  it('never sends it to another origin or a non-API path', async () => {
    viewing('c1');
    install(() => json(200));
    await authFetch('https://evil.example/api/v1/alerts');
    await authFetch('/_next/static/chunk.js');
    expect(calls.every((c) => c.view === null)).toBe(true);
  });

  it("does not modify the caller's init or headers", async () => {
    viewing('c1');
    install(() => json(200));
    const headers = { 'Content-Type': 'application/json' };
    const init: RequestInit = { method: 'GET', headers };
    await authFetch('/api/v1/alerts', init);
    expect(init.headers).toBe(headers);
    expect(headers).toEqual({ 'Content-Type': 'application/json' });
  });

  it('the retry after a token refresh asks for the viewed tenant too', async () => {
    viewing('c1');
    window.localStorage.setItem(AUTH_REFRESH_KEY, 'r1');
    let first = true;
    install((url) => {
      if (url === '/api/v1/auth/refresh') return json(200, { access_token: 'tok2', refresh_token: 'r2' });
      if (url === '/api/v1/auth/me') return json(200);
      if (first) {
        first = false;
        return json(401);
      }
      return json(200, { ok: true });
    });
    const res = await authFetch('/api/v1/alerts');
    expect(res.status).toBe(200);
    const alerts = calls.filter((c) => c.url === '/api/v1/alerts');
    expect(alerts.map((c) => c.view)).toEqual(['c1', 'c1']);
    expect(alerts[1].auth).toBe('Bearer tok2');
  });
});

describe('when the API refuses the view', () => {
  it.each(['forbidden', 'invalid'])('%s: stops sending it and reloads onto the own tenant', async (code) => {
    viewing('c1');
    install(() => refused(code === 'invalid' ? 400 : 403, code));
    const res = await authFetch('/api/v1/alerts');
    expect(res.status).toBe(code === 'invalid' ? 400 : 403); // the response is still handed back
    expect(window.localStorage.getItem(ACTIVE_TENANT_KEY)).toBeNull();
    expect(reload).toHaveBeenCalledTimes(1);
  });

  it('read_only is a refused WRITE, not a bad view: the view stays and nothing reloads', async () => {
    viewing('c1');
    install(() => refused(403, 'read_only'));
    const res = await authFetch('/api/v1/tenants/me/users', { method: 'POST', body: '{}' });
    expect(res.status).toBe(403);
    expect(window.localStorage.getItem(ACTIVE_TENANT_KEY)).toBe('c1');
    expect(reload).not.toHaveBeenCalled();
  });

  it.each(['session_only', 'something-new'])('%s: does not drop the view', async (code) => {
    viewing('c1');
    install(() => refused(403, code));
    await authFetch('/api/v1/alerts');
    expect(window.localStorage.getItem(ACTIVE_TENANT_KEY)).toBe('c1');
    expect(reload).not.toHaveBeenCalled();
  });

  it('a refusal when no view is in force does not reload (nothing to drop, no loop)', async () => {
    window.localStorage.setItem(USER_STORAGE_KEY, JSON.stringify({ id: 'u1', tenant_id: 'home' }));
    install(() => refused(403, 'forbidden'));
    await authFetch('/api/v1/alerts');
    expect(reload).not.toHaveBeenCalled();
  });

  it('an ordinary 403 with no view-as header does not touch the view', async () => {
    viewing('c1');
    install(() => json(403, { detail: 'Permission denied: users:write' }));
    await authFetch('/api/v1/tenants/me/users', { method: 'POST', body: '{}' });
    expect(window.localStorage.getItem(ACTIVE_TENANT_KEY)).toBe('c1');
    expect(reload).not.toHaveBeenCalled();
  });

  it('after the first refusal the next call no longer carries the header, so it cannot loop', async () => {
    viewing('c1');
    install((_url, init) => (new Headers(init?.headers).has('X-View-As-Tenant') ? refused(403, 'forbidden') : json(200)));
    await authFetch('/api/v1/alerts');
    const again = await authFetch('/api/v1/alerts');
    expect(again.status).toBe(200);
    expect(calls.map((c) => c.view)).toEqual(['c1', null]);
    expect(reload).toHaveBeenCalledTimes(1);
  });

  it('a refusal that arrives on the retry after a token refresh drops the view too', async () => {
    viewing('c1');
    window.localStorage.setItem(AUTH_REFRESH_KEY, 'r1');
    let first = true;
    install((url) => {
      if (url === '/api/v1/auth/refresh') return json(200, { access_token: 'tok2', refresh_token: 'r2' });
      if (url === '/api/v1/auth/me') return json(200);
      if (first) {
        first = false;
        return json(401); // the token had expired: refresh, then retry
      }
      return refused(403, 'forbidden'); // ...and the retry finds the view is no longer allowed
    });
    const res = await authFetch('/api/v1/alerts');
    expect(res.status).toBe(403);
    expect(window.localStorage.getItem(ACTIVE_TENANT_KEY)).toBeNull();
    expect(reload).toHaveBeenCalledTimes(1);
  });

  it('a response without headers (a test double) is handled, not a crash', async () => {
    viewing('c1');
    vi.stubGlobal('fetch', async () => ({ ok: true, status: 200 }) as unknown as Response);
    await expect(authFetch('/api/v1/alerts')).resolves.toBeDefined();
  });
});
