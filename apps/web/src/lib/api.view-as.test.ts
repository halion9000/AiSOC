/**
 * The API client's side of viewing another tenant: refusals carry the API's code, a refused WRITE explains itself in words, the helpers other code already calls keep their meaning, and the tenant list is fetched as the person.
 */
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { ApiError, DEFAULT_TENANT_ID, getActiveTenantId, setActiveTenantId, tenantsApi } from './api';
import { AUTH_TOKEN_KEY } from './auth-session';
import { ACTIVE_TENANT_KEY, USER_STORAGE_KEY } from './tenant-view';

let calls: { url: string; headers: Headers; method: string }[];
function install(respond: (url: string) => Response | Record<string, unknown>) {
  calls = [];
  vi.stubGlobal('fetch', async (input: RequestInfo | URL, init?: RequestInit) => {
    const url = typeof input === 'string' ? input : input instanceof URL ? input.href : input.url;
    calls.push({ url, headers: new Headers(init?.headers), method: init?.method ?? 'GET' });
    return respond(url) as Response;
  });
}
const json = (status: number, body: unknown, headers: Record<string, string> = {}) =>
  new Response(JSON.stringify(body), { status, headers: { 'Content-Type': 'application/json', ...headers } });
const signIn = (tenant_id = 'home') => window.localStorage.setItem(USER_STORAGE_KEY, JSON.stringify({ id: 'u1', tenant_id }));

beforeEach(() => {
  window.localStorage.clear();
  window.localStorage.setItem(AUTH_TOKEN_KEY, 'tok1');
});
afterEach(() => {
  vi.unstubAllGlobals();
  vi.restoreAllMocks();
});

async function failure(promise: Promise<unknown>): Promise<ApiError> {
  try {
    await promise;
  } catch (e) {
    return e as ApiError;
  }
  throw new Error('expected the call to fail');
}

describe('ApiError', () => {
  it('carries the view-as code when there is one', () => {
    expect(new ApiError('m', 403, 'b', 'read_only').viewAsError).toBe('read_only');
  });
  it('is unchanged for the three-argument form every existing caller uses', () => {
    const e = new ApiError('m', 500, 'b');
    expect(e.viewAsError).toBeUndefined();
    expect('viewAsError' in e).toBe(false);
    expect([e.message, e.status, e.body, e.name]).toEqual(['m', 500, 'b', 'ApiError']);
  });
});

describe('a refusal while viewing another tenant', () => {
  it('a refused write says so in the API\'s own words and carries the code', async () => {
    install(() => json(403, { detail: 'This tenant is read-only while you are viewing it as another tenant.' }, { 'X-View-As-Error': 'read_only' }));
    const e = await failure(tenantsApi.users());
    expect(e).toBeInstanceOf(ApiError);
    expect(e.message).toBe('This tenant is read-only while you are viewing it as another tenant.');
    expect([e.status, e.viewAsError]).toEqual([403, 'read_only']);
  });

  it.each([['not json at all'], [JSON.stringify({ other: 1 })], [JSON.stringify({ detail: '' })], [JSON.stringify({ detail: { nested: true } })]])(
    'a read-only refusal whose body has no usable sentence still explains itself (%s)',
    async (body) => {
      install(() => new Response(body, { status: 403, headers: { 'X-View-As-Error': 'read_only' } }));
      const e = await failure(tenantsApi.users());
      expect(e.message).toMatch(/read-only while you are viewing it/i);
      expect(e.message).toMatch(/switch back to your own tenant/i);
    },
  );

  it.each(['forbidden', 'invalid', 'session_only'])('%s keeps the usual message but carries the code', async (code) => {
    install(() => json(403, { detail: 'You may not view that tenant.' }, { 'X-View-As-Error': code }));
    const e = await failure(tenantsApi.users());
    expect(e.message).toMatch(/^API 403/);
    expect(e.message).not.toMatch(/may not view/);
    expect(e.viewAsError).toBe(code);
  });

  it('an ordinary error is exactly as before', async () => {
    install(() => json(500, { detail: 'boom' }));
    const e = await failure(tenantsApi.users());
    expect(e.message).toMatch(/^API 500/);
    expect(e.viewAsError).toBeUndefined();
    expect(JSON.parse(e.body)).toEqual({ detail: 'boom' });
  });

  it('a response object with no headers (a test double) becomes an ApiError, not a TypeError', async () => {
    install(() => ({ ok: false, status: 500, statusText: 'x', text: async () => '' }));
    const e = await failure(tenantsApi.users());
    expect(e).toBeInstanceOf(ApiError);
    expect(e.viewAsError).toBeUndefined();
  });
});

describe('tenantsApi.viewable', () => {
  const body = { home_tenant_id: 'home', tenants: [{ id: 'home', name: 'MSP', slug: 'msp', relationship: 'self' }, { id: 'c1', name: 'Customer', slug: 'c', relationship: 'granted' }] };

  it('reads the tenant list the server will honour', async () => {
    install(() => json(200, body));
    expect(await tenantsApi.viewable()).toEqual(body);
    expect(calls.map((c) => [c.method, c.url])).toEqual([['GET', '/api/v1/tenants/viewable']]);
  });

  it('asks as the person, not as the tenant being viewed: the list must not change when they switch', async () => {
    signIn('home');
    window.localStorage.setItem(ACTIVE_TENANT_KEY, 'c1');
    install(() => json(200, body));
    await tenantsApi.viewable();
    await tenantsApi.users();
    expect(calls[0].headers.get('X-View-As-Tenant')).toBeNull();
    expect(calls[1].headers.get('X-View-As-Tenant')).toBe('c1');
  });
});

describe('every API call through request()', () => {
  it('asks for the viewed tenant, and still sends the legacy X-Tenant-Id the API has always ignored', async () => {
    signIn('home');
    window.localStorage.setItem(ACTIVE_TENANT_KEY, 'c1');
    install(() => json(200, []));
    await tenantsApi.users();
    expect(calls[0].headers.get('X-View-As-Tenant')).toBe('c1');
    expect(calls[0].headers.get('X-Tenant-Id')).toBe('c1');
  });

  it('sends no view-as header while the person is on their own tenant', async () => {
    signIn('home');
    install(() => json(200, []));
    await tenantsApi.users();
    expect(calls[0].headers.get('X-View-As-Tenant')).toBeNull();
    expect(calls[0].headers.get('X-Tenant-Id')).toBe('home');
  });
});

describe('getActiveTenantId / setActiveTenantId keep their meaning for existing callers', () => {
  it('is the tenant being viewed', () => {
    signIn('home');
    window.localStorage.setItem(ACTIVE_TENANT_KEY, 'c1');
    expect(getActiveTenantId()).toBe('c1');
  });
  it('is the person\'s own tenant when nothing is chosen', () => {
    signIn('home');
    expect(getActiveTenantId()).toBe('home');
  });
  it('is the same own tenant when the stored choice is their own', () => {
    signIn('home');
    window.localStorage.setItem(ACTIVE_TENANT_KEY, 'home');
    expect(getActiveTenantId()).toBe('home');
  });
  it('is the build-time default when nobody is signed in', () => {
    expect(getActiveTenantId()).toBe(DEFAULT_TENANT_ID);
  });
  it('set stores a view, and null or the own tenant clears it', () => {
    signIn('home');
    setActiveTenantId('c1');
    expect(window.localStorage.getItem(ACTIVE_TENANT_KEY)).toBe('c1');
    setActiveTenantId(null);
    expect(window.localStorage.getItem(ACTIVE_TENANT_KEY)).toBeNull();
    setActiveTenantId('c1');
    setActiveTenantId('home');
    expect(window.localStorage.getItem(ACTIVE_TENANT_KEY)).toBeNull();
  });
});
