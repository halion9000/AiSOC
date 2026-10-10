/**
 * The API client for tenant access grants, every-tenant grants and the alert email setting: each call must reach the right route with the right method and body
 * (a wrong path or method would only fail in production), an account name must never be able to change the path it is placed in, and a refusal's own explanation
 * must be readable for showing to a person.
 */
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { ApiError, alertEmailApi, apiErrorDetail, tenantAccessApi } from './api';
import { AUTH_TOKEN_KEY } from './auth-session';

let calls: { url: string; method: string; body: string | null }[];
function install(respond: (url: string, method: string) => Response) {
  calls = [];
  vi.stubGlobal('fetch', async (input: RequestInfo | URL, init?: RequestInit) => {
    const url = typeof input === 'string' ? input : input instanceof URL ? input.href : input.url;
    const method = init?.method ?? 'GET';
    calls.push({ url, method, body: typeof init?.body === 'string' ? init.body : null });
    return respond(url, method);
  });
}
const json = (status: number, body: unknown) => new Response(JSON.stringify(body), { status, headers: { 'Content-Type': 'application/json' } });
const path = (i = 0) => new URL(calls[i].url, 'http://x').pathname + new URL(calls[i].url, 'http://x').search;

beforeEach(() => {
  window.localStorage.clear();
  window.localStorage.setItem(AUTH_TOKEN_KEY, 'tok1');
});
afterEach(() => {
  vi.unstubAllGlobals();
  vi.restoreAllMocks();
});

describe('tenantAccessApi', () => {
  it('manageable and list are plain reads of the right routes', async () => {
    install(() => json(200, { home_tenant_id: 'h', tenants: [] }));
    await tenantAccessApi.manageable();
    await tenantAccessApi.list('t-1');
    expect(calls.map((c) => [c.method, path(calls.indexOf(c))])).toEqual([['GET', '/api/v1/tenants/manageable'], ['GET', '/api/v1/tenants/t-1/access']]);
    expect(calls.every((c) => c.body === null)).toBe(true);
  });

  it('grant is a PUT to that tenant and person with the level in the body', async () => {
    install(() => json(200, {}));
    await tenantAccessApi.grant('t-1', 'tech.one', 'full');
    await tenantAccessApi.grant('t-1', 'tech.one', 'view');
    expect(calls.map((c) => [c.method, new URL(c.url, 'http://x').pathname, c.body])).toEqual([
      ['PUT', '/api/v1/tenants/t-1/access/tech.one', '{"access":"full"}'],
      ['PUT', '/api/v1/tenants/t-1/access/tech.one', '{"access":"view"}'],
    ]);
  });

  it('revoke is a DELETE of that grant with no body', async () => {
    install(() => new Response(null, { status: 204 }));
    await tenantAccessApi.revoke('t-1', 'tech.one');
    expect([calls[0].method, path(), calls[0].body]).toEqual(['DELETE', '/api/v1/tenants/t-1/access/tech.one', null]);
  });

  it('an account name or tenant id cannot change the path it is placed in', async () => {
    install(() => json(200, {}));
    await tenantAccessApi.grant('t/../x', 'a/b?c=d#e', 'view');
    const p = new URL(calls[0].url, 'http://x');
    expect(p.pathname).toBe('/api/v1/tenants/t%2F..%2Fx/access/a%2Fb%3Fc%3Dd%23e');
    expect(p.search).toBe('');
    expect(p.hash).toBe('');
  });

  it('every call that puts a tenant id or an account name in a path encodes it, not just grant', async () => {
    install((url, method) => (method === 'DELETE' ? new Response(null, { status: 204 }) : json(200, [])));
    await tenantAccessApi.list('t/../x');
    await tenantAccessApi.revoke('t/../x', 'a/b?c=d');
    await tenantAccessApi.revokeAll('p/../q');
    expect(calls.map((c) => new URL(c.url, 'http://x').pathname)).toEqual([
      '/api/v1/tenants/t%2F..%2Fx/access',
      '/api/v1/tenants/t%2F..%2Fx/access/a%2Fb%3Fc%3Dd',
      '/api/v1/platform/all-tenant-access/p%2F..%2Fq',
    ]);
    expect(calls.every((c) => new URL(c.url, 'http://x').search === '')).toBe(true);
  });

  it('the every-tenant calls use the platform routes, with the level in the body for a grant', async () => {
    install((url, method) => (method === 'DELETE' ? new Response(null, { status: 204 }) : json(200, [])));
    await tenantAccessApi.listAll();
    await tenantAccessApi.grantAll('tech.x', 'full');
    await tenantAccessApi.revokeAll('tech.x');
    expect(calls.map((c) => [c.method, new URL(c.url, 'http://x').pathname, c.body])).toEqual([
      ['GET', '/api/v1/platform/all-tenant-access', null],
      ['PUT', '/api/v1/platform/all-tenant-access/tech.x', '{"access":"full"}'],
      ['DELETE', '/api/v1/platform/all-tenant-access/tech.x', null],
    ]);
  });

  it('an every-tenant account name is encoded too', async () => {
    install(() => json(200, {}));
    await tenantAccessApi.grantAll('x/../../y', 'view');
    expect(new URL(calls[0].url, 'http://x').pathname).toBe('/api/v1/platform/all-tenant-access/x%2F..%2F..%2Fy');
  });
});

describe('alertEmailApi', () => {
  it('get, update, test and log reach the right routes with the right methods and bodies', async () => {
    install(() => json(200, []));
    await alertEmailApi.get();
    await alertEmailApi.update({ recipients: ['a@b.example'], min_severity: 'high', enabled: true });
    await alertEmailApi.test();
    await alertEmailApi.log();
    await alertEmailApi.log(5);
    expect(calls.map((c, i) => [c.method, path(i), c.body])).toEqual([
      ['GET', '/api/v1/platform/alert-email', null],
      ['PUT', '/api/v1/platform/alert-email', '{"recipients":["a@b.example"],"min_severity":"high","enabled":true}'],
      ['POST', '/api/v1/platform/alert-email/test', null],
      ['GET', '/api/v1/platform/alert-email/log?limit=50', null],
      ['GET', '/api/v1/platform/alert-email/log?limit=5', null],
    ]);
  });
});

describe('apiErrorDetail: the API\'s own explanation of a refusal', () => {
  const err = (body: string) => new ApiError('API 422 - /x', 422, body);

  it('reads a sentence', () => {
    expect(apiErrorDetail(err('{"detail":"No account with that name"}'))).toBe('No account with that name');
  });
  it('joins the messages of a validation failure', () => {
    expect(apiErrorDetail(err('{"detail":[{"loc":["body","access"],"msg":"Input should be \'view\' or \'full\'"},{"msg":"Field required"}]}'))).toBe("Input should be 'view' or 'full'; Field required");
  });
  it('ignores list entries that carry no message', () => {
    expect(apiErrorDetail(err('{"detail":[{"loc":["x"]},{"msg":"Field required"},null,5]}'))).toBe('Field required');
  });
  it.each([['not json'], [''], ['{}'], ['{"detail":""}'], ['{"detail":5}'], ['{"detail":[]}'], ['{"detail":[{"loc":[]}]}'], ['null'], ['[]']])('is null for %j', (body) => {
    expect(apiErrorDetail(err(body))).toBeNull();
  });
  it('does not trust anything that merely LOOKS like an API error: only a real ApiError is read', () => {
    expect(apiErrorDetail({ body: '{"detail":"leak"}' })).toBeNull();
    expect(apiErrorDetail(Object.assign(new Error('x'), { body: '{"detail":"leak"}' }))).toBeNull();
  });
  it('is null for anything that is not an API error', () => {
    expect(apiErrorDetail(new Error('{"detail":"x"}'))).toBeNull();
    expect(apiErrorDetail('{"detail":"x"}')).toBeNull();
    expect(apiErrorDetail(undefined)).toBeNull();
  });
  it('works on the error a real failed request throws', async () => {
    install(() => json(404, { detail: 'No account with that name' }));
    let caught: unknown;
    try {
      await tenantAccessApi.grant('t-1', 'nobody', 'view');
    } catch (e) {
      caught = e;
    }
    expect(caught).toBeInstanceOf(ApiError);
    expect(apiErrorDetail(caught)).toBe('No account with that name');
  });
});
