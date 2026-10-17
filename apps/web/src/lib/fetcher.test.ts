import { afterEach, describe, expect, it, vi } from 'vitest';

const authFetch = vi.fn();
vi.mock('./auth-session', () => ({ authFetch: (...args: unknown[]) => authFetch(...args) }));

import { safeFetcher } from './fetcher';

describe('safeFetcher', () => {
  afterEach(() => {
    authFetch.mockReset();
    vi.unstubAllGlobals();
  });

  // A bare fetch() carries no login token: the effective-permissions page worked in dev and got 401 in production.
  it('goes through authFetch so the request carries the login', async () => {
    const bare = vi.fn();
    vi.stubGlobal('fetch', bare);
    authFetch.mockResolvedValue(new Response(JSON.stringify({ ok: true }), { status: 200 }));
    await expect(safeFetcher('/api/v1/identity/x')).resolves.toEqual({ ok: true });
    expect(authFetch).toHaveBeenCalledWith('/api/v1/identity/x');
    expect(bare).not.toHaveBeenCalled();
  });

  it('throws a readable error on a non-2xx answer', async () => {
    authFetch.mockResolvedValue(new Response('nope', { status: 501, statusText: 'Not Implemented' }));
    await expect(safeFetcher('/api/v1/identity/x')).rejects.toThrow(/HTTP 501/);
  });
});
