import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { AUTH_REFRESH_KEY, AUTH_TOKEN_KEY, AUTH_USER_KEY, revokeServerSession } from './auth-session';

const json = (status: number, body: unknown) => new Response(JSON.stringify(body), { status, headers: { 'content-type': 'application/json' } });

// Signing out used to only clear the browser's copy of the tokens, so a copied or stolen token stayed valid until it expired. revokeServerSession asks the server to END the session.
describe('revokeServerSession', () => {
  const fetchMock = vi.fn();

  beforeEach(() => {
    window.localStorage.clear();
    fetchMock.mockReset();
    vi.stubGlobal('fetch', fetchMock);
  });
  afterEach(() => {
    vi.unstubAllGlobals();
    vi.useRealTimers();
  });

  it('has nothing to end, and calls nobody, when no one is signed in', async () => {
    expect(await revokeServerSession()).toEqual({ ended: true, message: null });
    expect(fetchMock).not.toHaveBeenCalled();
  });

  it('sends both tokens to the logout route, and reports it ended when the server confirms', async () => {
    window.localStorage.setItem(AUTH_TOKEN_KEY, 'access-123');
    window.localStorage.setItem(AUTH_REFRESH_KEY, 'refresh-456');
    fetchMock.mockResolvedValue(json(200, { revoked: true, detail: 'Session ended.' }));
    expect(await revokeServerSession()).toEqual({ ended: true, message: null });
    expect(fetchMock).toHaveBeenCalledTimes(1);
    const [url, init] = fetchMock.mock.calls[0];
    expect(url).toBe('/api/v1/auth/logout');
    expect(init.method).toBe('POST');
    expect(init.headers.Authorization).toBe('Bearer access-123');
    expect(JSON.parse(init.body)).toEqual({ refresh_token: 'refresh-456' });
  });

  it('sends an empty body when there is no refresh token', async () => {
    window.localStorage.setItem(AUTH_TOKEN_KEY, 'access-123');
    fetchMock.mockResolvedValue(json(200, { revoked: true, detail: 'ok' }));
    await revokeServerSession();
    expect(JSON.parse(fetchMock.mock.calls[0][1].body)).toEqual({});
  });

  it('does not clear the stored session itself: that stays the caller\'s decision, after this', async () => {
    window.localStorage.setItem(AUTH_TOKEN_KEY, 'access');
    window.localStorage.setItem(AUTH_REFRESH_KEY, 'refresh');
    window.localStorage.setItem(AUTH_USER_KEY, '{}');
    fetchMock.mockResolvedValue(json(200, { revoked: true, detail: 'ok' }));
    await revokeServerSession();
    expect(window.localStorage.getItem(AUTH_TOKEN_KEY)).toBe('access');
    expect(window.localStorage.getItem(AUTH_REFRESH_KEY)).toBe('refresh');
  });

  it('treats a 401 as ended (already expired or revoked), without retrying or refreshing', async () => {
    window.localStorage.setItem(AUTH_TOKEN_KEY, 'stale');
    fetchMock.mockResolvedValue(json(401, { detail: 'Token has been revoked' }));
    expect(await revokeServerSession()).toEqual({ ended: true, message: null });
    expect(fetchMock).toHaveBeenCalledTimes(1);
  });

  it("reports the server's reason when it could not end the session", async () => {
    window.localStorage.setItem(AUTH_TOKEN_KEY, 'access');
    fetchMock.mockResolvedValue(json(503, { detail: 'Could not end the session: the revocation store is unavailable. Try again.' }));
    expect(await revokeServerSession()).toEqual({ ended: false, message: 'Could not end the session: the revocation store is unavailable. Try again.' });
  });

  it('falls back to the bare status when the server gives no explanation', async () => {
    window.localStorage.setItem(AUTH_TOKEN_KEY, 'access');
    fetchMock.mockResolvedValue(new Response('<html>bad gateway</html>', { status: 502 }));
    expect(await revokeServerSession()).toEqual({ ended: false, message: 'HTTP 502' });
  });

  it('does not claim success when the server says it revoked nothing', async () => {
    window.localStorage.setItem(AUTH_TOKEN_KEY, 'old-token');
    fetchMock.mockResolvedValue(json(200, { revoked: false, detail: 'This session was issued before server-side revocation existed.' }));
    expect(await revokeServerSession()).toEqual({ ended: false, message: 'This session was issued before server-side revocation existed.' });
  });

  it('says the server could not be reached on a network failure, and never throws', async () => {
    window.localStorage.setItem(AUTH_TOKEN_KEY, 'access');
    fetchMock.mockRejectedValue(new TypeError('Failed to fetch'));
    expect(await revokeServerSession()).toEqual({ ended: false, message: 'the server could not be reached' });
  });

  it('gives up after the timeout instead of trapping the user, and says the server did not respond', async () => {
    vi.useFakeTimers();
    window.localStorage.setItem(AUTH_TOKEN_KEY, 'access');
    fetchMock.mockImplementation(
      (_url: string, init: { signal: AbortSignal }) =>
        new Promise((_resolve, reject) => {
          init.signal.addEventListener('abort', () => reject(new DOMException('aborted', 'AbortError')));
        }),
    );
    const pending = revokeServerSession(4000);
    await vi.advanceTimersByTimeAsync(3999);
    let settled = false;
    void pending.then(() => { settled = true; });
    await Promise.resolve();
    expect(settled).toBe(false); // still waiting just before the deadline
    await vi.advanceTimersByTimeAsync(2);
    expect(await pending).toEqual({ ended: false, message: 'the server did not respond in time' });
  });
});
