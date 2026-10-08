import { beforeEach, describe, expect, it, vi } from 'vitest';

const authFetch = vi.hoisted(() => vi.fn());
vi.mock('@/lib/auth-session', () => ({ authFetch }));

import { failureDetail, installCommunityItem } from './communityInstall';

const json = (status: number, body: unknown) => new Response(JSON.stringify(body), { status, headers: { 'content-type': 'application/json' } });

// The community install buttons used to `await authFetch(...)` and mark the item "Installed" whenever the request merely COMPLETED, so a 403, a 400 or a 500 still said Installed.
describe('installCommunityItem', () => {
  beforeEach(() => {
    authFetch.mockReset();
  });

  it('posts to the right route, with the id encoded', async () => {
    authFetch.mockResolvedValue(json(200, { message: 'ok' }));
    await installCommunityItem('detections', 'a/b c');
    expect(authFetch).toHaveBeenCalledWith('/api/v1/community/detections/a%2Fb%20c/install', { method: 'POST' });
    await installCommunityItem('playbooks', 'p1');
    expect(authFetch).toHaveBeenLastCalledWith('/api/v1/community/playbooks/p1/install', { method: 'POST' });
  });

  it('resolves installed on success', async () => {
    authFetch.mockResolvedValue(json(200, {}));
    await expect(installCommunityItem('detections', 'r1')).resolves.toBe('installed');
  });

  it('treats a 409 as already installed (true, and harmless to show as installed)', async () => {
    authFetch.mockResolvedValue(json(409, { detail: 'This detection is already installed' }));
    await expect(installCommunityItem('detections', 'r1')).resolves.toBe('already-installed');
  });

  it.each([400, 403, 404, 422, 500, 501, 503])('throws the server\'s own reason for a %i', async (status) => {
    authFetch.mockResolvedValue(json(status, { detail: `reason for ${status}` }));
    await expect(installCommunityItem('playbooks', 'p1')).rejects.toThrow(`reason for ${status}`);
  });

  it('falls back to the bare status when there is no JSON detail', async () => {
    authFetch.mockResolvedValue(new Response('<html>Bad gateway</html>', { status: 502 }));
    await expect(installCommunityItem('detections', 'r1')).rejects.toThrow('HTTP 502');
  });

  it('lets a network failure through as an error', async () => {
    authFetch.mockRejectedValue(new Error('network down'));
    await expect(installCommunityItem('detections', 'r1')).rejects.toThrow('network down');
  });
});

describe('failureDetail', () => {
  it('prefers a string detail, ignores non-string ones', async () => {
    expect(await failureDetail(json(400, { detail: 'nope' }))).toBe('nope');
    expect(await failureDetail(json(422, { detail: [{ msg: 'x' }] }))).toBe('HTTP 422');
    expect(await failureDetail(json(500, { detail: '' }))).toBe('HTTP 500');
  });
});
