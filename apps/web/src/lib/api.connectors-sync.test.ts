import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { connectorsApi } from './api';

const json = (body: unknown, status = 200) => new Response(JSON.stringify(body), { status, headers: { 'Content-Type': 'application/json' } });
const REQUESTED = '2026-10-16T12:00:00+00:00';

beforeEach(() => window.localStorage.clear());
afterEach(() => vi.unstubAllGlobals());

/** A fake API: POST /sync answers the request time; each GET of the connector answers the next last_health_check in `checks`. */
function fakeApi(checks: (string | null)[]) {
  const calls: string[] = [];
  let i = 0;
  vi.stubGlobal('fetch', async (url: string, init?: RequestInit) => {
    calls.push(`${init?.method ?? 'GET'} ${String(url).replace(/^.*\/api/, '/api')}`);
    if (String(url).endsWith('/sync')) return json({ requested_at: REQUESTED, vendor: 'ninjaone' }, 202);
    return json({ id: 'c1', last_health_check: checks[Math.min(i++, checks.length - 1)] });
  });
  return calls;
}

describe('connectorsApi.syncNow', () => {
  it('asks for a sync, then waits until CORE has reported after the request', async () => {
    const calls = fakeApi(['2026-10-16T11:58:00+00:00', '2026-10-16T11:59:00+00:00', '2026-10-16T12:00:07+00:00']);
    const out = await connectorsApi.syncNow('c1', { sleep: async () => {} });
    expect(out).toEqual({ reported: true });
    expect(calls).toEqual(['POST /api/v1/connectors/c1/sync', 'GET /api/v1/connectors/c1', 'GET /api/v1/connectors/c1', 'GET /api/v1/connectors/c1']);
  });

  it('an older report, or none at all, is not an answer', async () => {
    fakeApi([null, '2026-10-16T11:00:00+00:00']);
    const out = await connectorsApi.syncNow('c1', { intervalMs: 1000, timeoutMs: 5000, sleep: async () => {} });
    expect(out).toEqual({ reported: false });
  });

  it('stops waiting at the timeout', async () => {
    const calls = fakeApi(['2026-10-16T11:00:00+00:00']);
    await connectorsApi.syncNow('c1', { intervalMs: 1000, timeoutMs: 3000, sleep: async () => {} });
    expect(calls.filter((c) => c.startsWith('GET')).length).toBe(3);
  });

  it('a report at the exact moment of the request counts', async () => {
    fakeApi([REQUESTED]);
    expect(await connectorsApi.syncNow('c1', { sleep: async () => {} })).toEqual({ reported: true });
  });

  it('a refused request is an error, not a silent wait', async () => {
    vi.stubGlobal('fetch', async () => json({ detail: 'Only a connector fed by CORE can be synced from here.' }, 400));
    await expect(connectorsApi.syncNow('c1', { sleep: async () => {} })).rejects.toThrow(/400/);
  });
});
