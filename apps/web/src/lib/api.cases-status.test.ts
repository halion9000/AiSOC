import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { casesApi } from './api';

const json = (body: unknown) => new Response(JSON.stringify(body), { status: 200, headers: { 'Content-Type': 'application/json' } });

beforeEach(() => window.localStorage.clear());
afterEach(() => vi.unstubAllGlobals());

describe('casesApi.list', () => {
  it('asks the API for every case still waiting when Open is chosen, and for every case being worked when In Progress is', async () => {
    const urls: string[] = [];
    vi.stubGlobal('fetch', async (url: string) => {
      urls.push(String(url));
      return json([]);
    });
    await casesApi.list({ status: 'open', limit: 500 });
    await casesApi.list({ status: 'in_progress' });
    await casesApi.list({ status: 'resolved' });
    expect(urls.map((u) => decodeURIComponent(u))).toEqual([
      expect.stringContaining('status=new,triaged'),
      expect.stringContaining('status=investigating,contained'),
      expect.stringContaining('status=resolved'),
    ]);
    expect(urls[0]).toContain('limit=500');
  });
});
