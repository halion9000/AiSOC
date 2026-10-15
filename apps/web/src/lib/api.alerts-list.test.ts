import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { alertsApi } from './api';

/** The API's GET /api/v1/alerts answers { items, total, page, page_size, pages }. The list must read the rows from `items`. */
const json = (body: unknown) => new Response(JSON.stringify(body), { status: 200, headers: { 'Content-Type': 'application/json' } });

beforeEach(() => window.localStorage.clear());
afterEach(() => vi.unstubAllGlobals());

describe('alertsApi.list', () => {
  it("returns the rows the API sends under 'items', not just the total", async () => {
    vi.stubGlobal('fetch', async () =>
      json({
        items: [
          { id: 'a1', title: 'Persistent foothold', severity: 'high', status: 'new', created_at: '2026-10-13T19:40:00Z' },
          { id: 'a2', title: 'Second', severity: 'low', status: 'new', created_at: '2026-10-12T19:40:00Z' },
        ],
        total: 279,
        page: 1,
        page_size: 25,
        pages: 12,
      }),
    );
    const out = await alertsApi.list({ page: 1, pageSize: 25 });
    expect(out.total).toBe(279);
    expect(out.alerts.map((a) => a.id)).toEqual(['a1', 'a2']);
  });

  it("still reads rows sent under 'alerts' (older responses)", async () => {
    vi.stubGlobal('fetch', async () => json({ alerts: [{ id: 'old1', title: 'x', severity: 'low', status: 'new', created_at: '2026-10-12T00:00:00Z' }], total: 1 }));
    const out = await alertsApi.list();
    expect(out.alerts.map((a) => a.id)).toEqual(['old1']);
  });

  it("labels CORE-forwarded alerts by the tool, not 'Generic Generic JSON'", async () => {
    vi.stubGlobal('fetch', async () =>
      json({
        items: [
          { id: 'c1', title: 'x', severity: 'low', status: 'new', connector_type: 'Generic Generic JSON', raw_event: { source: 'ninjaone' }, created_at: '2026-10-13T00:00:00Z' },
          { id: 'c2', title: 'y', severity: 'low', status: 'new', connector_type: 'okta', raw_event: {}, created_at: '2026-10-13T00:00:00Z' },
        ],
        total: 2,
      }),
    );
    const out = await alertsApi.list();
    expect(out.alerts.map((a) => a.source)).toEqual(['ninjaone', 'okta']);
  });
});
