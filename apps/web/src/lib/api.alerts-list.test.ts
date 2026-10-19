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

  it('sends the client and page size under the API\'s snake_case names and keeps the client name', async () => {
    let url = '';
    vi.stubGlobal('fetch', async (u: string) => {
      url = String(u);
      return json({ items: [{ id: 'k1', title: 'x', severity: 'low', status: 'new', client_name: 'Setpoint', created_at: '2026-10-13T00:00:00Z' }], total: 1 });
    });
    const out = await alertsApi.list({ clientId: 'abc-123', pageSize: 50, severity: 'high' });
    expect(url).toContain('client_id=abc-123');
    expect(url).toContain('page_size=50');
    expect(url).toContain('severity=high');
    expect(url).not.toContain('clientId');
    expect(out.alerts[0].clientName).toBe('Setpoint');
  });

  it('exposes the first named host as device, and none when the list is empty or blank', async () => {
    vi.stubGlobal('fetch', async () =>
      json({
        items: [
          { id: 'a', title: 'x', severity: 'low', status: 'new', affected_hosts: ['  ', ' HCC-FS01 ', 'other'], created_at: '2026-10-13T00:00:00Z' },
          { id: 'b', title: 'y', severity: 'low', status: 'new', affected_hosts: [], created_at: '2026-10-13T00:00:00Z' },
          { id: 'c', title: 'z', severity: 'low', status: 'new', created_at: '2026-10-13T00:00:00Z' },
        ],
        total: 3,
      }),
    );
    const out = await alertsApi.list();
    expect(out.alerts.map((a) => a.device)).toEqual(['HCC-FS01', undefined, undefined]);
  });

  it('sends the device as the device query parameter', async () => {
    let url = '';
    vi.stubGlobal('fetch', async (u: string) => {
      url = String(u);
      return json({ items: [], total: 0 });
    });
    await alertsApi.list({ device: 'HCC-FS01' });
    expect(url).toContain('device=HCC-FS01');
  });

  it('passes the server tally through', async () => {
    vi.stubGlobal('fetch', async () => json({ summary: { total: 540, critical: 26, high: 21, unresolved: 255, no_ticket: 12 }, items: [], total: 21 }));
    const out = await alertsApi.list({ severity: 'high' });
    expect(out.summary).toEqual({ total: 540, critical: 26, high: 21, unresolved: 255, noTicket: 12 });
    expect(out.total).toBe(21);
  });
});

describe('alertsApi.get related entities', () => {
  const detail = (related: unknown[]) => ({ id: 'a1', title: 't', severity: 'low', status: 'new', created_at: '2026-10-13T00:00:00Z', related_entities: related });

  it('reads the API shape {group, kind, value, pivot}: group is the column, kind the concrete type, pivot the link', async () => {
    vi.stubGlobal('fetch', async () =>
      json(
        detail([
          { group: 'principal', kind: 'host', value: 'HCC-FS01', label: null, pivot: '/attack-graph?entity=host:HCC-FS01' },
          { group: 'network', kind: 'ip', value: '10.0.0.5', pivot: null },
        ]),
      ),
    );
    const out = await alertsApi.get('a1');
    expect(out.relatedEntities).toEqual([
      { kind: 'principal', type: 'host', value: 'HCC-FS01', label: null, pivotPath: '/attack-graph?entity=host:HCC-FS01' },
      { kind: 'network', type: 'ip', value: '10.0.0.5', label: null, pivotPath: null },
    ]);
  });

  it('still reads the older shape {kind: column, type, pivot_path}', async () => {
    vi.stubGlobal('fetch', async () => json(detail([{ kind: 'principal', type: 'user', value: 'alice', pivot_path: '/graph/user/alice' }])));
    const out = await alertsApi.get('a1');
    expect(out.relatedEntities).toEqual([{ kind: 'principal', type: 'user', value: 'alice', label: null, pivotPath: '/graph/user/alice' }]);
  });
});
