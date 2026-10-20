import { beforeEach, describe, expect, it, vi } from 'vitest';
import { render, waitFor } from '@testing-library/react';
import { SWRConfig } from 'swr';

const list = vi.hoisted(() => vi.fn());
const params = vi.hoisted(() => ({ current: new URLSearchParams('') }));
vi.mock('next/navigation', () => ({ useSearchParams: () => params.current }));
vi.mock('@/lib/api', async (importOriginal) => ({
  ...(await importOriginal<typeof import('@/lib/api')>()),
  alertsApi: { list: (...a: unknown[]) => list(...a) },
  connectorsApi: { list: async () => ({ connectors: [] }) },
  msspApi: { listChildren: async () => [] },
}));
vi.mock('./EntityRiskQueue', () => ({ EntityRiskQueue: () => null }));
vi.mock('./InvestigationRail', () => ({ InvestigationRail: () => null }));
vi.mock('@/components/saved-views/SavedViewsBar', () => ({ SavedViewsBar: () => null }));

import { AlertsView } from './AlertsView';

const empty = { alerts: [], total: 0, summary: { total: 0, critical: 0, high: 0, unresolved: 0, noTicket: 0 } };

function show() {
  return render(
    <SWRConfig value={{ provider: () => new Map(), dedupingInterval: 0 }}>
      <AlertsView />
    </SWRConfig>,
  );
}

beforeEach(() => {
  window.localStorage.clear();
  list.mockReset().mockResolvedValue(empty);
  params.current = new URLSearchParams('');
});

describe('Alerts remembers its filters', () => {
  it('opens with the filters saved last time, and saves what is picked', async () => {
    window.localStorage.setItem('aisoc.filters.alerts', JSON.stringify({ severity: 'critical', status: 'resolved', ticket: 'none' }));
    show();
    await waitFor(() => expect(list).toHaveBeenLastCalledWith(expect.objectContaining({ severity: 'critical', status: 'resolved', ticket: 'none', page: 1 })));
    const saved = JSON.parse(window.localStorage.getItem('aisoc.filters.alerts') ?? '{}');
    expect(saved).toMatchObject({ severity: 'critical', status: 'resolved', ticket: 'none' });
  });

  it('opens on Open all when nothing was saved', async () => {
    show();
    await waitFor(() => expect(list).toHaveBeenCalled());
    expect(list).toHaveBeenLastCalledWith(expect.objectContaining({ status: 'open' }));
  });

  it('a link that names a device or a status opens exactly that, and does not overwrite what was saved', async () => {
    window.localStorage.setItem('aisoc.filters.alerts', JSON.stringify({ severity: 'critical', status: 'resolved' }));
    params.current = new URLSearchParams('device=HCC-FS01');
    show();
    await waitFor(() => expect(list).toHaveBeenCalled());
    expect(list).toHaveBeenLastCalledWith(expect.objectContaining({ device: 'HCC-FS01', status: 'open' }));
    expect(list).not.toHaveBeenCalledWith(expect.objectContaining({ severity: 'critical' }));
    expect(JSON.parse(window.localStorage.getItem('aisoc.filters.alerts') ?? '{}')).toMatchObject({ severity: 'critical', status: 'resolved' });
  });

  it('a link from a client page (client, severity and ticket) opens exactly that list and leaves what was saved alone', async () => {
    window.localStorage.setItem('aisoc.filters.alerts', JSON.stringify({ severity: 'low', status: 'resolved' }));
    params.current = new URLSearchParams('client=c9&severity=critical&ticket=none');
    show();
    await waitFor(() => expect(list).toHaveBeenCalled());
    expect(list).toHaveBeenLastCalledWith(expect.objectContaining({ clientId: 'c9', severity: 'critical', ticket: 'none', status: 'open' }));
    expect(JSON.parse(window.localStorage.getItem('aisoc.filters.alerts') ?? '{}')).toMatchObject({ severity: 'low', status: 'resolved' });
  });

  it('ignores a severity or ticket value it does not know', async () => {
    params.current = new URLSearchParams('client=c9&severity=catastrophic&ticket=maybe');
    show();
    await waitFor(() => expect(list).toHaveBeenCalled());
    const sent = list.mock.calls[list.mock.calls.length - 1][0] as Record<string, unknown>;
    expect(sent.severity).toBeUndefined();
    expect(sent.ticket).toBeUndefined();
    expect(sent.clientId).toBe('c9');
  });
});
