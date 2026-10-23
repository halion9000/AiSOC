import { beforeEach, describe, expect, it, vi } from 'vitest';
import { render, screen, waitFor } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import type { DeviceList, DeviceRow } from '@/lib/api';

const listMock = vi.fn();
const exportMock = vi.fn();
vi.mock('@/lib/api', () => ({
  devicesApi: { rollup: async () => [], merges: async () => [], list: (...a: unknown[]) => listMock(...a), exportCsv: (...a: unknown[]) => exportMock(...a), setMaster: vi.fn(), hide: vi.fn(), unhide: vi.fn(), duplicates: async () => ({ items: [] }) },
  msspApi: { listChildren: async () => [] },
  apiErrorDetail: () => null,
}));
const routerParams = vi.hoisted(() => ({ current: new URLSearchParams('') }));
vi.mock('next/navigation', () => ({ useSearchParams: () => routerParams.current }));
vi.mock('react-hot-toast', () => ({ default: { success: vi.fn(), error: vi.fn() } }));

import DevicesView, { KIND_TABS, filtersFromParams } from './DevicesView';

const NOW = '2026-10-15T15:00:00Z';
const row = (hostname: string, kind: DeviceRow['kind'] = 'computer'): DeviceRow => ({
  id: `d-${hostname}`, tenant_id: 't1', client_name: 'Acme', hostname, serial_number: null, os: 'Windows 11', os_version: null, manufacturer: null, model: null,
  ip_addresses: [], last_seen: NOW, first_seen: NOW, sources: [{ vendor: 'ninjaone', name: hostname, last_seen: NOW }], in_master: true, kind,
});
const answer = (items: DeviceRow[], kinds: DeviceList['summary']['kinds']): DeviceList => ({ master_vendor: null, summary: { total: 10, not_in_master: 0, kinds }, items, total: items.length, page: 1, page_size: 50, pages: 1 });

beforeEach(() => {
  window.localStorage.clear();
  routerParams.current = new URLSearchParams('');
  listMock.mockReset().mockImplementation(async (q: { kind?: string }) => answer(q.kind === 'network' ? [row('SW-1', 'network')] : q.kind === 'camera' ? [row('CAM-1', 'camera')] : [row('PC-1')], { computer: 6, network: 3, camera: 1, other: 0 }));
  exportMock.mockReset().mockResolvedValue('csv');
});

describe('the kind of device tabs', () => {
  it('shows All devices, Computers, Network devices and Cameras with their counts', async () => {
    render(<DevicesView />);
    await screen.findByText('PC-1');
    const names = screen.getAllByRole('tab').map((t) => t.textContent);
    expect(names).toEqual(['All devices10', 'Computers6', 'Network devices3', 'Cameras1']);
    expect(screen.getByRole('tab', { name: /All devices/ })).toHaveAttribute('aria-selected', 'true');
  });

  it('shows Other only when there is something in it', async () => {
    listMock.mockImplementation(async () => answer([row('PC-1')], { computer: 6, network: 3, camera: 1, other: 2 }));
    render(<DevicesView />);
    await screen.findByText('PC-1');
    expect(screen.getByRole('tab', { name: /Other/ })).toHaveTextContent('2');
  });

  it('choosing Network devices asks for that kind, shows only those, and goes back to page 1', async () => {
    render(<DevicesView />);
    await screen.findByText('PC-1');
    await userEvent.click(screen.getByRole('tab', { name: /Network devices/ }));
    await waitFor(() => expect(listMock).toHaveBeenLastCalledWith(expect.objectContaining({ kind: 'network', page: 1 })));
    expect(await screen.findByText('SW-1')).toBeInTheDocument();
    expect(screen.queryByText('PC-1')).toBeNull();
    expect(screen.getByRole('tab', { name: /Network devices/ })).toHaveAttribute('aria-selected', 'true');
  });

  it('Cameras works the same, and All devices clears the choice', async () => {
    render(<DevicesView />);
    await screen.findByText('PC-1');
    await userEvent.click(screen.getByRole('tab', { name: /Cameras/ }));
    expect(await screen.findByText('CAM-1')).toBeInTheDocument();
    await userEvent.click(screen.getByRole('tab', { name: /All devices/ }));
    await waitFor(() => expect(listMock).toHaveBeenLastCalledWith(expect.objectContaining({ kind: undefined })));
  });

  it('no kind is asked for until one is chosen', async () => {
    render(<DevicesView />);
    await screen.findByText('PC-1');
    expect(listMock.mock.calls[0][0].kind).toBeUndefined();
  });

  it('the choice is remembered for next time', async () => {
    const first = render(<DevicesView />);
    await screen.findByText('PC-1');
    await userEvent.click(screen.getByRole('tab', { name: /Cameras/ }));
    await screen.findByText('CAM-1');
    first.unmount();
    render(<DevicesView />);
    expect(await screen.findByText('CAM-1')).toBeInTheDocument();
    expect(screen.getByRole('tab', { name: /Cameras/ })).toHaveAttribute('aria-selected', 'true');
  });

  it('a link can open the page on one kind (?kind=network), and an unknown kind is ignored', async () => {
    expect(filtersFromParams(new URLSearchParams('kind=network'))).toEqual({ kind: 'network' });
    expect(filtersFromParams(new URLSearchParams('kind=toaster'))).toBeNull();
    routerParams.current = new URLSearchParams('kind=camera');
    render(<DevicesView />);
    expect(await screen.findByText('CAM-1')).toBeInTheDocument();
  });

  it('a kind in the tabs list matches what the API accepts', () => {
    expect(KIND_TABS.map((t) => t.value)).toEqual(['', 'computer', 'network', 'camera', 'other']);
  });
});
