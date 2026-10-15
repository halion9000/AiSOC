import { beforeEach, describe, expect, it, vi } from 'vitest';
import { render, screen, waitFor, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import type { DeviceList, DeviceRow } from '@/lib/api';

const listMock = vi.fn();
const masterMock = vi.fn();
const childrenMock = vi.fn();
vi.mock('@/lib/api', () => ({
  devicesApi: { list: (...a: unknown[]) => listMock(...a), setMaster: (...a: unknown[]) => masterMock(...a) },
  msspApi: { listChildren: () => childrenMock() },
}));
vi.mock('react-hot-toast', () => ({ default: { success: vi.fn(), error: vi.fn() } }));

import DevicesView, { specs } from './DevicesView';

const NOW = '2026-10-15T15:00:00Z';
function device(over: Partial<DeviceRow> & { hostname: string }): DeviceRow {
  return {
    id: `d-${over.hostname}`, tenant_id: 't1', client_name: 'Acme', serial_number: null, os: 'Windows 11', os_version: null, manufacturer: null, model: null,
    ip_addresses: [], last_seen: NOW, first_seen: NOW, sources: [{ vendor: 'ninjaone', name: over.hostname, last_seen: NOW }], in_master: true, ...over,
  };
}
function list(items: DeviceRow[], over: Partial<DeviceList> = {}): DeviceList {
  return { master_vendor: null, summary: { total: items.length, not_in_master: 0 }, items, total: items.length, page: 1, page_size: 50, pages: 1, ...over };
}

beforeEach(() => {
  listMock.mockReset();
  masterMock.mockReset().mockResolvedValue({ master_vendor: 'ninjaone' });
  childrenMock.mockReset().mockResolvedValue([{ id: 'c1', name: 'Acme', mssp_role: 'child' }]);
});

describe('DevicesView', () => {
  it('shows one row per device with every tool that feeds it', async () => {
    listMock.mockResolvedValue(
      list([
        device({
          hostname: 'FRONT-DESK',
          serial_number: 'SER-1',
          sources: [
            { vendor: 'ninjaone', name: 'FRONT-DESK', last_seen: NOW },
            { vendor: 'addigy', name: 'front-desk', last_seen: NOW },
          ],
        }),
      ]),
    );
    render(<DevicesView />);
    const row = (await screen.findByText('FRONT-DESK')).closest('tr') as HTMLElement;
    expect(within(row).getByText('SER-1')).toBeInTheDocument();
    expect(within(row).getByAltText('NinjaOne')).toBeInTheDocument();
    expect(within(row).getByAltText('Addigy')).toBeInTheDocument();
    expect(screen.getByTestId('devices-total')).toHaveTextContent('1');
  });

  it('flags a device the master tool does not report, and the tally counts it', async () => {
    listMock.mockResolvedValue(
      list([device({ hostname: 'ONLY-ADDIGY', in_master: false, sources: [{ vendor: 'addigy', name: 'x', last_seen: NOW }] })], {
        master_vendor: 'ninjaone',
        summary: { total: 5, not_in_master: 1 },
      }),
    );
    render(<DevicesView />);
    expect(await screen.findByText('Not in NinjaOne', { selector: 'span' })).toBeInTheDocument();
    expect(screen.getByTestId('devices-gaps')).toHaveTextContent('1');
  });

  it('the gap card narrows the list to devices missing from the master', async () => {
    listMock.mockResolvedValue(list([device({ hostname: 'A' })], { master_vendor: 'ninjaone', summary: { total: 5, not_in_master: 1 } }));
    render(<DevicesView />);
    await screen.findByText('A');
    await userEvent.click(screen.getByRole('button', { name: /Not in NinjaOne/ }));
    await waitFor(() => expect(listMock).toHaveBeenLastCalledWith(expect.objectContaining({ notInMaster: true })));
  });

  it('choosing a master tool saves it and reloads', async () => {
    listMock.mockResolvedValue(list([device({ hostname: 'A' })]));
    render(<DevicesView />);
    await screen.findByText('A');
    await userEvent.selectOptions(screen.getByLabelText('Master device list'), 'ninjaone');
    await waitFor(() => expect(masterMock).toHaveBeenCalledWith('ninjaone'));
    expect(listMock.mock.calls.length).toBeGreaterThan(1);
  });

  it('filters by client and by tool through the API', async () => {
    listMock.mockResolvedValue(list([device({ hostname: 'A' })]));
    render(<DevicesView />);
    await screen.findByText('A');
    await userEvent.selectOptions(await screen.findByLabelText('Client'), 'c1');
    await waitFor(() => expect(listMock).toHaveBeenLastCalledWith(expect.objectContaining({ clientId: 'c1' })));
    await userEvent.selectOptions(screen.getByLabelText('Reported by'), 'addigy');
    await waitFor(() => expect(listMock).toHaveBeenLastCalledWith(expect.objectContaining({ vendor: 'addigy', clientId: 'c1' })));
  });

  it('opening a row lists each feeding tool and the name it uses', async () => {
    listMock.mockResolvedValue(
      list([device({ hostname: 'MAC-1', model: 'MacBook Pro', sources: [{ vendor: 'addigy', name: 'Hals-MacBook', last_seen: NOW }] })]),
    );
    render(<DevicesView />);
    await userEvent.click(await screen.findByText('MAC-1'));
    expect(screen.getByText('Feeding this device')).toBeInTheDocument();
    expect(screen.getByText('as “Hals-MacBook”')).toBeInTheDocument();
    expect(screen.getByText('MacBook Pro')).toBeInTheDocument();
  });

  it('shows the failure instead of an empty table', async () => {
    listMock.mockRejectedValue(new Error('boom'));
    render(<DevicesView />);
    expect(await screen.findByRole('alert')).toHaveTextContent('boom');
  });

  it('without a client list (no clients) the client picker is not shown', async () => {
    childrenMock.mockResolvedValue([]);
    listMock.mockResolvedValue(list([device({ hostname: 'A' })]));
    render(<DevicesView />);
    await screen.findByText('A');
    expect(screen.queryByLabelText('Client')).toBeNull();
  });
});

describe('specs', () => {
  it('shows memory, processor and disks from the feed that reports them', () => {
    const d = device({ hostname: 'H',
      sources: [
        { vendor: 'addigy', name: 'x', last_seen: NOW },
        { vendor: 'ninjaone', name: 'x', last_seen: NOW, details: { memory_gb: 16, processor: 'Intel i7', cpu_cores: 4, disks: [{ name: 'C:', size_gb: 511, free_gb: 120 }] } },
      ],
    });
    expect(specs(d)).toEqual([
      ['Memory', '16 GB'],
      ['Processor', 'Intel i7 (4 cores)'],
      ['Disks', 'C: 511 GB (120 free)'],
    ]);
  });

  it('shows nothing when no feed reports specs', () => {
    expect(specs(device({ hostname: 'H' }))).toEqual([]);
  });
});
