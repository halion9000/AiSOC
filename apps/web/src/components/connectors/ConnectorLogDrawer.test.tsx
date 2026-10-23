import { beforeEach, describe, expect, it, vi } from 'vitest';
import { render, screen, waitFor } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { SWRConfig } from 'swr';
import type { Connector, ConnectorLogEntry } from '@/lib/api';

const api = vi.hoisted(() => ({ log: vi.fn() }));
vi.mock('@/lib/api', () => ({ connectorsApi: api }));

import { ConnectorLogDrawer, describeEntry } from './ConnectorLogDrawer';

const connector = { id: 'c1', name: 'NinjaOne (via CORE)' } as Connector;
const entry = (over: Partial<ConnectorLogEntry>): ConnectorLogEntry => ({ at: '2026-10-16T18:18:44Z', status: 'warning', message: null, fetched: 0, sent: 0, ...over }) as ConnectorLogEntry;

function open(onClose = vi.fn()) {
  render(
    <SWRConfig value={{ provider: () => new Map(), dedupingInterval: 0, shouldRetryOnError: false }}>
      <ConnectorLogDrawer connector={connector} onClose={onClose} />
    </SWRConfig>,
  );
  return onClose;
}

beforeEach(() => {
  api.log.mockReset();
});

describe('describeEntry', () => {
  it("uses the message CORE reported", () => {
    expect(describeEntry(entry({ message: 'Alerts are flowing, but ninjaone devices: 48 device(s) belong to clients not mapped yet' }))).toMatch(/48 device/);
  });
  it('explains a healthy line that has no message by its counts', () => {
    expect(describeEntry(entry({ status: 'ok', fetched: 1200, sent: 7 }))).toBe('Running normally: 1,200 fetched, 7 sent in that run.');
  });
  it('says so when a failing line has no details', () => {
    expect(describeEntry(entry({ status: 'error' }))).toBe('No details were reported.');
  });
});

describe('ConnectorLogDrawer', () => {
  it('lists the lines newest first with their status words', async () => {
    api.log.mockResolvedValue([entry({ status: 'warning', message: 'newest' }), entry({ status: 'ok', fetched: 3, sent: 1, at: '2026-10-16T16:00:00Z' }), entry({ status: 'error', message: 'oldest', at: '2026-10-16T15:00:00Z' })]);
    open();
    expect(await screen.findByText('newest')).toBeInTheDocument();
    const items = screen.getAllByRole('listitem');
    expect(items).toHaveLength(3);
    expect(items[0]).toHaveTextContent('Warning');
    expect(items[1]).toHaveTextContent('Healthy');
    expect(items[2]).toHaveTextContent('Error');
    expect(api.log).toHaveBeenCalledWith('c1');
  });

  it('says nothing has been logged yet, instead of showing an empty list', async () => {
    api.log.mockResolvedValue([]);
    open();
    expect(await screen.findByText(/Nothing logged yet/)).toBeInTheDocument();
    expect(screen.queryByRole('list')).not.toBeInTheDocument();
  });

  it('closes from the Close button, the backdrop and the Escape key', async () => {
    api.log.mockResolvedValue([]);
    const onClose = open();
    await screen.findByText(/Nothing logged yet/);
    await userEvent.click(screen.getByRole('button', { name: 'Close' }));
    await userEvent.click(screen.getByRole('button', { name: 'Close log' }));
    await userEvent.keyboard('{Escape}');
    await waitFor(() => expect(onClose).toHaveBeenCalledTimes(3));
  });
});
