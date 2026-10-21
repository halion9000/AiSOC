import { beforeEach, describe, expect, it, vi } from 'vitest';
import { render, screen, waitFor, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { SWRConfig } from 'swr';
import type { Connector } from '@/lib/api';

const api = vi.hoisted(() => ({ log: vi.fn() }));
vi.mock('@/lib/api', () => ({ connectorsApi: api }));

import { ConnectorInstanceList, feedVendor } from './ConnectorInstanceList';

const base = { status: 'active', alertCount: 0, tenantId: 't1', category: 'edr' } as unknown as Connector;
const feed = (vendor: string | undefined, name: string, id = `f-${vendor}`) =>
  ({ ...base, id, name, type: 'core_feed', config: vendor ? { vendor, managed_by: 'core' } : {} }) as Connector;
const okta = { ...base, id: 'o1', name: 'Okta production', type: 'okta' } as Connector;

function renderList(connectors: Connector[]) {
  return render(
    <SWRConfig value={{ provider: () => new Map(), dedupingInterval: 0, shouldRetryOnError: false }}>
      <ConnectorInstanceList connectors={connectors} onTest={vi.fn()} onAdd={vi.fn()} />
    </SWRConfig>,
  );
}

beforeEach(() => {
  api.log.mockReset(); // braces: a function returned from beforeEach would run as a teardown hook
});

describe('the badge on a CORE-fed connector card', () => {
  it('is the vendor logo, not the first three letters of the type', () => {
    renderList([feed('huntress', 'Huntress (via CORE)'), feed('ninjaone', 'NinjaOne (via CORE)')]);
    expect(screen.getByRole('img', { name: 'Huntress' })).toHaveAttribute('src', '/vendors/huntress.png');
    expect(screen.getByRole('img', { name: 'NinjaOne' })).toHaveAttribute('src', '/vendors/ninjaone.png');
    expect(screen.queryByText('COR')).not.toBeInTheDocument();
  });

  it('includes Blumira and Field Effect, whose logos were added to the vendors folder', () => {
    renderList([feed('blumira', 'Blumira (via CORE)'), feed('fieldeffect', 'Field Effect (via CORE)')]);
    expect(screen.getByRole('img', { name: 'Blumira' })).toHaveAttribute('src', '/vendors/blumira.png');
    expect(screen.getByRole('img', { name: 'Field Effect' })).toHaveAttribute('src', '/vendors/fieldeffect.png');
  });

  it('is a labelled letter for a vendor with no logo file yet, never "COR"', () => {
    renderList([feed('newtool', 'Newtool (via CORE)')]);
    expect(screen.getByRole('img', { name: 'Newtool' })).toHaveTextContent('N');
    expect(screen.queryByText('COR')).not.toBeInTheDocument();
  });

  it('keeps the type abbreviation for every other connector', () => {
    renderList([okta]);
    expect(screen.getByText('OKT')).toBeInTheDocument();
  });

  it('reads the vendor from the connector config, only for a CORE feed', () => {
    expect(feedVendor(feed('petra', 'Petra'))).toBe('petra');
    expect(feedVendor(feed(undefined, 'No vendor'))).toBeUndefined();
    expect(feedVendor({ ...okta, config: { vendor: 'huntress' } } as Connector)).toBeUndefined();
  });
});

describe('the Log button', () => {
  it('is only on CORE-fed cards, because only those have a log', () => {
    renderList([okta]);
    expect(screen.queryByRole('button', { name: /log for/i })).not.toBeInTheDocument();
  });

  it('opens that connector\'s log, newest first, with the words CORE reported', async () => {
    api.log.mockResolvedValue([
      { at: '2026-10-16T16:00:00Z', status: 'ok', message: null, fetched: 12, sent: 12 },
      { at: '2026-10-16T15:00:00Z', status: 'warning', message: '0 of 12 alerts matched a Halo ticket', fetched: 12, sent: 12 },
      { at: '2026-10-16T14:00:00Z', status: 'error', message: 'Blumira returned 403', fetched: 0, sent: 0 },
    ]);
    renderList([feed('ninjaone', 'NinjaOne (via CORE)', 'n1')]);
    await userEvent.setup().click(screen.getByRole('button', { name: 'Open the log for NinjaOne (via CORE)' }));
    const dialog = await screen.findByRole('dialog', { name: 'NinjaOne (via CORE) log' });
    expect(api.log).toHaveBeenCalledWith('n1');
    const items = await within(dialog).findAllByRole('listitem');
    expect(items.map((li) => li.textContent)).toEqual([
      expect.stringContaining('Running normally: 12 fetched, 12 sent in that run.'),
      expect.stringContaining('0 of 12 alerts matched a Halo ticket'),
      expect.stringContaining('Blumira returned 403'),
    ]);
    expect(items[0]).toHaveTextContent('Healthy');
    expect(items[1]).toHaveTextContent('Warning');
    expect(items[2]).toHaveTextContent('Error');
  });

  it('says so when nothing has been logged yet', async () => {
    api.log.mockResolvedValue([]);
    renderList([feed('petra', 'Petra (via CORE)')]);
    await userEvent.setup().click(screen.getByRole('button', { name: /Open the log for Petra/ }));
    expect(await screen.findByText(/Nothing logged yet/)).toBeInTheDocument();
  });

  it('says it could not load when the request fails, instead of an empty list', async () => {
    api.log.mockImplementation(async () => {
      throw new Error('boom');
    });
    renderList([feed('petra', 'Petra (via CORE)')]);
    await userEvent.setup().click(screen.getByRole('button', { name: /Open the log for Petra/ }));
    expect(await screen.findByText(/Couldn't load the log/)).toBeInTheDocument();
    expect(screen.queryByText(/Nothing logged yet/)).not.toBeInTheDocument();
  });

  it('closes with the Close button, the backdrop and Escape', async () => {
    api.log.mockResolvedValue([]);
    renderList([feed('petra', 'Petra (via CORE)')]);
    const user = userEvent.setup();
    const open = () => user.click(screen.getByRole('button', { name: /Open the log for Petra/ }));

    await open();
    await screen.findByRole('dialog');
    await user.click(screen.getByRole('button', { name: 'Close' }));
    await waitFor(() => expect(screen.queryByRole('dialog')).not.toBeInTheDocument());

    await open();
    await user.click(await screen.findByRole('button', { name: 'Close log' }));
    await waitFor(() => expect(screen.queryByRole('dialog')).not.toBeInTheDocument());

    await open();
    await screen.findByRole('dialog');
    await user.keyboard('{Escape}');
    await waitFor(() => expect(screen.queryByRole('dialog')).not.toBeInTheDocument());
  });
});

describe('the Map clients button', () => {
  const unmapped = (vendor: string) =>
    ({ ...feed(vendor, `${vendor} (via CORE)`), status: 'warning', errorMessage: `Alerts are flowing, but ${vendor} devices: 48 device(s) belong to clients not mapped yet (map them on the MSSP page)` }) as Connector;

  it('opens the MSSP page on that tool\'s clients, because unmapped devices are not stored and so are not on the Devices page', () => {
    renderList([unmapped('ninjaone')]);
    expect(screen.getByRole('link', { name: 'Map clients' })).toHaveAttribute('href', '/mssp?vendor=ninjaone');
  });

  it('is not shown for any other warning, or for a healthy card', () => {
    renderList([
      { ...unmapped('addigy'), errorMessage: 'Alerts are flowing, but addigy devices: 500' } as Connector,
      feed('petra', 'Petra (via CORE)'),
    ]);
    expect(screen.queryByRole('link', { name: 'Map clients' })).not.toBeInTheDocument();
  });

  it('can be told apart per tool when several cards have the problem', () => {
    renderList([unmapped('ninjaone'), unmapped('threatmate')]);
    expect(screen.getAllByRole('link', { name: 'Map clients' }).map((a) => a.getAttribute('href'))).toEqual(['/mssp?vendor=ninjaone', '/mssp?vendor=threatmate']);
  });
});

describe('the counts on a CORE-fed card', () => {
  it('says how many devices the last sync read for a tool that only supplies devices, and how many events for one that raises alerts', () => {
    const devicesOnly = { ...feed('dnsfilter', 'DNSFilter (via CORE)'), config: { vendor: 'dnsfilter', managed_by: 'core', kind: 'devices', devices: 850 }, lastSync: new Date().toISOString() } as Connector;
    const alerts = { ...feed('huntress', 'Huntress (via CORE)'), alertCount: 1311, lastSync: new Date().toISOString() } as Connector;
    renderList([devicesOnly, alerts]);
    expect(screen.getByText('Devices read')).toBeInTheDocument();
    expect(screen.getByText('850')).toBeInTheDocument();
    expect(screen.getByText('Events ingested')).toBeInTheDocument();
    expect(screen.getByText('1,311')).toBeInTheDocument();
    expect(screen.getAllByText('just now')).toHaveLength(2);
  });
});
