import { beforeEach, describe, expect, it, vi } from 'vitest';
import { act, render, screen, waitFor } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { SWRConfig } from 'swr';

const api = vi.hoisted(() => ({ list: vi.fn(), health: vi.fn(), catalog: vi.fn(), test: vi.fn(), delete: vi.fn() }));
vi.mock('@/lib/api', () => ({ connectorsApi: api }));
vi.mock('react-hot-toast', () => ({ __esModule: true, default: Object.assign(vi.fn(), { error: vi.fn(), success: vi.fn() }) }));
// Exposes the view's onCreated callback, which re-fetches the list: the way these tests trigger a real refresh.
vi.mock('./AddConnectorModal', () => ({ AddConnectorModal: ({ onCreated }: { onCreated: () => void }) => <button onClick={onCreated}>trigger-refresh</button> }));
vi.mock('./EditConnectorModal', () => ({ EditConnectorModal: () => null }));
vi.mock('./InboxTokensPanel', () => ({ InboxTokensPanel: () => null }));
vi.mock('./ConnectorInstanceList', () => ({
  ConnectorInstanceList: ({ connectors }: { connectors: { id: string; name: string }[] }) => (
    <div data-testid="instance-list">
      {connectors.length === 0 ? <span>no instances</span> : connectors.map((c) => <span key={c.id}>{c.name}</span>)}
    </div>
  ),
}));

import { ConnectorsView } from './ConnectorsView';

const connectors = [
  { id: 'c1', name: 'Okta production', type: 'okta', status: 'active', alertCount: 40 },
  { id: 'c2', name: 'CrowdStrike', type: 'crowdstrike', status: 'error', alertCount: 2 },
];
const health = { total: 2, healthy: 1, unhealthy: 1, totalEventsIngested: 1234, driftedRecently: 0, totalEventsDropped: 0, lastDriftAt: null };

function renderView() {
  return render(
    <SWRConfig value={{ provider: () => new Map(), dedupingInterval: 0, shouldRetryOnError: false }}>
      <ConnectorsView />
    </SWRConfig>,
  );
}
/** The text of the stat tile with this label, e.g. "1,234Events Ingested". */
const tile = (label: string) => screen.getByText(label).parentElement!.textContent;

beforeEach(() => {
  Object.values(api).forEach((m) => m.mockReset());
  api.list.mockResolvedValue({ connectors });
  api.health.mockResolvedValue(health);
  api.catalog.mockResolvedValue({ connectors: [] });
});

// When the connector list could not be loaded this screen said "Connectors API unreachable, showing demo instances so you can explore the interface" (no demo instances exist) over an EMPTY list,
// and its stat tiles computed from that empty list: Total 0, Active 0, Errors 0, Events 0. "0 errors" reads as healthy when the truth is that nothing is known.
describe('when the connector list loads', () => {
  it('shows the real connectors and the real figures, with no demo wording', async () => {
    const { container } = renderView();
    expect(await screen.findByText('Okta production')).toBeInTheDocument();
    expect(screen.getByText('CrowdStrike')).toBeInTheDocument();
    await waitFor(() => expect(tile('Events Ingested')).toBe('1,234Events Ingested'));
    expect(tile('Errors')).toBe('1Errors');
    expect(container.textContent).not.toMatch(/demo/i);
  });

  it('shows true zeros for a workspace that really has no connectors', async () => {
    api.list.mockResolvedValue({ connectors: [] });
    api.health.mockResolvedValue({ ...health, total: 0, healthy: 0, unhealthy: 0, totalEventsIngested: 0 });
    renderView();
    expect(await screen.findByText('no instances')).toBeInTheDocument();
    await waitFor(() => expect(tile('Errors')).toBe('0Errors'));
    expect(screen.queryByText("Couldn't load connectors")).not.toBeInTheDocument();
  });
});

describe('when the connector list cannot be loaded', () => {
  beforeEach(() => {
    api.list.mockRejectedValue(new Error('HTTP 503'));
    api.health.mockResolvedValue(null);
  });

  it('says so with the reason, offers a working Retry, and shows no instance list at all', async () => {
    const { container } = renderView();
    expect(await screen.findByText("Couldn't load connectors")).toBeInTheDocument();
    expect(screen.getByText(/HTTP 503/)).toBeInTheDocument();
    expect(screen.queryByTestId('instance-list')).not.toBeInTheDocument();
    expect(container.textContent).not.toMatch(/demo/i);

    api.list.mockResolvedValue({ connectors });
    await userEvent.setup().click(screen.getByRole('button', { name: 'Retry' }));
    expect(await screen.findByText('Okta production')).toBeInTheDocument();
    expect(screen.queryByText("Couldn't load connectors")).not.toBeInTheDocument();
  });

  it('shows dashes, never invented zeros, for the figures it does not know', async () => {
    renderView();
    await screen.findByText("Couldn't load connectors");
    for (const label of ['Total Connectors', 'Active', 'Errors', 'Events Ingested']) {
      expect(tile(label)).toBe(`\u2014${label}`);
    }
  });

  it('still shows the health summary figures when only the list failed (they come from a separate endpoint and are real)', async () => {
    api.health.mockResolvedValue(health);
    renderView();
    await screen.findByText("Couldn't load connectors");
    await waitFor(() => expect(tile('Errors')).toBe('1Errors'));
    expect(tile('Total Connectors')).toBe('2Total Connectors');
  });
});

describe('when a later refresh fails', () => {
  it('keeps the last loaded connectors and figures, and says the refresh failed', async () => {
    renderView();
    await screen.findByText('Okta production');
    await waitFor(() => expect(tile('Errors')).toBe('1Errors'));

    api.list.mockRejectedValue(new Error('HTTP 500'));
    await userEvent.setup().click(screen.getByRole('button', { name: 'trigger-refresh' }));

    expect(await screen.findByText(/Couldn.t refresh connectors; showing what was last loaded/)).toBeInTheDocument();
    expect(screen.getByText('Okta production')).toBeInTheDocument(); // still there
    expect(screen.queryByText("Couldn't load connectors")).not.toBeInTheDocument(); // this is not the first-load failure
    expect(tile('Errors')).toBe('1Errors'); // and the figures were not zeroed
  });
});
