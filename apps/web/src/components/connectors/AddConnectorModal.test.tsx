import { beforeEach, describe, expect, it, vi } from 'vitest';
import { render, screen, waitFor, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';

const api = vi.hoisted(() => ({ catalog: vi.fn(), testInline: vi.fn(), create: vi.fn(), lastEvent: vi.fn(), troubleshoot: vi.fn() }));
const toast = vi.hoisted(() => ({ success: vi.fn(), error: vi.fn() }));
vi.mock('@/lib/api', () => ({ connectorsApi: api }));
vi.mock('react-hot-toast', () => ({ __esModule: true, default: toast }));
vi.mock('framer-motion', async () => {
  const React = await import('react');
  const passthrough = ({ children, initial, animate, exit, transition, ...rest }: Record<string, unknown>) => React.createElement('div', rest as object, children as React.ReactNode);
  return { motion: { div: passthrough }, AnimatePresence: ({ children }: { children: React.ReactNode }) => React.createElement(React.Fragment, null, children) };
});

import { AddConnectorModal } from './AddConnectorModal';

const entry = (id: string, name: string, category: string, extra: Record<string, unknown> = {}) => ({ connector_id: id, connector_name: name, category, description: `${name} alerts`, fields: [], ...extra });
const CATALOG = [
  entry('crowdstrike', 'CrowdStrike Falcon', 'edr', {
    fields: [
      { name: 'client_id', label: 'Client ID', type: 'string', required: true, placeholder: 'abc123' },
      { name: 'client_secret', label: 'Client secret', type: 'secret', required: true },
      { name: 'region', label: 'Region', type: 'select', options: [{ value: 'us-1', label: 'US-1' }, { value: 'eu-1', label: 'EU-1' }], default: 'us-1' },
      { name: 'interval', label: 'Interval', type: 'number', default: 5 },
      { name: 'verbose', label: 'Verbose', type: 'boolean' },
      { name: 'tag', label: 'Tag', type: 'string' },
    ],
    docs_url: 'https://docs.example/crowdstrike',
  }),
  entry('okta', 'Okta', 'iam', { oauth: { supported_in_hosted: false } }),
  entry('sentinelone', 'SentinelOne', 'edr'),
  entry('weirdtool', 'Weird Tool', 'brand-new-category'),
];

function open(props: Record<string, unknown> = {}) {
  const onClose = vi.fn();
  const onCreated = vi.fn();
  const view = render(<AddConnectorModal open onClose={onClose} onCreated={onCreated} {...props} />);
  return { onClose, onCreated, ...view };
}

beforeEach(() => {
  api.catalog.mockReset().mockResolvedValue({ connectors: CATALOG });
  api.testInline.mockReset().mockResolvedValue({ success: true, message: 'Connected as svc-account' });
  api.create.mockReset().mockResolvedValue({ id: 'new1', name: 'CrowdStrike Falcon', type: 'crowdstrike', status: 'pending', alertCount: 0 });
  api.lastEvent.mockReset().mockResolvedValue({ last_event_at: null });
  api.troubleshoot.mockReset();
  toast.success.mockReset();
  toast.error.mockReset();
});

describe('AddConnectorModal: picking', () => {
  it('shows nothing when closed', () => {
    const { container } = render(<AddConnectorModal open={false} onClose={() => {}} />);
    expect(container).toBeEmptyDOMElement();
    expect(api.catalog).not.toHaveBeenCalled();
  });

  it('loads the catalog on open and groups connectors by category in the usual order, unknown categories last', async () => {
    open();
    await screen.findByText('Weird Tool');
    const headings = screen.getAllByRole('heading', { level: 3 }).map((h) => h.textContent);
    expect(headings).toEqual(['Most teams pick', 'Endpoint', 'Identity', 'brand-new-category']);
    expect(screen.getByText('4 connector types available')).toBeInTheDocument();
  });

  it('a failed catalog load says so', async () => {
    api.catalog.mockRejectedValue(new Error('catalog offline'));
    open();
    expect(await screen.findByText('Failed to load connector catalog: catalog offline')).toBeInTheDocument();
  });

  it('an empty catalog says nothing is registered', async () => {
    api.catalog.mockResolvedValue({ connectors: [] });
    open();
    expect(await screen.findByText('No connector types are registered in this build.')).toBeInTheDocument();
  });

  it('searching finds by name, id, description or category, hides the curated row, and says when nothing matches', async () => {
    open();
    await screen.findByText('Weird Tool');
    const search = screen.getByPlaceholderText('Search by name, vendor, or capability');
    await userEvent.type(search, 'sentinel');
    expect(screen.getByText('SentinelOne')).toBeInTheDocument();
    expect(screen.queryByText('Okta')).toBeNull();
    expect(screen.queryByText('Most teams pick')).toBeNull();
    await userEvent.clear(search);
    await userEvent.type(search, 'identity-nonsense');
    expect(screen.getByText(/No connectors match/)).toHaveTextContent('No connectors match identity-nonsense.');
    await userEvent.clear(search);
    await userEvent.type(search, 'iam');
    expect(screen.getByText('Okta')).toBeInTheDocument();
    expect(screen.queryByText('SentinelOne')).toBeNull();
  });

  it('opened on a category it shows only that category, with a chip that clears the filter', async () => {
    open({ activeCategory: 'edr' });
    await screen.findByText('SentinelOne');
    expect(screen.queryByText('Okta')).toBeNull();
    expect(screen.queryByText('Most teams pick')).toBeNull();
    await userEvent.click(screen.getByTitle('Clear category filter'));
    expect(screen.getAllByText('Okta').length).toBeGreaterThan(0);
  });

  it('Escape, Cancel and the X close the picker', async () => {
    const { onClose } = open();
    await screen.findByText('Weird Tool');
    await userEvent.keyboard('{Escape}');
    await userEvent.click(screen.getByRole('button', { name: 'Cancel' }));
    await userEvent.click(screen.getByRole('button', { name: 'Close' }));
    expect(onClose).toHaveBeenCalledTimes(3);
  });
});

describe('AddConnectorModal: configuring', () => {
  const pickCrowdStrike = async () => {
    const view = open();
    await screen.findByText('Weird Tool');
    await userEvent.click(screen.getAllByText('CrowdStrike Falcon')[0].closest('button') as HTMLElement);
    return view;
  };

  it('picking a connector shows its form with schema defaults, an instance name and the setup guide link', async () => {
    await pickCrowdStrike();
    expect(screen.getByRole('heading', { name: 'Configure CrowdStrike Falcon' })).toBeInTheDocument();
    expect(screen.getByDisplayValue('CrowdStrike Falcon')).toBeInTheDocument();
    expect(screen.getByDisplayValue('5')).toBeInTheDocument();
    expect(screen.getByRole('combobox')).toHaveValue('us-1');
    expect(screen.getByRole('checkbox')).not.toBeChecked();
    expect(screen.getByRole('link', { name: 'View setup guide' })).toHaveAttribute('href', 'https://docs.example/crowdstrike');
  });

  it('a connector opened from the onboarding page goes straight to its form; an unknown primed id falls back to the picker', async () => {
    const first = open({ primedConnectorId: 'okta' });
    expect(await screen.findByRole('heading', { name: 'Configure Okta' })).toBeInTheDocument();
    first.unmount();
    open({ primedConnectorId: 'removed-long-ago' });
    expect(await screen.findByText('Weird Tool')).toBeInTheDocument();
    expect(screen.getByRole('heading', { name: 'Add connector' })).toBeInTheDocument();
  });

  it('Back returns to the picker', async () => {
    await pickCrowdStrike();
    await userEvent.click(screen.getByRole('button', { name: '← Back' }));
    expect(screen.getByRole('heading', { name: 'Add connector' })).toBeInTheDocument();
  });

  it('Test sends secrets as auth_config and the rest as connector_config, leaving out blank optional ones, and shows the result', async () => {
    await pickCrowdStrike();
    await userEvent.type(screen.getByPlaceholderText('abc123'), 'my-client');
    await userEvent.type(screen.getByPlaceholderText('••••••••'), 'my-secret');
    await userEvent.click(screen.getByRole('button', { name: 'Test connection' }));
    await waitFor(() => expect(api.testInline).toHaveBeenCalledTimes(1));
    expect(api.testInline).toHaveBeenCalledWith({
      connector_type: 'crowdstrike',
      auth_config: { client_secret: 'my-secret' },
      connector_config: { client_id: 'my-client', region: 'us-1', interval: 5, verbose: false },
    });
    expect(await screen.findByText('Connected as svc-account')).toBeInTheDocument();
    expect(toast.success).toHaveBeenCalledWith('Connection test passed');
  });

  it('a required field left blank is still sent (as blank) so the server can say what is missing', async () => {
    await pickCrowdStrike();
    await userEvent.click(screen.getByRole('button', { name: 'Test connection' }));
    await waitFor(() => expect(api.testInline).toHaveBeenCalled());
    const body = api.testInline.mock.calls[0][0];
    expect(body.auth_config).toEqual({ client_secret: '' });
    expect(body.connector_config.client_id).toBe('');
  });

  it('a failed test shows the error in the footer and a toast, and offers the troubleshooter', async () => {
    api.testInline.mockResolvedValue({ success: false, error: 'invalid_client' });
    await pickCrowdStrike();
    await userEvent.click(screen.getByRole('button', { name: 'Test connection' }));
    expect((await screen.findAllByText('invalid_client')).length).toBeGreaterThan(0);
    expect(screen.getByTitle('invalid_client')).toBeInTheDocument();
    expect(toast.error).toHaveBeenCalledWith('invalid_client');
    expect(screen.getByRole('button', { name: /Ask AI to fix/ })).toBeInTheDocument();
  });

  it('a test that cannot even be sent shows that reason', async () => {
    api.testInline.mockRejectedValue(new Error('network down'));
    await pickCrowdStrike();
    await userEvent.click(screen.getByRole('button', { name: 'Test connection' }));
    expect((await screen.findAllByText('network down')).length).toBeGreaterThan(0);
    expect(toast.error).toHaveBeenCalledWith('network down');
    expect(screen.getByRole('button', { name: 'Test connection' })).toBeEnabled();
  });

  it('an empty instance name is refused before anything is sent', async () => {
    await pickCrowdStrike();
    await userEvent.clear(screen.getByDisplayValue('CrowdStrike Falcon'));
    await userEvent.click(screen.getByRole('button', { name: 'Save connector' }));
    expect(toast.error).toHaveBeenCalledWith('Please give this connector an instance name');
    expect(api.create).not.toHaveBeenCalled();
  });

  it('a failed save shows the reason and stays on the form', async () => {
    api.create.mockRejectedValue(new Error('name already used'));
    await pickCrowdStrike();
    await userEvent.click(screen.getByRole('button', { name: 'Save connector' }));
    await waitFor(() => expect(toast.error).toHaveBeenCalledWith('name already used'));
    expect(screen.getByRole('heading', { name: 'Configure CrowdStrike Falcon' })).toBeInTheDocument();
  });
});

describe('AddConnectorModal: saving and verifying', () => {
  async function saveIt() {
    const view = open();
    await screen.findByText('Weird Tool');
    await userEvent.click(screen.getAllByText('CrowdStrike Falcon')[0].closest('button') as HTMLElement);
    const name = screen.getByDisplayValue('CrowdStrike Falcon');
    await userEvent.clear(name);
    await userEvent.type(name, '  Falcon production  ');
    await userEvent.click(screen.getByRole('button', { name: 'Save connector' }));
    return view;
  }

  it('saving creates the connector with the trimmed name, type and category, tells the parent, and moves to verifying', async () => {
    const { onCreated } = await saveIt();
    await waitFor(() => expect(api.create).toHaveBeenCalledTimes(1));
    expect(api.create.mock.calls[0][0]).toMatchObject({ name: 'Falcon production', connector_type: 'crowdstrike', category: 'edr' });
    expect(toast.success).toHaveBeenCalledWith('Connected CrowdStrike Falcon');
    expect(onCreated).toHaveBeenCalledWith(expect.objectContaining({ id: 'new1' }));
    expect(await screen.findByRole('heading', { name: 'Verifying CrowdStrike Falcon' })).toBeInTheDocument();
    expect(screen.getByText('Waiting for first event…')).toBeInTheDocument();
    expect(screen.getByRole('button', { name: 'Close — keep waiting in background' })).toBeInTheDocument();
  });

  it('Escape does not close the wizard once past the picker, so typed credentials are not lost', async () => {
    const { onClose } = open({ primedConnectorId: 'crowdstrike' });
    await screen.findByRole('heading', { name: 'Configure CrowdStrike Falcon' });
    await userEvent.keyboard('{Escape}');
    expect(onClose).not.toHaveBeenCalled();
  });

  it('when the first event arrives it says data is flowing and offers Done', async () => {
    api.lastEvent.mockResolvedValue({ last_event_at: new Date().toISOString(), kind: 'detection' });
    const { onClose } = await saveIt();
    expect(await screen.findByText('Data is flowing')).toBeInTheDocument();
    expect(screen.getByText('First event')).toBeInTheDocument();
    await userEvent.click(screen.getByRole('button', { name: 'Done' }));
    expect(onClose).toHaveBeenCalledTimes(1);
  });

  it('a polling error is shown without ending the wizard', async () => {
    api.lastEvent.mockRejectedValue(new Error('poll failed'));
    await saveIt();
    expect(await screen.findByText('Polling error: poll failed')).toBeInTheDocument();
  });

  it('reopening starts fresh at the picker', async () => {
    const view = open();
    await screen.findByText('Weird Tool');
    await userEvent.click(screen.getAllByText('CrowdStrike Falcon')[0].closest('button') as HTMLElement);
    view.rerender(<AddConnectorModal open={false} onClose={() => {}} />);
    view.rerender(<AddConnectorModal open onClose={() => {}} />);
    expect(await screen.findByRole('heading', { name: 'Add connector' })).toBeInTheDocument();
    expect(api.catalog).toHaveBeenCalledTimes(2);
    expect(within(screen.getByRole('dialog')).getByPlaceholderText('Search by name, vendor, or capability')).toHaveValue('');
  });
});
