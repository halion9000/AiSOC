import { beforeEach, describe, expect, it, vi } from 'vitest';
import { render, screen, waitFor } from '@testing-library/react';
import userEvent from '@testing-library/user-event';

const api = vi.hoisted(() => ({ update: vi.fn() }));
const toast = vi.hoisted(() => ({ success: vi.fn(), error: vi.fn() }));
vi.mock('@/lib/api', () => ({ connectorsApi: api }));
vi.mock('react-hot-toast', () => ({ __esModule: true, default: toast }));

import { EditConnectorModal } from './EditConnectorModal';

const catalogEntry = {
  connector_id: 'okta',
  connector_name: 'Okta',
  category: 'iam',
  fields: [
    { name: 'domain', label: 'Okta domain', type: 'string', required: true, placeholder: 'acme.okta.com', help_text: 'Your org domain' },
    { name: 'api_token', label: 'API token', type: 'secret', required: true },
    { name: 'region', label: 'Region', type: 'select', required: false, options: [{ value: 'us', label: 'US' }, { value: 'eu', label: 'EU' }] },
    { name: 'poll_minutes', label: 'Poll every (min)', type: 'number', default: 5 },
    { name: 'verify_tls', label: 'Verify TLS', type: 'boolean', placeholder: 'Check certificates' },
    { name: 'notes', label: 'Notes', type: 'textarea', placeholder: 'free text' },
  ],
} as never;

const connector = (over: Record<string, unknown> = {}) => ({
  id: 'c1',
  name: 'Okta prod',
  type: 'okta',
  status: 'active',
  alertCount: 0,
  tags: ['prod', 'critical'],
  connectorConfig: { domain: 'acme.okta.com', region: 'eu', poll_minutes: 15, verify_tls: true },
  authConfig: {},
  ...over,
}) as never;

function show(props: Record<string, unknown> = {}) {
  const onClose = vi.fn();
  const onUpdated = vi.fn();
  const view = render(<EditConnectorModal open connector={connector()} catalogEntry={catalogEntry} onClose={onClose} onUpdated={onUpdated} {...props} />);
  return { onClose, onUpdated, ...view };
}

beforeEach(() => {
  api.update.mockReset().mockResolvedValue({});
  toast.success.mockReset();
  toast.error.mockReset();
});

describe('EditConnectorModal', () => {
  it('shows nothing when closed or when there is no connector', () => {
    const { container, rerender } = show({ open: false });
    expect(container).toBeEmptyDOMElement();
    rerender(<EditConnectorModal open connector={null} catalogEntry={catalogEntry} onClose={() => {}} onUpdated={() => {}} />);
    expect(container).toBeEmptyDOMElement();
  });

  it('fills in the saved name, tags and settings, and shows the field labels, required stars and help', async () => {
    show();
    expect(await screen.findByDisplayValue('Okta prod')).toBeInTheDocument();
    expect(screen.getByDisplayValue('prod, critical')).toBeInTheDocument();
    expect(screen.getByDisplayValue('acme.okta.com')).toBeInTheDocument();
    expect(screen.getByDisplayValue('15')).toBeInTheDocument();
    expect(screen.getByRole('combobox')).toHaveValue('eu');
    expect(screen.getByRole('checkbox')).toBeChecked();
    expect(screen.getByText('Okta domain')).toBeInTheDocument();
    expect(screen.getByText('Your org domain')).toBeInTheDocument();
    expect(screen.getByText('Okta — Okta prod')).toBeInTheDocument();
    expect(screen.getAllByText('*')).toHaveLength(2);
  });

  it('never shows a secret: it starts empty and says leaving it blank keeps the saved one', async () => {
    show({ connector: connector({ authConfig: { api_token: 'SHOULD-NOT-SHOW' } }) });
    const secret = await screen.findByPlaceholderText('Leave blank to keep current value');
    expect(secret).toHaveValue('');
    expect(secret).toHaveAttribute('type', 'password');
    expect(screen.queryByDisplayValue('SHOULD-NOT-SHOW')).toBeNull();
  });

  it('uses the catalog default for a setting the connector has not saved, and a blank otherwise', async () => {
    show({ connector: connector({ connectorConfig: {} }) });
    expect(await screen.findByDisplayValue('5')).toBeInTheDocument();
    expect(screen.getByRole('checkbox')).not.toBeChecked();
    expect(screen.getByPlaceholderText('acme.okta.com')).toHaveValue('');
  });

  it('a select that is not required offers "none"', async () => {
    show();
    await screen.findByDisplayValue('Okta prod');
    expect(screen.getByRole('option', { name: '— none —' })).toBeInTheDocument();
  });

  it('saving with no changes sends the saved values and no secret, then reports, refreshes and closes', async () => {
    const { onClose, onUpdated } = show();
    await screen.findByDisplayValue('Okta prod');
    await userEvent.click(screen.getByRole('button', { name: 'Save Changes' }));
    await waitFor(() => expect(api.update).toHaveBeenCalledTimes(1));
    expect(api.update).toHaveBeenCalledWith('c1', {
      name: 'Okta prod',
      auth_config: undefined,
      connector_config: { domain: 'acme.okta.com', region: 'eu', poll_minutes: 15, verify_tls: true },
      tags: ['prod', 'critical'],
    });
    expect(toast.success).toHaveBeenCalledWith('Updated Okta prod');
    expect(onUpdated).toHaveBeenCalledTimes(1);
    expect(onClose).toHaveBeenCalledTimes(1);
  });

  it('a new secret goes in auth_config, never in connector_config', async () => {
    show();
    await userEvent.type(await screen.findByPlaceholderText('Leave blank to keep current value'), 'new-token-123');
    await userEvent.click(screen.getByRole('button', { name: 'Save Changes' }));
    await waitFor(() => expect(api.update).toHaveBeenCalled());
    const body = api.update.mock.calls[0][1];
    expect(body.auth_config).toEqual({ api_token: 'new-token-123' });
    expect(body.connector_config).not.toHaveProperty('api_token');
  });

  it('changed values, a trimmed name and re-split tags are what is sent', async () => {
    show();
    const name = await screen.findByDisplayValue('Okta prod');
    await userEvent.clear(name);
    await userEvent.type(name, '  Okta EU  ');
    const tags = screen.getByDisplayValue('prod, critical');
    await userEvent.clear(tags);
    await userEvent.type(tags, ' a ,, b ');
    await userEvent.selectOptions(screen.getByRole('combobox'), 'us');
    await userEvent.click(screen.getByRole('checkbox'));
    const poll = screen.getByDisplayValue('15');
    await userEvent.clear(poll);
    await userEvent.type(poll, '30');
    await userEvent.click(screen.getByRole('button', { name: 'Save Changes' }));
    await waitFor(() => expect(api.update).toHaveBeenCalled());
    expect(api.update.mock.calls[0][1]).toMatchObject({ name: 'Okta EU', tags: ['a', 'b'], connector_config: { region: 'us', verify_tls: false, poll_minutes: 30, domain: 'acme.okta.com' } });
    expect(toast.success).toHaveBeenCalledWith('Updated Okta EU');
  });

  it('a blank setting is left out so the saved value is kept, not overwritten with nothing', async () => {
    show();
    const domain = await screen.findByDisplayValue('acme.okta.com');
    await userEvent.clear(domain);
    await userEvent.click(screen.getByRole('button', { name: 'Save Changes' }));
    await waitFor(() => expect(api.update).toHaveBeenCalled());
    expect(api.update.mock.calls[0][1].connector_config).not.toHaveProperty('domain');
  });

  it('a failed save shows the reason, keeps the dialog open and lets the person try again', async () => {
    api.update.mockRejectedValueOnce(new Error('403 forbidden'));
    const { onClose, onUpdated } = show();
    await screen.findByDisplayValue('Okta prod');
    await userEvent.click(screen.getByRole('button', { name: 'Save Changes' }));
    await waitFor(() => expect(toast.error).toHaveBeenCalledWith('403 forbidden'));
    expect(onClose).not.toHaveBeenCalled();
    expect(onUpdated).not.toHaveBeenCalled();
    expect(screen.getByRole('button', { name: 'Save Changes' })).toBeEnabled();
  });

  it('while saving both buttons are disabled and the label says so', async () => {
    let finish: (v: unknown) => void = () => {};
    api.update.mockReturnValue(new Promise((r) => { finish = r; }));
    show();
    await screen.findByDisplayValue('Okta prod');
    await userEvent.click(screen.getByRole('button', { name: 'Save Changes' }));
    expect(await screen.findByRole('button', { name: 'Saving…' })).toBeDisabled();
    expect(screen.getByRole('button', { name: 'Cancel' })).toBeDisabled();
    finish({});
    await waitFor(() => expect(screen.queryByRole('button', { name: 'Saving…' })).toBeNull());
  });

  it('Cancel and the X close without saving', async () => {
    const { onClose } = show();
    await screen.findByDisplayValue('Okta prod');
    await userEvent.click(screen.getByRole('button', { name: 'Cancel' }));
    expect(onClose).toHaveBeenCalledTimes(1);
    expect(api.update).not.toHaveBeenCalled();
  });

  it('a connector with no catalog entry can still be renamed', async () => {
    show({ catalogEntry: undefined });
    const name = await screen.findByDisplayValue('Okta prod');
    expect(screen.getByText('okta — Okta prod')).toBeInTheDocument();
    await userEvent.clear(name);
    await userEvent.type(name, 'Renamed');
    await userEvent.click(screen.getByRole('button', { name: 'Save Changes' }));
    await waitFor(() => expect(api.update).toHaveBeenCalledWith('c1', { name: 'Renamed', auth_config: undefined, connector_config: undefined, tags: ['prod', 'critical'] }));
  });
});
