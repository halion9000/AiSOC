import { beforeEach, describe, expect, it, vi } from 'vitest';
import { render, screen, waitFor } from '@testing-library/react';
import userEvent from '@testing-library/user-event';

const api = vi.hoisted(() => ({ hideType: vi.fn(), suppressions: vi.fn(), liftSuppression: vi.fn() }));
vi.mock('@/lib/api', () => ({ alertsApi: api }));
vi.mock('react-hot-toast', () => ({ default: { success: vi.fn(), error: vi.fn() } }));
vi.mock('next/link', () => ({ default: ({ children, href }: { children: React.ReactNode; href: string }) => <a href={href}>{children}</a> }));

import { HideAlertTypeModal, parseDays } from './HideAlertTypeModal';
import { HiddenAlertTypes, coverage, lasts } from './HiddenAlertTypes';
import { SWRConfig } from 'swr';

const alert = (over: Record<string, unknown> = {}) => ({ id: 'a1', title: "Process: 'x' does not exist", clientName: 'Acme Dental', affectedHosts: ['PC-1'], device: 'PC-1', source: 'ninjaone', ...over });
const out = (over: Record<string, unknown> = {}) => ({ id: 'r1', scope: 'client', client_id: 'c1', client_name: 'Acme', device: null, source: 'ninjaone', title: 'T', expires_at: null, indefinite: true, created_at: '2026-10-23T00:00:00Z', active: true, hidden_alerts: 4, ...over });

beforeEach(() => {
  Object.values(api).forEach((m) => m.mockReset());
  api.hideType.mockResolvedValue(out());
});

function open(a = alert(), onClose = vi.fn(), onHidden = vi.fn()) {
  render(<HideAlertTypeModal open alert={a as never} onClose={onClose} onHidden={onHidden} />);
  return { onClose, onHidden };
}

describe('parseDays', () => {
  it('takes whole days from 1 to 3650 and nothing else', () => {
    expect(parseDays('1')).toBe(1);
    expect(parseDays(' 30 ')).toBe(30);
    expect(parseDays('3650')).toBe(3650);
    for (const bad of ['', '0', '3651', '-1', '2.5', 'ten', '1e3', '12345']) expect(parseDays(bad), bad).toBeNull();
  });
});

describe('the Hide alert type window', () => {
  it('offers this device, this client or all clients, and for a number of days or indefinitely', () => {
    open();
    expect(screen.getByRole('radio', { name: /This device only/ })).toBeChecked();
    expect(screen.getByRole('radio', { name: /This client/ })).toBeInTheDocument();
    expect(screen.getByRole('radio', { name: /All clients/ })).toBeInTheDocument();
    expect(screen.getByLabelText('Days')).toHaveValue('30');
    expect(screen.getByRole('checkbox', { name: /Hide indefinitely/ })).not.toBeChecked();
  });

  it('hides for the device for the days typed', async () => {
    const { onHidden, onClose } = open();
    await userEvent.clear(screen.getByLabelText('Days'));
    await userEvent.type(screen.getByLabelText('Days'), '14');
    await userEvent.click(screen.getByRole('button', { name: 'Hide alert type' }));
    await waitFor(() => expect(api.hideType).toHaveBeenCalledWith({ alertId: 'a1', scope: 'device', days: 14, device: 'PC-1' }));
    expect(onHidden).toHaveBeenCalled();
    expect(onClose).toHaveBeenCalled();
  });

  it('hides for the client or for all clients, and indefinitely sends no end', async () => {
    open();
    await userEvent.click(screen.getByRole('radio', { name: /All clients/ }));
    await userEvent.click(screen.getByRole('checkbox', { name: /Hide indefinitely/ }));
    expect(screen.getByLabelText('Days')).toBeDisabled();
    await userEvent.click(screen.getByRole('button', { name: 'Hide alert type' }));
    await waitFor(() => expect(api.hideType).toHaveBeenCalledWith({ alertId: 'a1', scope: 'all', days: null, device: undefined }));
  });

  it('refuses a bad number of days and will not send until it is fixed', async () => {
    open();
    await userEvent.clear(screen.getByLabelText('Days'));
    await userEvent.type(screen.getByLabelText('Days'), '0');
    expect(screen.getByRole('button', { name: 'Hide alert type' })).toBeDisabled();
    expect(screen.getByText(/whole number of days from 1 to 3650/)).toBeInTheDocument();
    await userEvent.click(screen.getByRole('checkbox', { name: /Hide indefinitely/ }));
    expect(screen.getByRole('button', { name: 'Hide alert type' })).toBeEnabled();
    expect(api.hideType).not.toHaveBeenCalled();
  });

  it('an alert with no device can only be hidden for the client or everyone', () => {
    open(alert({ affectedHosts: [], device: undefined }));
    expect(screen.getByRole('radio', { name: /This device only/ })).toBeDisabled();
    expect(screen.getByRole('radio', { name: /This client/ })).toBeChecked();
  });

  it('an alert naming several devices lets you pick which one', async () => {
    open(alert({ affectedHosts: ['PC-1', 'PC-2'] }));
    await userEvent.selectOptions(screen.getByLabelText('Device'), 'PC-2');
    await userEvent.click(screen.getByRole('button', { name: 'Hide alert type' }));
    await waitFor(() => expect(api.hideType).toHaveBeenCalledWith(expect.objectContaining({ scope: 'device', device: 'PC-2' })));
  });

  it('stays open and says so when the server refuses', async () => {
    api.hideType.mockRejectedValue(new Error('This alert names no device to hide it for'));
    const { onClose, onHidden } = open();
    await userEvent.click(screen.getByRole('button', { name: 'Hide alert type' }));
    await waitFor(() => expect(api.hideType).toHaveBeenCalled());
    expect(onClose).not.toHaveBeenCalled();
    expect(onHidden).not.toHaveBeenCalled();
  });
});

describe('the hidden alert types page', () => {
  const view = () =>
    render(
      <SWRConfig value={{ provider: () => new Map(), dedupingInterval: 0, shouldRetryOnError: false }}>
        <HiddenAlertTypes />
      </SWRConfig>,
    );

  it('says who each is hidden for, how long and how many alerts it hides, and lifts one', async () => {
    api.suppressions.mockResolvedValue([out({ id: 'r1', scope: 'device', device: 'pc-1', client_name: 'Acme', indefinite: true }), out({ id: 'r2', scope: 'all', client_id: null, client_name: null, indefinite: false, expires_at: new Date(Date.now() + 5 * 86_400_000).toISOString(), hidden_alerts: 9 })]);
    api.liftSuppression.mockResolvedValue(out({ hidden_alerts: 4, active: false }));
    view();
    const rows = await screen.findAllByTestId('rule');
    expect(rows[0]).toHaveTextContent('pc-1 (Acme)');
    expect(rows[0]).toHaveTextContent('Hidden indefinitely');
    expect(rows[1]).toHaveTextContent('All clients');
    expect(rows[1]).toHaveTextContent(/5 days left|4 days left/);
    expect(rows[1]).toHaveTextContent('9');
    await userEvent.click(screen.getAllByRole('button', { name: /Stop hiding/ })[0]);
    await waitFor(() => expect(api.liftSuppression).toHaveBeenCalledWith('r1'));
  });

  it('says plainly when nothing is hidden, and when it cannot load', async () => {
    api.suppressions.mockResolvedValue([]);
    view();
    expect(await screen.findByTestId('none')).toBeInTheDocument();
  });

  it('shows an error instead of an empty list when the rules cannot be read', async () => {
    api.suppressions.mockRejectedValue(new Error('API 500'));
    view();
    expect(await screen.findByRole('alert')).toHaveTextContent('Could not load the hidden alert types: API 500');
  });

  it('describes coverage and timing in words', () => {
    expect(coverage({ scope: 'all', client_name: null, device: null })).toBe('All clients');
    expect(coverage({ scope: 'client', client_name: 'Acme', device: null })).toBe('Acme');
    expect(coverage({ scope: 'device', client_name: 'Acme', device: 'pc-1' })).toBe('pc-1 (Acme)');
    expect(lasts({ indefinite: true, expires_at: null })).toBe('Hidden indefinitely');
    expect(lasts({ indefinite: false, expires_at: new Date(Date.now() - 1000).toISOString() })).toBe('Ending now');
  });
});
