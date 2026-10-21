import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { act, render, screen } from '@testing-library/react';
import userEvent from '@testing-library/user-event';

const refresh = vi.hoisted(() => vi.fn());
const vendorActions = vi.hoisted(() => vi.fn());
vi.mock('@/lib/api', () => ({ alertsApi: { refresh, vendorActions } }));
const toast = vi.hoisted(() => ({ success: vi.fn(), error: vi.fn() }));
vi.mock('react-hot-toast', () => ({ default: toast }));

import { SWRConfig } from 'swr';
import { RefreshStatusButton, REFRESH_CHECKS_MS, agoLabel } from './RefreshStatusButton';

const show = (onRefreshed = vi.fn()) => render(<SWRConfig value={{ provider: () => new Map(), dedupingInterval: 0 }}><RefreshStatusButton alertId="a1" onRefreshed={onRefreshed} /></SWRConfig>);

beforeEach(() => {
  vi.useFakeTimers({ shouldAdvanceTime: true });
  refresh.mockReset().mockResolvedValue({ vendor: 'huntress', requested_at: 'now' });
  vendorActions.mockReset().mockResolvedValue({ vendor_state: null });
  toast.success.mockReset();
  toast.error.mockReset();
});
afterEach(() => vi.useRealTimers());

describe('RefreshStatusButton', () => {
  it('asks for this alert, then re-reads the alert while the answer arrives', async () => {
    const onRefreshed = vi.fn();
    show(onRefreshed);
    await userEvent.click(screen.getByRole('button', { name: 'Refresh status' }));
    expect(refresh).toHaveBeenCalledWith('a1');
    expect(toast.success).toHaveBeenCalled();
    expect(screen.getByRole('button', { name: 'Checking…' })).toBeDisabled();
    await act(async () => {
      vi.advanceTimersByTime(REFRESH_CHECKS_MS[REFRESH_CHECKS_MS.length - 1] + 1);
    });
    expect(onRefreshed).toHaveBeenCalledTimes(REFRESH_CHECKS_MS.length);
    expect(screen.getByRole('button', { name: 'Refresh status' })).toBeEnabled();
  });

  it('says why when it cannot be asked, and stays usable', async () => {
    refresh.mockRejectedValue(new Error('CORE is not feeding huntress into this organization'));
    const onRefreshed = vi.fn();
    show(onRefreshed);
    await userEvent.click(screen.getByRole('button', { name: 'Refresh status' }));
    expect(toast.error).toHaveBeenCalledWith('CORE is not feeding huntress into this organization');
    expect(screen.getByRole('button', { name: 'Refresh status' })).toBeEnabled();
    expect(onRefreshed).not.toHaveBeenCalled();
  });
});

describe('the status-checked line', () => {
  it('says when CORE last reported the incident state, and nothing when it never did', async () => {
    vendorActions.mockResolvedValue({ vendor_state: { vendor: 'huntress', at: new Date(Date.now() - 4 * 60_000).toISOString(), status: 'sent', remediations: [], psa_ticket_eids: [] } });
    const first = show();
    expect(await screen.findByTestId('status-checked')).toHaveTextContent('status checked 4 min ago');
    first.unmount();
    vendorActions.mockResolvedValue({ vendor_state: null });
    show();
    await screen.findByRole('button', { name: 'Refresh status' });
    expect(screen.queryByTestId('status-checked')).not.toBeInTheDocument();
  });
  it('agoLabel reads minutes, hours and days', () => {
    const now = Date.parse('2026-10-20T12:00:00Z');
    expect(agoLabel('2026-10-20T11:59:40Z', now)).toBe('just now');
    expect(agoLabel('2026-10-20T11:30:00Z', now)).toBe('30 min ago');
    expect(agoLabel('2026-10-20T07:00:00Z', now)).toBe('5 h ago');
    expect(agoLabel('2026-10-15T12:00:00Z', now)).toBe('5 days ago');
    expect(agoLabel('nope', now)).toBe('');
    expect(agoLabel(null, now)).toBe('');
  });
});
