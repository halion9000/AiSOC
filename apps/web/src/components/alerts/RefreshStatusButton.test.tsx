import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { act, render, screen } from '@testing-library/react';
import userEvent from '@testing-library/user-event';

const refresh = vi.hoisted(() => vi.fn());
vi.mock('@/lib/api', () => ({ alertsApi: { refresh } }));
const toast = vi.hoisted(() => ({ success: vi.fn(), error: vi.fn() }));
vi.mock('react-hot-toast', () => ({ default: toast }));

import { RefreshStatusButton, REFRESH_CHECKS_MS } from './RefreshStatusButton';

beforeEach(() => {
  vi.useFakeTimers({ shouldAdvanceTime: true });
  refresh.mockReset().mockResolvedValue({ vendor: 'huntress', requested_at: 'now' });
  toast.success.mockReset();
  toast.error.mockReset();
});
afterEach(() => vi.useRealTimers());

describe('RefreshStatusButton', () => {
  it('asks for this alert, then re-reads the alert while the answer arrives', async () => {
    const onRefreshed = vi.fn();
    render(<RefreshStatusButton alertId="a1" onRefreshed={onRefreshed} />);
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
    render(<RefreshStatusButton alertId="a1" onRefreshed={onRefreshed} />);
    await userEvent.click(screen.getByRole('button', { name: 'Refresh status' }));
    expect(toast.error).toHaveBeenCalledWith('CORE is not feeding huntress into this organization');
    expect(screen.getByRole('button', { name: 'Refresh status' })).toBeEnabled();
    expect(onRefreshed).not.toHaveBeenCalled();
  });
});
