import { act, fireEvent, render, screen } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

const copilotApi = vi.hoisted(() => ({ confirmAction: vi.fn() }));
vi.mock('@/lib/api', async (importOriginal) => ({ ...(await importOriginal<typeof import('@/lib/api')>()), copilotApi }));

import { ApiError, type CopilotPendingAction } from '@/lib/api';
import { PendingActionPrompt } from './PendingActionPrompt';

// The Copilot's delete_alert only REQUESTS a deletion. This prompt is where the analyst approves it: nothing happens until they click, the token is signed, expiring and bound to them, so a message in the conversation can never approve it for them.

const inFuture = (seconds: number) => Math.floor(Date.now() / 1000) + seconds;
const pending = (over: Partial<CopilotPendingAction> = {}): CopilotPendingAction => ({
  action: 'delete_alert',
  summary: 'Permanently delete alert "Suspicious login" (1234)? This cannot be undone.',
  token: 'signed-token-abc',
  expiresAt: inFuture(300),
  ...over,
});

beforeEach(() => {
  copilotApi.confirmAction.mockReset();
});
afterEach(() => {
  vi.useRealTimers();
});

describe('before the analyst decides', () => {
  it('shows what would be deleted and makes NO call', () => {
    render(<PendingActionPrompt action={pending()} />);
    expect(screen.getByRole('group', { name: 'Confirmation required' })).toBeInTheDocument();
    expect(screen.getByText(/Permanently delete alert "Suspicious login"/)).toBeInTheDocument();
    expect(screen.getByRole('button', { name: 'Delete' })).toBeEnabled();
    expect(screen.getByRole('button', { name: 'Cancel' })).toBeEnabled();
    expect(copilotApi.confirmAction).not.toHaveBeenCalled();
  });

  it('labels a non-delete action Confirm rather than Delete', () => {
    render(<PendingActionPrompt action={pending({ action: 'isolate_host', summary: 'Isolate host?' })} />);
    expect(screen.getByRole('button', { name: 'Confirm' })).toBeInTheDocument();
    expect(screen.queryByRole('button', { name: 'Delete' })).not.toBeInTheDocument();
  });
});

describe('confirming', () => {
  it('sends the token once, reports it, and removes the buttons', async () => {
    copilotApi.confirmAction.mockResolvedValue({ status: 'done', action: 'delete_alert', result: { deleted: true } });
    render(<PendingActionPrompt action={pending()} />);
    await userEvent.setup().click(screen.getByRole('button', { name: 'Delete' }));
    expect(await screen.findByText('Deleted.')).toBeInTheDocument();
    expect(copilotApi.confirmAction).toHaveBeenCalledTimes(1);
    expect(copilotApi.confirmAction).toHaveBeenCalledWith('signed-token-abc');
    expect(screen.queryByRole('button', { name: 'Delete' })).not.toBeInTheDocument();
    expect(screen.queryByRole('button', { name: 'Cancel' })).not.toBeInTheDocument();
  });

  it('says so, and that nothing changed, when the server reports it could not complete', async () => {
    copilotApi.confirmAction.mockResolvedValue({ status: 'failed', action: 'delete_alert', result: { error: 'alert not found or already deleted' } });
    render(<PendingActionPrompt action={pending()} />);
    await userEvent.setup().click(screen.getByRole('button', { name: 'Delete' }));
    expect(await screen.findByText('alert not found or already deleted Nothing was changed.')).toBeInTheDocument();
    expect(screen.queryByText('Deleted.')).not.toBeInTheDocument();
  });

  it("shows the server's own reason when it refuses (expired, not issued to you)", async () => {
    copilotApi.confirmAction.mockRejectedValue(new ApiError('API 410', 410, JSON.stringify({ detail: 'That confirmation has expired. Ask the Copilot again.' })));
    render(<PendingActionPrompt action={pending()} />);
    await userEvent.setup().click(screen.getByRole('button', { name: 'Delete' }));
    expect(await screen.findByText('That confirmation has expired. Ask the Copilot again.')).toBeInTheDocument();
    expect(screen.queryByText('Deleted.')).not.toBeInTheDocument();
  });

  it('says the API could not be reached, and that nothing was changed, on a network failure', async () => {
    copilotApi.confirmAction.mockRejectedValue(new ApiError('Network error', 0, ''));
    render(<PendingActionPrompt action={pending()} />);
    await userEvent.setup().click(screen.getByRole('button', { name: 'Delete' }));
    expect(await screen.findByText('The AiSOC API could not be reached. Nothing was changed.')).toBeInTheDocument();
  });

  it('falls back to a plain message for an unexpected error', async () => {
    copilotApi.confirmAction.mockRejectedValue(new Error('boom'));
    render(<PendingActionPrompt action={pending()} />);
    await userEvent.setup().click(screen.getByRole('button', { name: 'Delete' }));
    expect(await screen.findByText('Could not confirm. Nothing was changed.')).toBeInTheDocument();
  });

  it('ignores a second click while the first is in flight', () => {
    copilotApi.confirmAction.mockReturnValue(new Promise(() => undefined));
    render(<PendingActionPrompt action={pending()} />);
    const button = screen.getByRole('button', { name: 'Delete' });
    fireEvent.click(button);
    fireEvent.click(button);
    expect(copilotApi.confirmAction).toHaveBeenCalledTimes(1);
    expect(screen.getByRole('button', { name: 'Working...' })).toBeDisabled();
    expect(screen.getByRole('button', { name: 'Cancel' })).toBeDisabled();
  });
});

describe('cancelling', () => {
  it('makes no call, says nothing changed, and cannot then be confirmed', async () => {
    render(<PendingActionPrompt action={pending()} />);
    await userEvent.setup().click(screen.getByRole('button', { name: 'Cancel' }));
    expect(screen.getByText('Cancelled. Nothing was changed.')).toBeInTheDocument();
    expect(screen.queryByRole('button', { name: 'Delete' })).not.toBeInTheDocument();
    expect(copilotApi.confirmAction).not.toHaveBeenCalled();
  });
});

describe('expiry', () => {
  it('offers no way to confirm a prompt that has already expired', () => {
    render(<PendingActionPrompt action={pending({ expiresAt: inFuture(-5) })} />);
    expect(screen.getByText(/This confirmation has expired\. Ask the Copilot again/)).toBeInTheDocument();
    expect(screen.queryByRole('button', { name: 'Delete' })).not.toBeInTheDocument();
    expect(copilotApi.confirmAction).not.toHaveBeenCalled();
  });

  it('withdraws the buttons when it expires while the analyst is looking at it', () => {
    vi.useFakeTimers();
    render(<PendingActionPrompt action={pending({ expiresAt: inFuture(2) })} />);
    expect(screen.getByRole('button', { name: 'Delete' })).toBeInTheDocument();
    act(() => {
      vi.advanceTimersByTime(3000);
    });
    expect(screen.getByText(/This confirmation has expired/)).toBeInTheDocument();
    expect(screen.queryByRole('button', { name: 'Delete' })).not.toBeInTheDocument();
  });

  it('does not show the expiry note once the analyst has already decided', async () => {
    vi.useFakeTimers({ shouldAdvanceTime: true });
    render(<PendingActionPrompt action={pending({ expiresAt: inFuture(2) })} />);
    fireEvent.click(screen.getByRole('button', { name: 'Cancel' }));
    act(() => {
      vi.advanceTimersByTime(5000);
    });
    expect(screen.getByText('Cancelled. Nothing was changed.')).toBeInTheDocument();
    expect(screen.queryByText(/has expired/)).not.toBeInTheDocument();
  });
});
