/**
 * Revoking an API key is permanent and breaks whatever uses it (pipelines, forwarders, webhooks). The Revoke button used to revoke on the first click; it now opens a confirmation that names the key.
 */
import { beforeEach, describe, expect, it, vi } from 'vitest';
import { render, screen, waitFor, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';

const swrData = vi.hoisted(() => new Map<string, unknown>());
const swrMutate = vi.hoisted(() => vi.fn());
vi.mock('swr', () => ({
  __esModule: true,
  default: (key: unknown) => {
    const k = typeof key === 'string' ? key : JSON.stringify(key);
    return { data: swrData.get(k), error: undefined, isLoading: false, mutate: swrMutate };
  },
}));

const apiKeysApi = vi.hoisted(() => ({ list: vi.fn(), create: vi.fn(), revoke: vi.fn() }));
vi.mock('@/lib/api', () => ({
  __esModule: true,
  apiKeysApi,
  deploymentApi: { getAirgapStatus: vi.fn(), getLlmStatus: vi.fn(), getLlmCredential: vi.fn(), upsertLlmCredential: vi.fn(), deleteLlmCredential: vi.fn() },
  connectorsApi: { list: vi.fn(), statuses: vi.fn() },
  authApi: { currentUser: () => null, updateUserPreferences: vi.fn() },
  tenantsApi: { details: vi.fn(), users: vi.fn() },
  ApiError: class ApiError extends Error {
    status: number;
    constructor(message: string, status = 500) {
      super(message);
      this.status = status;
    }
  },
}));

const toastSuccess = vi.hoisted(() => vi.fn());
const toastError = vi.hoisted(() => vi.fn());
vi.mock('react-hot-toast', () => ({ __esModule: true, default: { success: toastSuccess, error: toastError }, toast: { success: toastSuccess, error: toastError } }));
vi.mock('date-fns', async () => ({ ...(await vi.importActual<typeof import('date-fns')>('date-fns')), formatDistanceToNow: () => '3 months ago' }));

import { SettingsView } from './SettingsView';

const key = (id: string, name: string) => ({ id, name, prefix: `ak_${id}`, scopes: ['alerts:read'], createdAt: '2026-01-01T00:00:00Z', lastUsedAt: null });

beforeEach(() => {
  apiKeysApi.revoke.mockReset();
  toastSuccess.mockReset();
  toastError.mockReset();
  swrMutate.mockReset();
  swrData.clear();
  swrData.set('settings:api-keys', [key('k1', 'SIEM forwarder'), key('k2', 'Backup script')]);
});

async function openApiKeys() {
  const user = userEvent.setup();
  render(<SettingsView />);
  await user.click(await screen.findByRole('button', { name: /^api keys/i }));
  await screen.findByText(/Long-lived tokens used by pipelines/);
  return user;
}
const revokeButtonFor = (name: string) => within(screen.getByText(name).closest('tr')!).getByRole('button', { name: 'Revoke' });

describe('revoking an API key', () => {
  it('does NOT revoke on the first click: it asks, naming the key', async () => {
    const user = await openApiKeys();
    await user.click(revokeButtonFor('SIEM forwarder'));
    const dialog = await screen.findByRole('alertdialog', { name: 'Revoke API key?' });
    expect(dialog).toHaveAccessibleDescription(/Revoke "SIEM forwarder"\? Anything using this key will stop working immediately\. This cannot be undone\./);
    expect(apiKeysApi.revoke).not.toHaveBeenCalled();
  });

  it('revokes exactly the key the analyst chose, once, only after confirming', async () => {
    apiKeysApi.revoke.mockResolvedValue(undefined);
    const user = await openApiKeys();
    await user.click(revokeButtonFor('Backup script'));
    await user.click(await screen.findByRole('button', { name: 'Revoke key' }));
    await waitFor(() => expect(toastSuccess).toHaveBeenCalledWith('Key revoked'));
    expect(apiKeysApi.revoke).toHaveBeenCalledTimes(1);
    expect(apiKeysApi.revoke).toHaveBeenCalledWith('k2');
    expect(screen.queryByRole('alertdialog')).not.toBeInTheDocument();
    expect(swrMutate).toHaveBeenCalled();
  });

  it('Cancel revokes nothing and closes the dialog', async () => {
    const user = await openApiKeys();
    await user.click(revokeButtonFor('SIEM forwarder'));
    await user.click(await screen.findByRole('button', { name: 'Cancel' }));
    expect(screen.queryByRole('alertdialog')).not.toBeInTheDocument();
    expect(apiKeysApi.revoke).not.toHaveBeenCalled();
  });

  it('Escape revokes nothing and closes the dialog', async () => {
    const user = await openApiKeys();
    await user.click(revokeButtonFor('SIEM forwarder'));
    await screen.findByRole('alertdialog');
    await user.keyboard('{Escape}');
    expect(screen.queryByRole('alertdialog')).not.toBeInTheDocument();
    expect(apiKeysApi.revoke).not.toHaveBeenCalled();
  });

  it('after cancelling one key, a later confirm applies to the key chosen THEN, not the earlier one', async () => {
    apiKeysApi.revoke.mockResolvedValue(undefined);
    const user = await openApiKeys();
    await user.click(revokeButtonFor('SIEM forwarder'));
    await user.click(await screen.findByRole('button', { name: 'Cancel' }));
    await user.click(revokeButtonFor('Backup script'));
    expect(await screen.findByRole('alertdialog')).toHaveAccessibleDescription(/"Backup script"/);
    await user.click(screen.getByRole('button', { name: 'Revoke key' }));
    await waitFor(() => expect(apiKeysApi.revoke).toHaveBeenCalledWith('k2'));
    expect(apiKeysApi.revoke).toHaveBeenCalledTimes(1);
  });

  it('locks the dialog while the revoke is in flight, so a second click cannot revoke twice', async () => {
    apiKeysApi.revoke.mockReturnValue(new Promise(() => undefined));
    const user = await openApiKeys();
    await user.click(revokeButtonFor('SIEM forwarder'));
    await user.click(await screen.findByRole('button', { name: 'Revoke key' }));
    const working = await screen.findByRole('button', { name: 'Working...' });
    expect(working).toBeDisabled();
    expect(screen.getByRole('button', { name: 'Cancel' })).toBeDisabled();
    await user.click(working);
    expect(apiKeysApi.revoke).toHaveBeenCalledTimes(1);
  });

  it('reports a failure, still closes the dialog, and does not claim success', async () => {
    apiKeysApi.revoke.mockRejectedValue(new Error('500'));
    const user = await openApiKeys();
    await user.click(revokeButtonFor('SIEM forwarder'));
    await user.click(await screen.findByRole('button', { name: 'Revoke key' }));
    await waitFor(() => expect(toastError).toHaveBeenCalledWith('Could not revoke key'));
    expect(toastSuccess).not.toHaveBeenCalled();
    expect(screen.queryByRole('alertdialog')).not.toBeInTheDocument();
  });
});
