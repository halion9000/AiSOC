/**
 * The Test button on Settings > Integrations: a CORE-fed tool is synced first (CORE is asked to run it now), any other connector is tested directly.
 */
import { beforeEach, describe, expect, it, vi } from 'vitest';
import { render, screen, waitFor } from '@testing-library/react';
import userEvent from '@testing-library/user-event';

const api = vi.hoisted(() => ({ syncNow: vi.fn(), test: vi.fn() }));
const swrMutate = vi.hoisted(() => vi.fn());
const connectors = vi.hoisted(() => [
  { id: 'c1', name: 'NinjaOne', type: 'core_feed', status: 'active', description: '' },
  { id: 'c2', name: 'Splunk', type: 'splunk', status: 'active', description: '' },
]);
vi.mock('swr', () => ({
  __esModule: true,
  default: (key: string) => ({ data: key === 'settings:connectors' ? { connectors } : undefined, error: undefined, isLoading: false, mutate: swrMutate }),
}));
vi.mock('@/lib/api', () => ({
  __esModule: true,
  apiKeysApi: { list: vi.fn(), create: vi.fn(), revoke: vi.fn() },
  deploymentApi: { getAirgapStatus: vi.fn(), getLlmStatus: vi.fn(), getLlmCredential: vi.fn(), upsertLlmCredential: vi.fn(), deleteLlmCredential: vi.fn() },
  connectorsApi: { list: vi.fn(), statuses: vi.fn(), syncNow: api.syncNow, test: api.test },
  authApi: { currentUser: () => ({ id: 'u1', email: 'a@b.com', account_name: 'a', role: 'admin', tenant_id: 't1' }), updateUserPreferences: vi.fn() },
  tenantsApi: { details: vi.fn(), users: vi.fn() },
  ApiError: class ApiError extends Error {},
}));
const toast = vi.hoisted(() => ({ success: vi.fn(), error: vi.fn() }));
vi.mock('react-hot-toast', () => ({ __esModule: true, default: toast }));

import { SettingsView } from './SettingsView';

beforeEach(() => {
  api.syncNow.mockReset();
  api.test.mockReset();
  swrMutate.mockReset();
  toast.success.mockReset();
  api.test.mockResolvedValue({ success: true, latencyMs: 12 });
});

async function openIntegrations() {
  render(<SettingsView />);
  await userEvent.click(await screen.findByRole('button', { name: /^integrations/i }));
  return screen.findAllByRole('button', { name: 'Test' });
}

describe('Settings > Integrations Test button', () => {
  it('syncs a CORE-fed tool first, then tests it', async () => {
    api.syncNow.mockResolvedValue({ reported: true });
    const buttons = await openIntegrations();
    await userEvent.click(buttons[0]);
    await waitFor(() => expect(api.test).toHaveBeenCalledWith('c1'));
    expect(api.syncNow).toHaveBeenCalledWith('c1');
    expect(api.syncNow.mock.invocationCallOrder[0]).toBeLessThan(api.test.mock.invocationCallOrder[0]);
  });

  it('says so when CORE did not answer, and still shows the last report', async () => {
    api.syncNow.mockResolvedValue({ reported: false });
    const buttons = await openIntegrations();
    await userEvent.click(buttons[0]);
    await waitFor(() => expect(toast.success).toHaveBeenCalled());
    expect(String(toast.success.mock.calls[0][0])).toContain("CORE didn't answer");
  });

  it('tests any other connector directly, without a sync', async () => {
    const buttons = await openIntegrations();
    await userEvent.click(buttons[1]);
    await waitFor(() => expect(api.test).toHaveBeenCalledWith('c2'));
    expect(api.syncNow).not.toHaveBeenCalled();
  });
});
