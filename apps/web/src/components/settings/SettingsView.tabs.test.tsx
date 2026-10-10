/**
 * Which Settings tabs a person is offered. The server decides what anyone may do (every route checks it); the tabs only keep the screen from offering what a
 * person cannot use: Tenant access needs `manage_users`, Alert email needs `platform_admin`, from the capabilities /auth/me gave at sign-in.
 */
import { beforeEach, describe, expect, it, vi } from 'vitest';
import { render, screen } from '@testing-library/react';
import userEvent from '@testing-library/user-event';

const swrMutate = vi.hoisted(() => vi.fn());
vi.mock('swr', () => ({ __esModule: true, default: () => ({ data: undefined, error: undefined, isLoading: false, mutate: swrMutate }) }));

const currentUser = vi.hoisted(() => vi.fn());
vi.mock('@/lib/api', () => ({
  __esModule: true,
  apiKeysApi: { list: vi.fn(), create: vi.fn(), revoke: vi.fn() },
  deploymentApi: { getAirgapStatus: vi.fn(), getLlmStatus: vi.fn(), getLlmCredential: vi.fn(), upsertLlmCredential: vi.fn(), deleteLlmCredential: vi.fn() },
  connectorsApi: { list: vi.fn(), statuses: vi.fn() },
  authApi: { currentUser: () => currentUser(), updateUserPreferences: vi.fn() },
  tenantsApi: { details: vi.fn(), users: vi.fn() },
  ApiError: class ApiError extends Error {},
}));
vi.mock('react-hot-toast', () => ({ __esModule: true, default: { success: vi.fn(), error: vi.fn() } }));
vi.mock('./TenantAccessPanel', async () => {
  const React = await import('react');
  return { TenantAccessPanel: (p: { canGrantAll: boolean }) => React.createElement('div', { 'data-testid': 'tenant-access-stub', 'data-grant-all': String(p.canGrantAll) }) };
});
vi.mock('./AlertEmailPanel', async () => {
  const React = await import('react');
  return { AlertEmailPanel: () => React.createElement('div', { 'data-testid': 'alert-email-stub' }) };
});

import { SettingsView } from './SettingsView';

const person = (capabilities?: string[]) => ({ id: 'u1', email: 'a@b.com', account_name: 'a', role: 'admin', tenant_id: 't1', ...(capabilities ? { capabilities } : {}) });
const tab = (name: RegExp) => screen.queryByRole('button', { name });

beforeEach(() => currentUser.mockReset());

describe('Settings tabs by capability', () => {
  it('offers neither new tab to someone with no capabilities, or when nobody is signed in', async () => {
    for (const who of [person([]), person(), null]) {
      currentUser.mockReturnValue(who);
      const { unmount } = render(<SettingsView />);
      expect(await screen.findByRole('button', { name: /^profile/i })).toBeInTheDocument();
      expect(tab(/^tenant access/i)).toBeNull();
      expect(tab(/^alert email/i)).toBeNull();
      unmount();
    }
  });

  it('offers Tenant access (but not Alert email) to someone who can manage users', async () => {
    currentUser.mockReturnValue(person(['manage_users']));
    render(<SettingsView />);
    expect(await screen.findByRole('button', { name: /^tenant access/i })).toBeInTheDocument();
    expect(tab(/^alert email/i)).toBeNull();
  });

  it('offers Alert email (but not Tenant access) to a platform administrator who has only that capability', async () => {
    currentUser.mockReturnValue(person(['platform_admin']));
    render(<SettingsView />);
    expect(await screen.findByRole('button', { name: /^alert email/i })).toBeInTheDocument();
    expect(tab(/^tenant access/i)).toBeNull();
  });

  it('offers both to a platform administrator who can also manage users, and keeps every existing tab', async () => {
    currentUser.mockReturnValue(person(['manage_users', 'platform_admin']));
    render(<SettingsView />);
    expect(await screen.findByRole('button', { name: /^tenant access/i })).toBeInTheDocument();
    expect(tab(/^alert email/i)).toBeInTheDocument();
    for (const existing of [/^profile/i, /^workspace/i, /^integrations/i, /^api keys/i, /^notifications/i, /^audit/i]) expect(tab(existing)).toBeInTheDocument();
  });

  it('an unrecognised capability opens nothing', async () => {
    currentUser.mockReturnValue(person(['something_else', 'PLATFORM_ADMIN']));
    render(<SettingsView />);
    await screen.findByRole('button', { name: /^profile/i });
    expect(tab(/^tenant access/i)).toBeNull();
    expect(tab(/^alert email/i)).toBeNull();
  });

  it('opening Tenant access shows its panel, and only a platform administrator is told they may grant every tenant', async () => {
    currentUser.mockReturnValue(person(['manage_users']));
    const user = userEvent.setup();
    const { unmount } = render(<SettingsView />);
    await user.click(await screen.findByRole('button', { name: /^tenant access/i }));
    expect(await screen.findByTestId('tenant-access-stub')).toHaveAttribute('data-grant-all', 'false');
    unmount();
    currentUser.mockReturnValue(person(['manage_users', 'platform_admin']));
    render(<SettingsView />);
    await user.click(await screen.findByRole('button', { name: /^tenant access/i }));
    expect(await screen.findByTestId('tenant-access-stub')).toHaveAttribute('data-grant-all', 'true');
  });

  it('opening Alert email shows its panel', async () => {
    currentUser.mockReturnValue(person(['platform_admin']));
    const user = userEvent.setup();
    render(<SettingsView />);
    await user.click(await screen.findByRole('button', { name: /^alert email/i }));
    expect(await screen.findByTestId('alert-email-stub')).toBeInTheDocument();
  });

  it('neither panel is rendered until its tab is opened', async () => {
    currentUser.mockReturnValue(person(['manage_users', 'platform_admin']));
    render(<SettingsView />);
    await screen.findByRole('button', { name: /^tenant access/i });
    expect(screen.queryByTestId('tenant-access-stub')).toBeNull();
    expect(screen.queryByTestId('alert-email-stub')).toBeNull();
  });
});
