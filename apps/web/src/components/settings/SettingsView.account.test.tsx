import { beforeEach, describe, expect, it, vi } from 'vitest';
import { render, screen, waitFor } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { SWRConfig } from 'swr';
import type { AuthUser, TenantDetails, TenantUser } from '@/lib/api';

const currentUser = vi.hoisted(() => vi.fn());
const updateUserPreferences = vi.hoisted(() => vi.fn());
const details = vi.hoisted(() => vi.fn());
const users = vi.hoisted(() => vi.fn());
const toastSuccess = vi.hoisted(() => vi.fn());
const toastError = vi.hoisted(() => vi.fn());

vi.mock('@/lib/api', () => ({
  __esModule: true,
  authApi: { currentUser: () => currentUser(), updateUserPreferences: (p: unknown) => updateUserPreferences(p) },
  tenantsApi: { details: () => details(), users: () => users() },
  ApiError: class ApiError extends Error {
    status: number;
    constructor(message: string, status = 500) {
      super(message);
      this.status = status;
    }
  },
}));
vi.mock('react-hot-toast', () => ({ __esModule: true, default: { success: toastSuccess, error: toastError } }));

import { ApiError } from '@/lib/api';
import { SettingsView, profileFromAccount, workspaceProblem } from './SettingsView';

// Settings > Profile used to show a made-up person ("Sasha Lin", sasha.lin@example.com, "Senior SOC Analyst") kept only in this browser, not the
// signed-in account, and Settings > Workspace showed a made-up workspace ("AiSOC Demo", tenant_demo_01H0XE4T2WJ9N6, region "us-east-1", a creation
// date computed as "96 days ago") and five made-up members. Now both show the real account and tenant.
const DEMO = ['Sasha Lin', 'sasha.lin@example.com', 'Senior SOC Analyst', 'AiSOC Demo', 'tenant_demo_01H0XE4T2WJ9N6', 'us-east-1', 'Avi Sharma', 'Diego Vega', 'Mia Ocampo', 'CI Service', 'demo data'];

const account: AuthUser = { id: 'u1', account_name: 'hal.owner', email: 'owner@liveoak.test', username: 'hal', role: 'admin', tenant_id: 't1', preferences: {} };
const tenant: TenantDetails = { id: '0b6f2a52-1c1e-4a8e-9a55-0c4a3f1d9d11', name: 'Live Oak IT', slug: 'live-oak-it', plan: 'open-source', is_active: true, created_at: '2026-10-07T03:00:00Z' };
const member = (over: Partial<TenantUser> & { email: string }): TenantUser => ({ id: over.email, account_name: over.email.split('@')[0], username: null, role: 'analyst', is_active: true, last_login: null, created_at: '2026-10-07T03:00:00Z', ...over });

function renderSettings() {
  return render(
    <SWRConfig value={{ provider: () => new Map(), dedupingInterval: 0 }}>
      <SettingsView />
    </SWRConfig>,
  );
}

beforeEach(() => {
  [currentUser, updateUserPreferences, details, users, toastSuccess, toastError].forEach((m) => m.mockReset());
  window.localStorage.clear();
});

describe('profileFromAccount', () => {
  it('takes the email and the default display name from the account, and invents nothing else', () => {
    const profile = profileFromAccount(account);
    expect(profile).toMatchObject({ email: 'owner@liveoak.test', displayName: 'hal', title: '' });
    expect(profile?.timezone).toBeTruthy();
  });

  it('prefers what was saved on the account', () => {
    const saved = { ...account, preferences: { profile: { displayName: 'Hal M', title: 'Owner', timezone: 'America/Los_Angeles' } } };
    expect(profileFromAccount(saved)).toEqual({ displayName: 'Hal M', accountName: 'hal.owner', email: 'owner@liveoak.test', title: 'Owner', timezone: 'America/Los_Angeles' });
  });

  it('has the account name, and an empty email when the account has none', () => {
    expect(profileFromAccount(account)).toMatchObject({ accountName: 'hal.owner', email: 'owner@liveoak.test' });
    expect(profileFromAccount({ ...account, email: null })).toMatchObject({ accountName: 'hal.owner', email: '' });
    expect(profileFromAccount({ ...account, email: undefined })).toMatchObject({ email: '' });
    expect(profileFromAccount({ ...account, account_name: undefined })).toMatchObject({ accountName: '' });
  });

  it('the default display name is the username, else the account name: never blank for a real account', () => {
    expect(profileFromAccount(account)).toMatchObject({ displayName: 'hal' });
    expect(profileFromAccount({ ...account, username: undefined })).toMatchObject({ displayName: 'hal.owner' });
    expect(profileFromAccount({ ...account, username: null })).toMatchObject({ displayName: 'hal.owner' });
    expect(profileFromAccount({ ...account, username: undefined, account_name: undefined })).toMatchObject({ displayName: '' });
  });

  it('ignores saved values of the wrong type, and returns null when nobody is signed in', () => {
    expect(profileFromAccount({ ...account, username: undefined, preferences: { profile: { displayName: 7, title: {} } } })).toMatchObject({ displayName: 'hal.owner', title: '' });
    expect(profileFromAccount(null)).toBeNull();
  });
});

describe('Settings > Profile', () => {
  it('shows the signed-in account, not a made-up person', async () => {
    currentUser.mockReturnValue(account);
    const { container } = renderSettings();
    expect(await screen.findByDisplayValue('owner@liveoak.test')).toBeInTheDocument();
    expect(screen.getByDisplayValue('hal')).toBeInTheDocument();
    expect(screen.getByDisplayValue('admin')).toBeInTheDocument();
    for (const demo of DEMO) expect(container.textContent).not.toContain(demo);
    for (const demo of DEMO) expect(Array.from(container.querySelectorAll('input')).map((i) => i.value)).not.toContain(demo);
  });

  it('makes the email read-only: it is the account address given at setup', async () => {
    currentUser.mockReturnValue(account);
    renderSettings();
    const email = await screen.findByDisplayValue('owner@liveoak.test');
    expect(email).toHaveAttribute('readonly');
  });

  it('shows the account name, read-only: it is what the person signs in with', async () => {
    currentUser.mockReturnValue(account);
    renderSettings();
    const name = await screen.findByDisplayValue('hal.owner');
    expect(name).toHaveAttribute('readonly');
    expect(screen.getByText('What you sign in with.')).toBeInTheDocument();
  });

  it('says the email is optional and not needed to sign in', async () => {
    currentUser.mockReturnValue(account);
    renderSettings();
    expect(await screen.findByText('Optional contact address. It is not needed to sign in.')).toBeInTheDocument();
    expect(screen.queryByText(/It is used to sign in/)).not.toBeInTheDocument();
  });

  it('shows an account with NO email: the account name, and an empty read-only email', async () => {
    currentUser.mockReturnValue({ ...account, email: null, username: null });
    const { container } = renderSettings();
    const accountName = (await screen.findByLabelText(/^Account name/)) as HTMLInputElement;
    expect(accountName.value).toBe('hal.owner');
    expect(accountName).toHaveAttribute('readonly');
    expect((screen.getByLabelText(/^Display name/) as HTMLInputElement).value).toBe('hal.owner'); // no username: the display name falls back to the account name
    const email = screen.getByLabelText(/^Email/) as HTMLInputElement;
    expect(email.value).toBe('');
    expect(email).toHaveAttribute('readonly');
    expect(email).toHaveAttribute('placeholder', 'None');
    expect(container.textContent).not.toContain('null');
    expect(container.textContent).not.toContain('undefined');
  });

  it('saves the display name, title and timezone to the account', async () => {
    currentUser.mockReturnValue(account);
    updateUserPreferences.mockResolvedValue({ ...account, preferences: { profile: { displayName: 'Hal M', title: 'Owner', timezone: 'UTC' } } });
    renderSettings();
    const user = userEvent.setup();
    const save = await screen.findByRole('button', { name: 'Save changes' });
    expect(save).toBeDisabled();

    const name = screen.getByPlaceholderText('Your name');
    await user.clear(name);
    await user.type(name, 'Hal M');
    await user.type(screen.getByPlaceholderText('e.g. SOC Analyst'), 'Owner');
    const timezone = screen.getByPlaceholderText('e.g. America/Los_Angeles');
    await user.clear(timezone);
    await user.type(timezone, 'UTC');
    expect(save).toBeEnabled();
    await user.click(save);

    await waitFor(() => expect(updateUserPreferences).toHaveBeenCalledWith({ profile: { displayName: 'Hal M', title: 'Owner', timezone: 'UTC' } }));
    expect(toastSuccess).toHaveBeenCalledWith('Profile updated');
    await waitFor(() => expect(screen.getByRole('button', { name: 'Save changes' })).toBeDisabled());
  });

  it('says so when saving fails, and keeps the changes so they can be retried', async () => {
    currentUser.mockReturnValue(account);
    updateUserPreferences.mockRejectedValue(new Error('network'));
    renderSettings();
    const user = userEvent.setup();
    await user.type(await screen.findByPlaceholderText('e.g. SOC Analyst'), 'Owner');
    await user.click(screen.getByRole('button', { name: 'Save changes' }));
    await waitFor(() => expect(toastError).toHaveBeenCalledWith('Could not save your profile. Try again.'));
    expect(toastSuccess).not.toHaveBeenCalled();
    expect(screen.getByRole('button', { name: 'Save changes' })).toBeEnabled();
  });

  it('asks you to sign in rather than showing anyone when nobody is signed in', async () => {
    currentUser.mockReturnValue(null);
    const { container } = renderSettings();
    expect(await screen.findByText('Sign in to view and edit your profile.')).toBeInTheDocument();
    for (const demo of DEMO) expect(container.textContent).not.toContain(demo);
  });

  it('removes, and never reads, the old browser-only profile that was seeded with a made-up person', async () => {
    window.localStorage.setItem('aisoc:settings:profile', JSON.stringify({ displayName: 'Sasha Lin', email: 'sasha.lin@example.com', title: 'Senior SOC Analyst' }));
    currentUser.mockReturnValue(account);
    const { container } = renderSettings();
    await screen.findByDisplayValue('owner@liveoak.test');
    expect(window.localStorage.getItem('aisoc:settings:profile')).toBeNull();
    expect(container.textContent).not.toContain('Sasha Lin');
  });
});

describe('Settings > Workspace', () => {
  async function openWorkspace() {
    currentUser.mockReturnValue(account);
    const view = renderSettings();
    await userEvent.setup().click(await screen.findByRole('button', { name: /^Workspace/ }));
    return view;
  }

  it('shows the real tenant and its real members, and nothing made up', async () => {
    details.mockResolvedValue(tenant);
    users.mockResolvedValue([member({ email: 'owner@liveoak.test', username: 'hal', role: 'admin' }), member({ email: 'tech@liveoak.test', role: 'analyst', is_active: false })]);
    const { container } = await openWorkspace();

    expect(await screen.findByText('Live Oak IT')).toBeInTheDocument();
    expect(screen.getByText(tenant.id)).toBeInTheDocument();
    expect(screen.getByText('open-source')).toBeInTheDocument();
    expect(screen.getByText('October 7th, 2026')).toBeInTheDocument();
    expect(await screen.findByText('2 members in this workspace.')).toBeInTheDocument();
    expect(screen.getByText('hal')).toBeInTheDocument();
    expect(screen.getAllByText(/tech@liveoak\.test/).length).toBeGreaterThan(0);
    expect(screen.getByText('Disabled')).toBeInTheDocument();
    for (const demo of DEMO) expect(container.textContent).not.toContain(demo);
    expect(screen.queryByText('Region')).not.toBeInTheDocument(); // there is no source for a region
  });

  it('counts a single member in the singular', async () => {
    details.mockResolvedValue(tenant);
    users.mockResolvedValue([member({ email: 'owner@liveoak.test', role: 'admin' })]);
    await openWorkspace();
    expect(await screen.findByText('1 member in this workspace.')).toBeInTheDocument();
  });

  it('says there are no members rather than inventing some', async () => {
    details.mockResolvedValue(tenant);
    users.mockResolvedValue([]);
    await openWorkspace();
    expect(await screen.findByText('No members found.')).toBeInTheDocument();
  });

  it('tells a role that is not permitted so, and shows no sample data in its place', async () => {
    details.mockRejectedValue(new ApiError('Permission denied: settings:read', 403, ''));
    users.mockRejectedValue(new ApiError('Permission denied: users:read', 403, ''));
    const { container } = await openWorkspace();
    expect(await screen.findByText(/not permitted to view this workspace/)).toBeInTheDocument();
    expect(await screen.findByText(/not permitted to view the members of this workspace/)).toBeInTheDocument();
    for (const demo of DEMO) expect(container.textContent).not.toContain(demo);
  });

  it('shows the real error for any other failure', async () => {
    details.mockRejectedValue(new Error('connection refused'));
    users.mockResolvedValue([]);
    await openWorkspace();
    expect(await screen.findByText(/Could not load this workspace \(connection refused\)/)).toBeInTheDocument();
  });

  it('shows the tenant even when the member list is refused (separate permissions)', async () => {
    details.mockResolvedValue(tenant);
    users.mockRejectedValue(new ApiError('Permission denied: users:read', 403, ''));
    await openWorkspace();
    expect(await screen.findByText('Live Oak IT')).toBeInTheDocument();
    expect(await screen.findByText(/not permitted to view the members/)).toBeInTheDocument();
  });
});

describe('workspaceProblem', () => {
  it('distinguishes "not permitted" from "failed"', () => {
    expect(workspaceProblem(new ApiError('x', 403, ''), 'this workspace')).toBe('Your role is not permitted to view this workspace. Ask a workspace administrator.');
    expect(workspaceProblem(new Error('boom'), 'this workspace')).toBe('Could not load this workspace (boom).');
    expect(workspaceProblem('weird', 'this workspace')).toBe('Could not load this workspace.');
  });
});
