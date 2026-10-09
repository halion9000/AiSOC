import { beforeEach, describe, expect, it, vi } from 'vitest';
import { render, screen, waitFor, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';

// Revoking a passkey is permanent and can lock a responder out of a device. The Revoke button used to revoke on the first click; it now opens a confirmation naming the passkey, with an extra warning when it is the only one.

const passkeyApi = vi.hoisted(() => ({ list: vi.fn(), delete: vi.fn(), registerBegin: vi.fn(), registerFinish: vi.fn() }));
vi.mock('@/lib/api', () => ({ __esModule: true, passkeyApi, responderApi: { testNotify: vi.fn() } }));
vi.mock('next/navigation', () => ({ useRouter: () => ({ push: vi.fn(), replace: vi.fn() }) }));
vi.mock('@/lib/responder/auth', () => ({ clearSession: vi.fn(), getProfile: () => null }));
vi.mock('@/lib/responder/webauthn', () => ({ createPasskey: vi.fn(), isWebAuthnSupported: () => true }));
vi.mock('@/lib/pwa', () => ({
  getServiceWorkerStatus: vi.fn().mockResolvedValue(null),
  isStandalone: () => false,
  onInstallPromptAvailable: () => () => undefined,
  requestNotificationPermission: vi.fn().mockResolvedValue({ supported: false, state: 'default' }),
  showInstallPrompt: vi.fn(),
  subscribeToPush: vi.fn(),
  unsubscribeFromPush: vi.fn().mockResolvedValue(undefined),
}));

import ResponderSettingsPage from './page';

const cred = (id: string, name: string) => ({ id, device_name: name, created_at: '2026-01-01T00:00:00Z', last_used_at: null });

beforeEach(() => {
  passkeyApi.list.mockReset();
  passkeyApi.delete.mockReset();
});

async function open(items = [cred('p1', 'Pixel 9'), cred('p2', 'Work laptop')]) {
  passkeyApi.list.mockResolvedValue({ items });
  render(<ResponderSettingsPage />);
  await screen.findByText(items[0].device_name);
  return userEvent.setup();
}
const revokeFor = (name: string) => within(screen.getByText(name).closest('li')!).getByRole('button', { name: /^revoke$/i });

describe('revoking a passkey', () => {
  it('does NOT revoke on the first click: it asks, naming the passkey', async () => {
    const user = await open();
    await user.click(revokeFor('Pixel 9'));
    const dialog = await screen.findByRole('alertdialog', { name: 'Revoke passkey?' });
    expect(dialog).toHaveAccessibleDescription(/Revoke "Pixel 9"\? You will no longer be able to sign in with it\. This cannot be undone\./);
    expect(passkeyApi.delete).not.toHaveBeenCalled();
  });

  it('names the passkey that was CHOSEN, not the first one in the list', async () => {
    const user = await open();
    await user.click(revokeFor('Work laptop'));
    const description = (await screen.findByRole('alertdialog')).getAttribute('aria-describedby');
    expect(document.getElementById(description!)).toHaveTextContent('Revoke "Work laptop"?');
    expect(document.getElementById(description!)).not.toHaveTextContent('Pixel 9');
  });

  it('revokes exactly the passkey chosen, once, only after confirming, and removes it from the list', async () => {
    passkeyApi.delete.mockResolvedValue(undefined);
    const user = await open();
    await user.click(revokeFor('Work laptop'));
    await user.click(await screen.findByRole('button', { name: 'Revoke passkey' }));
    await waitFor(() => expect(passkeyApi.delete).toHaveBeenCalledWith('p2'));
    expect(passkeyApi.delete).toHaveBeenCalledTimes(1);
    expect(await screen.findByText('Passkey revoked.')).toBeInTheDocument();
    expect(screen.queryByText('Work laptop')).not.toBeInTheDocument();
    expect(screen.getByText('Pixel 9')).toBeInTheDocument();
    expect(screen.queryByRole('alertdialog')).not.toBeInTheDocument();
  });

  it('Cancel revokes nothing', async () => {
    const user = await open();
    await user.click(revokeFor('Pixel 9'));
    await user.click(await screen.findByRole('button', { name: 'Cancel' }));
    expect(screen.queryByRole('alertdialog')).not.toBeInTheDocument();
    expect(passkeyApi.delete).not.toHaveBeenCalled();
    expect(screen.getByText('Pixel 9')).toBeInTheDocument();
  });

  it('Escape revokes nothing', async () => {
    const user = await open();
    await user.click(revokeFor('Pixel 9'));
    await screen.findByRole('alertdialog');
    await user.keyboard('{Escape}');
    expect(screen.queryByRole('alertdialog')).not.toBeInTheDocument();
    expect(passkeyApi.delete).not.toHaveBeenCalled();
  });

  it('warns that the responder may be locked out when it is the ONLY passkey', async () => {
    const user = await open([cred('p1', 'Pixel 9')]);
    await user.click(revokeFor('Pixel 9'));
    expect(await screen.findByRole('alertdialog')).toHaveAccessibleDescription(/It is your only registered passkey, so you may be locked out\./);
  });

  it('gives no lockout warning when another passkey remains', async () => {
    const user = await open();
    await user.click(revokeFor('Pixel 9'));
    expect(await screen.findByRole('alertdialog')).not.toHaveAccessibleDescription(/locked out/);
  });

  it('shows the error, keeps the passkey and closes the dialog when the revoke fails', async () => {
    passkeyApi.delete.mockRejectedValue(new Error('Server said no'));
    const user = await open();
    await user.click(revokeFor('Pixel 9'));
    await user.click(await screen.findByRole('button', { name: 'Revoke passkey' }));
    expect(await screen.findByText('Server said no')).toBeInTheDocument();
    expect(screen.getByText('Pixel 9')).toBeInTheDocument();
    expect(screen.queryByText('Passkey revoked.')).not.toBeInTheDocument();
    expect(screen.queryByRole('alertdialog')).not.toBeInTheDocument();
  });

  it('locks the dialog while the revoke is in flight, so a second click cannot revoke twice', async () => {
    passkeyApi.delete.mockReturnValue(new Promise(() => undefined));
    const user = await open();
    await user.click(revokeFor('Pixel 9'));
    await user.click(await screen.findByRole('button', { name: 'Revoke passkey' }));
    const working = await screen.findByRole('button', { name: 'Working...' });
    expect(working).toBeDisabled();
    await user.click(working);
    expect(passkeyApi.delete).toHaveBeenCalledTimes(1);
  });
});
