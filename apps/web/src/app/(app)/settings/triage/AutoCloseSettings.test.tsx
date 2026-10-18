import { cleanup, render, screen, waitFor } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

import { AutoCloseSettings } from './AutoCloseSettings';

const authFetch = vi.fn();
vi.mock('@/lib/auth-session', () => ({ authFetch: (...a: unknown[]) => authFetch(...a) }));
vi.mock('@/lib/api', () => ({
  apiErrorDetail: (e: { body?: string }) => {
    try {
      return JSON.parse(e.body ?? '{}').detail ?? null;
    } catch {
      return null;
    }
  },
}));

const reply = (body: unknown, status = 200) => Promise.resolve({ ok: status < 400, status, json: () => Promise.resolve(body), text: () => Promise.resolve(JSON.stringify(body)) });

beforeEach(() => {
  authFetch.mockReset();
});
afterEach(() => cleanup());

describe('AutoCloseSettings', () => {
  it('says the tenant follows the platform value when it has none, and offers no reset', async () => {
    authFetch.mockReturnValue(reply({ threshold: null, minimum: 0.5, maximum: 1 }));
    render(<AutoCloseSettings />);
    await waitFor(() => expect(screen.getByTestId('current').textContent).toContain('follows the platform value'));
    expect(screen.getByRole('button', { name: /Use the platform value/ })).toBeDisabled();
  });

  it('saves a valid number with PUT and reflects it', async () => {
    authFetch.mockReturnValueOnce(reply({ threshold: null, minimum: 0.5, maximum: 1 }));
    render(<AutoCloseSettings />);
    const input = await screen.findByLabelText('Auto-close confidence');
    authFetch.mockReturnValueOnce(reply({ threshold: 0.93, minimum: 0.5, maximum: 1 }));
    const user = userEvent.setup();
    await user.type(input, '0.93');
    await user.click(screen.getByRole('button', { name: 'Save' }));
    await waitFor(() => expect(screen.getByTestId('current').textContent).toContain('0.93'));
    const [, init] = authFetch.mock.calls[1];
    expect(init.method).toBe('PUT');
    expect(JSON.parse(init.body)).toEqual({ threshold: 0.93 });
  });

  it('will not send a number outside the range, and says so', async () => {
    authFetch.mockReturnValue(reply({ threshold: null, minimum: 0.5, maximum: 1 }));
    render(<AutoCloseSettings />);
    const user = userEvent.setup();
    await user.type(await screen.findByLabelText('Auto-close confidence'), '0.2');
    expect(screen.getByRole('button', { name: 'Save' })).toBeDisabled();
    expect(screen.getByRole('note').textContent).toContain('from 0.5 to 1');
    expect(authFetch).toHaveBeenCalledTimes(1); // only the initial read
  });

  it('goes back to the platform value with DELETE', async () => {
    authFetch.mockReturnValueOnce(reply({ threshold: 0.9, minimum: 0.5, maximum: 1 }));
    render(<AutoCloseSettings />);
    await screen.findByText(/closes at confidence 0.9/);
    authFetch.mockReturnValueOnce(reply({ threshold: null, minimum: 0.5, maximum: 1 }));
    await userEvent.setup().click(screen.getByRole('button', { name: /Use the platform value/ }));
    await waitFor(() => expect(screen.getByTestId('current').textContent).toContain('follows the platform value'));
    expect(authFetch.mock.calls[1][1].method).toBe('DELETE');
  });

  it("shows the API's reason when a save is refused", async () => {
    authFetch.mockReturnValueOnce(reply({ threshold: null, minimum: 0.5, maximum: 1 }));
    render(<AutoCloseSettings />);
    const input = await screen.findByLabelText('Auto-close confidence');
    authFetch.mockReturnValueOnce(reply({ detail: 'You need the settings:write permission' }, 403));
    const user = userEvent.setup();
    await user.type(input, '0.9');
    await user.click(screen.getByRole('button', { name: 'Save' }));
    expect((await screen.findByRole('alert')).textContent).toContain('settings:write');
  });
});
