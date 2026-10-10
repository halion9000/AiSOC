import { describe, expect, it, vi, beforeEach } from 'vitest';
import { render, screen, waitFor } from '@testing-library/react';
import userEvent from '@testing-library/user-event';

const push = vi.fn();
const replace = vi.fn();
const login = vi.fn();
const isAuthenticated = vi.fn();

vi.mock('next/navigation', () => ({
  useRouter: () => ({ push, replace }),
  useSearchParams: () => new URLSearchParams(),
  usePathname: () => '/login',
}));

vi.mock('@/lib/api', () => ({
  authApi: { login: (...args: unknown[]) => login(...args), isAuthenticated: () => isAuthenticated() },
}));

import LoginPage from './page';

// There is no demo mode. The sign-in page used to offer a "Public demo" card whose credentials were empty strings (so it showed a bare "/" and
// "Use demo" filled in nothing) and a subtitle telling people to use "the demo credentials below".
describe('the sign-in page', () => {
  beforeEach(() => {
    push.mockReset();
    replace.mockReset();
    login.mockReset();
    isAuthenticated.mockReset();
    isAuthenticated.mockReturnValue(false);
  });

  it('offers no demo credentials, button or wording anywhere', () => {
    const { container } = render(<LoginPage />);
    expect(screen.queryByText(/public demo/i)).not.toBeInTheDocument();
    expect(screen.queryByRole('button', { name: /use demo/i })).not.toBeInTheDocument();
    expect(container.textContent ?? '').not.toMatch(/demo/i);
  });

  it('presents an account name and password sign-in', () => {
    render(<LoginPage />);
    expect(screen.getByRole('heading', { name: /sign in to aisoc/i })).toBeInTheDocument();
    expect(screen.getByPlaceholderText('your.account.name')).toBeInTheDocument();
    expect(screen.getByLabelText(/account name/i)).toBeInTheDocument();
    expect(screen.queryByLabelText(/^email/i)).not.toBeInTheDocument();
    expect(screen.getByRole('button', { name: /^sign in$/i })).toBeInTheDocument();
    expect(screen.getByText(/sign in with your tenant/i)).toBeInTheDocument();
  });

  it('signs in with exactly what the person typed (nothing is pre-filled)', async () => {
    login.mockResolvedValue({});
    const user = userEvent.setup();
    render(<LoginPage />);
    const name = screen.getByPlaceholderText('your.account.name') as HTMLInputElement;
    expect(name.value).toBe('');
    await user.type(name, 'hal.liveoak');
    await user.type(document.querySelector('input[type="password"]') as HTMLInputElement, 'a-real-password');
    await user.click(screen.getByRole('button', { name: /^sign in$/i }));
    await waitFor(() => expect(login).toHaveBeenCalledWith('hal.liveoak', 'a-real-password'));
  });

  describe('the account name field', () => {
    const fill = async (identifier: string, password = 'pw') => {
      const user = userEvent.setup();
      render(<LoginPage />);
      await user.type(screen.getByLabelText(/account name/i), identifier);
      await user.type(document.querySelector('input[type="password"]') as HTMLInputElement, password);
      return user;
    };

    it('is a plain text field: a browser would refuse a name with no "@" in an email field', () => {
      render(<LoginPage />);
      const field = screen.getByLabelText(/account name/i);
      expect(field).toHaveAttribute('type', 'text');
      expect(field).not.toHaveAttribute('inputmode', 'email');
      expect(field).toHaveAttribute('autocomplete', 'username');
      expect(field).toHaveAttribute('autocapitalize', 'off');
    });

    it('trims what was typed before sending it', async () => {
      login.mockResolvedValue({});
      const user = await fill('  hal.liveoak  ');
      await user.click(screen.getByRole('button', { name: /^sign in$/i }));
      await waitFor(() => expect(login).toHaveBeenCalledWith('hal.liveoak', 'pw'));
    });

    it('still takes the old email, exactly as typed (the server allows it while people move over)', async () => {
      login.mockResolvedValue({});
      const user = await fill('hal@example.com');
      await user.click(screen.getByRole('button', { name: /^sign in$/i }));
      await waitFor(() => expect(login).toHaveBeenCalledWith('hal@example.com', 'pw'));
    });

    it('does not lower-case or otherwise change it (the server decides what matches)', async () => {
      login.mockResolvedValue({});
      const user = await fill('Hal.LiveOak');
      await user.click(screen.getByRole('button', { name: /^sign in$/i }));
      await waitFor(() => expect(login).toHaveBeenCalledWith('Hal.LiveOak', 'pw'));
    });

    it('keeps the button disabled until both an account name and a password are given', async () => {
      const user = userEvent.setup();
      render(<LoginPage />);
      const button = screen.getByRole('button', { name: /^sign in$/i });
      expect(button).toBeDisabled();
      await user.type(screen.getByLabelText(/account name/i), 'hal');
      expect(button).toBeDisabled();
      await user.type(document.querySelector('input[type="password"]') as HTMLInputElement, 'pw');
      expect(button).toBeEnabled();
    });
  });

  it('sends someone who is already signed in straight on instead of showing the form', async () => {
    isAuthenticated.mockReturnValue(true);
    render(<LoginPage />);
    await waitFor(() => expect(replace).toHaveBeenCalled());
  });
  describe('when the API refuses further sign-ins after too many failures', () => {
    const attempt = async () => {
      render(<LoginPage />);
      await userEvent.type(screen.getByLabelText(/account name/i), 'a.person');
      await userEvent.type(screen.getByLabelText(/password/i), 'wrong');
      await userEvent.click(screen.getByRole('button', { name: /sign in/i }));
    };
    const refusal = (status: number, body: string, message = `API ${status} x - /api/v1/auth/login`) => Object.assign(new Error(message), { status, body });

    it("shows the server's own sentence, with how long to wait, not 'API 429 ...'", async () => {
      login.mockRejectedValue(refusal(429, JSON.stringify({ detail: 'Too many failed sign-in attempts. Try again in about 12 minutes.' })));
      await attempt();
      expect(await screen.findByText('Too many failed sign-in attempts. Try again in about 12 minutes.')).toBeInTheDocument();
      expect(screen.queryByText(/API 429/)).not.toBeInTheDocument();
    });

    it.each([['not json'], [JSON.stringify({ other: 1 })], [JSON.stringify({ detail: '' })], [JSON.stringify({ detail: { nested: true } })]])(
      'still says so in plain words when the body is unusable (%s)',
      async (body) => {
        login.mockRejectedValue(refusal(429, body));
        await attempt();
        expect(await screen.findByText(/too many failed sign-in attempts/i)).toBeInTheDocument();
        expect(screen.queryByText(/API 429/)).not.toBeInTheDocument();
      },
    );

    it('a wrong password is still a plain "Account name or password incorrect."', async () => {
      login.mockRejectedValue(refusal(401, '{"detail":"Incorrect email or password"}', 'API 401 Unauthorized - /api/v1/auth/login'));
      await attempt();
      expect(await screen.findByText('Account name or password incorrect.')).toBeInTheDocument();
    });

    it('any other failure still shows its own message', async () => {
      login.mockRejectedValue(refusal(500, 'boom', 'Network error talking to /api/v1/auth/login'));
      await attempt();
      expect(await screen.findByText('Network error talking to /api/v1/auth/login')).toBeInTheDocument();
    });

    it('a 429 from somewhere that is not the lock is not mistaken for it if it has no status', async () => {
      login.mockRejectedValue(new Error('API 429 Too Many Requests'));
      await attempt();
      expect(await screen.findByText('API 429 Too Many Requests')).toBeInTheDocument();
    });
  });
});
