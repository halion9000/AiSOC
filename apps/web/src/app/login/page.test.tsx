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

  it('still presents a normal email and password sign-in', () => {
    render(<LoginPage />);
    expect(screen.getByRole('heading', { name: /sign in to aisoc/i })).toBeInTheDocument();
    expect(screen.getByPlaceholderText('you@company.com')).toBeInTheDocument();
    expect(screen.getByRole('button', { name: /^sign in$/i })).toBeInTheDocument();
    expect(screen.getByText(/sign in with your tenant/i)).toBeInTheDocument();
  });

  it('signs in with exactly what the person typed (nothing is pre-filled)', async () => {
    login.mockResolvedValue({});
    const user = userEvent.setup();
    render(<LoginPage />);
    const email = screen.getByPlaceholderText('you@company.com') as HTMLInputElement;
    expect(email.value).toBe('');
    await user.type(email, 'hal@example.com');
    await user.type(document.querySelector('input[type="password"]') as HTMLInputElement, 'a-real-password');
    await user.click(screen.getByRole('button', { name: /^sign in$/i }));
    await waitFor(() => expect(login).toHaveBeenCalledWith('hal@example.com', 'a-real-password'));
  });

  it('sends someone who is already signed in straight on instead of showing the form', async () => {
    isAuthenticated.mockReturnValue(true);
    render(<LoginPage />);
    await waitFor(() => expect(replace).toHaveBeenCalled());
  });
});
