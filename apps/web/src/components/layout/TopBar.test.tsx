import { beforeEach, describe, expect, it, vi } from 'vitest';
import { act, render, screen, waitFor } from '@testing-library/react';
import userEvent from '@testing-library/user-event';

const pathnameMock = vi.fn(() => '/cases');
const replaceMock = vi.fn();
// A plain function, NOT vi.fn(): a spy attaches its own handler to any promise it returns (to record settled results), so it could never
// hand the component an unhandled rejection.
const pushTeardown = { calls: 0, impl: (): Promise<boolean> => Promise.resolve(true) };
// Stand-in for the server-side session end. It records whether the stored login STILL EXISTED when it was called (the whole point of the ordering).
const serverSignOut = {
  calls: 0,
  tokenAtCall: null as string | null,
  impl: (): Promise<{ ended: boolean; message: string | null }> => Promise.resolve({ ended: true, message: null }),
};
const toastError = vi.hoisted(() => vi.fn());

vi.mock('next/navigation', () => ({
  usePathname: () => pathnameMock(),
  useRouter: () => ({ push: vi.fn(), replace: replaceMock }),
}));

vi.mock('react-hot-toast', () => ({ __esModule: true, default: Object.assign(vi.fn(), { error: toastError, success: vi.fn() }) }));

vi.mock('@/lib/auth-session', async (importOriginal) => ({
  ...(await importOriginal<typeof import('@/lib/auth-session')>()),
  revokeServerSession: () => {
    serverSignOut.calls += 1;
    serverSignOut.tokenAtCall = window.localStorage.getItem('aisoc.responder.accessToken');
    return serverSignOut.impl();
  },
}));

// Keep every other export of the push module real; only the network teardown is stubbed.
vi.mock('@/lib/pwa', async (importOriginal) => ({
  ...(await importOriginal<typeof import('@/lib/pwa')>()),
  unsubscribeFromPush: () => {
    pushTeardown.calls += 1;
    return pushTeardown.impl();
  },
}));

import { TopBar } from './TopBar';
import { ThemeProvider } from '../theme/ThemeProvider';
import { TimeWindowProvider } from './TimeWindowProvider';
import { TenantProvider } from './TenantProvider';
import { AUTH_REFRESH_KEY, AUTH_TOKEN_KEY, AUTH_USER_KEY } from '@/lib/auth-session';

// TopBar depends on three React contexts:
//  - <ThemeProvider/>      for the WS-F1 theme toggle (`useTheme`)
//  - <TimeWindowProvider/> for the v1.5 W4 global time-window selector
//  - <TenantProvider/>     for the v1.5 W5 tenant switcher + role badge
// Wrap all three here so each test reads naturally without re-stating the
// provider scaffolding.
function renderTopBar() {
  return render(
    <ThemeProvider>
      <TimeWindowProvider>
        <TenantProvider>
          <TopBar />
        </TenantProvider>
      </TimeWindowProvider>
    </ThemeProvider>,
  );
}

describe('TopBar', () => {
  it('shows the per-route title and description for known paths', () => {
    pathnameMock.mockReturnValue('/cases');
    renderTopBar();

    expect(screen.getByRole('heading', { level: 1 })).toHaveTextContent('Cases');
    expect(screen.getByText('Incident case management')).toBeInTheDocument();
  });

  it('matches the most specific nested route first', () => {
    // /detection/catalog must win over /detection.
    pathnameMock.mockReturnValue('/detection/catalog');
    renderTopBar();

    expect(screen.getByRole('heading', { level: 1 })).toHaveTextContent('Detection Catalog');
  });

  it('derives a sensible title for unknown routes from the path itself', () => {
    // Regression: previously fell back to "Alerts" for everything unmapped.
    pathnameMock.mockReturnValue('/some-new-page');
    renderTopBar();

    expect(screen.getByRole('heading', { level: 1 })).toHaveTextContent('Some New Page');
  });

  it('dispatches a Cmd-K keyboard event when the palette button is clicked', async () => {
    pathnameMock.mockReturnValue('/dashboard');
    renderTopBar();

    const listener = vi.fn();
    window.addEventListener('keydown', listener);

    await userEvent.click(screen.getByRole('button', { name: /open command palette/i }));

    expect(listener).toHaveBeenCalled();
    const event = listener.mock.calls[0][0] as KeyboardEvent;
    expect(event.key).toBe('k');
    expect(event.metaKey).toBe(true);

    window.removeEventListener('keydown', listener);
  });
});

class WatchedFailure extends Promise<boolean> {
  static get [Symbol.species]() {
    return Promise;
  }

  handled = false;

  then<T1 = boolean, T2 = never>(
    onFulfilled?: ((value: boolean) => T1 | PromiseLike<T1>) | null,
    onRejected?: ((reason: unknown) => T2 | PromiseLike<T2>) | null,
  ): Promise<T1 | T2> {
    if (onRejected) this.handled = true;
    return super.then(onFulfilled, onRejected);
  }
}

// The desktop console had NO way to end a session (a logout function existed; nothing called it), and the identity at the right of the bar
// was hard-coded placeholder text ("SO" / "SOC Analyst" / "Admin") for everyone.
describe('TopBar: who is signed in, and signing out', () => {
  const user = { id: 'u1', email: 'hal@example.com', role: 'tenant_admin', tenant_id: 't1' };

  beforeEach(() => {
    window.localStorage.clear();
    replaceMock.mockReset();
    pushTeardown.calls = 0;
    pushTeardown.impl = () => Promise.resolve(true);
    serverSignOut.calls = 0;
    serverSignOut.tokenAtCall = null;
    serverSignOut.impl = () => Promise.resolve({ ended: true, message: null });
    toastError.mockReset();
    pathnameMock.mockReturnValue('/cases');
  });

  it('offers a Sign out button', () => {
    renderTopBar();
    expect(screen.getByRole('button', { name: /sign out/i })).toBeInTheDocument();
  });

  it('signing out clears the stored login, drops the push subscription, and goes to the sign-in page', async () => {
    window.localStorage.setItem(AUTH_TOKEN_KEY, 'access');
    window.localStorage.setItem(AUTH_REFRESH_KEY, 'refresh');
    window.localStorage.setItem(AUTH_USER_KEY, JSON.stringify(user));
    renderTopBar();
    await userEvent.setup().click(screen.getByRole('button', { name: /sign out/i }));
    await waitFor(() => expect(replaceMock).toHaveBeenCalledWith('/login'));

    expect(window.localStorage.getItem(AUTH_TOKEN_KEY)).toBeNull();
    expect(window.localStorage.getItem(AUTH_REFRESH_KEY)).toBeNull();
    expect(window.localStorage.getItem(AUTH_USER_KEY)).toBeNull();
    expect(pushTeardown.calls).toBe(1);
    expect(replaceMock).toHaveBeenCalledWith('/login');
  });

  it('still signs out when the push teardown fails, and the failure is handled rather than left unhandled', async () => {
    // The stub returns a rejected promise that records whether anything attached a REJECTION handler to it. That is true for .catch(),
    // .then(_, handler) and try { await } catch (await on a Promise subclass goes through its `then`), and false for a bare `void`,
    // which leaves an unhandled rejection (Vitest reports those outside the pass/fail count).
    let watched: WatchedFailure | undefined;
    pushTeardown.impl = () => {
      watched = new WatchedFailure((_resolve, reject) => reject(new Error('gateway unreachable')));
      Promise.prototype.then.call(watched, undefined, () => undefined); // keeps this test's OWN promise from being reported as unhandled
      return watched;
    };
    window.localStorage.setItem(AUTH_TOKEN_KEY, 'access');
    renderTopBar();
    await userEvent.setup().click(screen.getByRole('button', { name: /sign out/i }));
    await new Promise((resolve) => setTimeout(resolve, 0)); // let an async try/await/catch reach its catch
    await waitFor(() => expect(replaceMock).toHaveBeenCalledWith('/login'));

    expect(watched?.handled).toBe(true);
    expect(window.localStorage.getItem(AUTH_TOKEN_KEY)).toBeNull();
    expect(replaceMock).toHaveBeenCalledWith('/login');
  });

  it('shows the real signed-in user instead of hard-coded placeholder text', async () => {
    window.localStorage.setItem(AUTH_USER_KEY, JSON.stringify(user));
    renderTopBar();
    expect(await screen.findByText('hal@example.com')).toBeInTheDocument();
    expect(screen.getByText('HA')).toBeInTheDocument();
    expect(screen.queryByText('SOC Analyst')).not.toBeInTheDocument();
    expect(screen.queryByText('SO')).not.toBeInTheDocument();
  });

  it('shows the username with the email beneath it when there is one', async () => {
    window.localStorage.setItem(AUTH_USER_KEY, JSON.stringify({ ...user, username: 'hal' }));
    renderTopBar();
    expect(await screen.findByText('hal')).toBeInTheDocument();
    expect(screen.getByText('hal@example.com')).toBeInTheDocument();
  });

  describe('with an account name', () => {
    const named = { id: 'u1', account_name: 'hal.liveoak', role: 'tenant_admin', tenant_id: 't1' };

    it('shows the account name for a person who has no email and no display name', async () => {
      window.localStorage.setItem(AUTH_USER_KEY, JSON.stringify(named));
      renderTopBar();
      expect(await screen.findByText('hal.liveoak')).toBeInTheDocument();
      expect(screen.getByText('HA')).toBeInTheDocument();
      expect(screen.queryByText('undefined')).not.toBeInTheDocument();
      expect(screen.queryByText('null')).not.toBeInTheDocument();
    });

    it('prefers the account name to the email when there is no display name', async () => {
      window.localStorage.setItem(AUTH_USER_KEY, JSON.stringify({ ...named, email: 'hal@example.com' }));
      renderTopBar();
      expect(await screen.findByText('hal.liveoak')).toBeInTheDocument();
      expect(screen.queryByText('hal@example.com')).not.toBeInTheDocument();
    });

    it('shows the display name with the account name beneath it, not the email', async () => {
      window.localStorage.setItem(AUTH_USER_KEY, JSON.stringify({ ...named, username: 'Hal M', email: 'hal@example.com' }));
      renderTopBar();
      expect(await screen.findByText('Hal M')).toBeInTheDocument();
      expect(screen.getByText('hal.liveoak')).toBeInTheDocument();
      expect(screen.queryByText('hal@example.com')).not.toBeInTheDocument();
    });

    it('shows the display name with the account name beneath it when there is no email at all', async () => {
      window.localStorage.setItem(AUTH_USER_KEY, JSON.stringify({ ...named, username: 'Hal M' }));
      renderTopBar();
      expect(await screen.findByText('Hal M')).toBeInTheDocument();
      expect(screen.getByText('hal.liveoak')).toBeInTheDocument();
    });

    it('still shows an older stored login that has only an email', async () => {
      window.localStorage.setItem(AUTH_USER_KEY, JSON.stringify({ id: 'u1', email: 'old@example.com', role: 'tenant_admin', tenant_id: 't1' }));
      renderTopBar();
      expect(await screen.findByText('old@example.com')).toBeInTheDocument();
    });
  });
  it('claims no identity when nobody is stored, and Sign out still works', async () => {
    renderTopBar();
    expect(screen.queryByText('SOC Analyst')).not.toBeInTheDocument();
    expect(screen.getByText('?')).toBeInTheDocument();
    await userEvent.setup().click(screen.getByRole('button', { name: /sign out/i }));
    await waitFor(() => expect(replaceMock).toHaveBeenCalledWith('/login'));
  });

  describe('ending the session on the server', () => {
    const storeLogin = () => {
      window.localStorage.setItem(AUTH_TOKEN_KEY, 'access');
      window.localStorage.setItem(AUTH_REFRESH_KEY, 'refresh');
      window.localStorage.setItem(AUTH_USER_KEY, JSON.stringify(user));
    };

    it('asks the server while the login still exists, after the push teardown, and before forgetting it', async () => {
      storeLogin();
      const order: string[] = [];
      pushTeardown.impl = () => { order.push('push'); return Promise.resolve(true); };
      serverSignOut.impl = () => { order.push('server'); return Promise.resolve({ ended: true, message: null }); };
      renderTopBar();
      await userEvent.setup().click(screen.getByRole('button', { name: /sign out/i }));
      await waitFor(() => expect(replaceMock).toHaveBeenCalledWith('/login'));

      expect(serverSignOut.calls).toBe(1);
      expect(serverSignOut.tokenAtCall).toBe('access'); // the token was still there to authorise the revocation
      expect(order).toEqual(['push', 'server']);
      expect(window.localStorage.getItem(AUTH_TOKEN_KEY)).toBeNull(); // and was forgotten afterwards
    });

    it('says nothing alarming when the server confirms', async () => {
      storeLogin();
      renderTopBar();
      await userEvent.setup().click(screen.getByRole('button', { name: /sign out/i }));
      await waitFor(() => expect(replaceMock).toHaveBeenCalledWith('/login'));
      expect(toastError).not.toHaveBeenCalled();
    });

    it('still signs out here, and says honestly that the server did not end the session, when it could not', async () => {
      storeLogin();
      serverSignOut.impl = () => Promise.resolve({ ended: false, message: 'the server could not be reached' });
      renderTopBar();
      await userEvent.setup().click(screen.getByRole('button', { name: /sign out/i }));
      await waitFor(() => expect(replaceMock).toHaveBeenCalledWith('/login'));

      expect(window.localStorage.getItem(AUTH_TOKEN_KEY)).toBeNull(); // signed out on this device regardless
      expect(window.localStorage.getItem(AUTH_REFRESH_KEY)).toBeNull();
      expect(toastError).toHaveBeenCalledTimes(1);
      const message = toastError.mock.calls[0][0] as string;
      expect(message).toContain('Signed out on this device');
      expect(message).toContain('the server could not be reached');
      expect(message).toContain('change your password');
    });

    it('does not repeat the sign-out when the button is clicked again while it is in progress', async () => {
      storeLogin();
      let release: (v: { ended: boolean; message: string | null }) => void = () => undefined;
      serverSignOut.impl = () => new Promise((resolve) => { release = resolve; });
      renderTopBar();
      const user2 = userEvent.setup();
      const button = screen.getByRole('button', { name: /sign out/i });
      await user2.click(button);
      expect(button).toBeDisabled();
      await user2.click(button);
      await act(async () => { release({ ended: true, message: null }); });
      await waitFor(() => expect(replaceMock).toHaveBeenCalledWith('/login'));
      expect(serverSignOut.calls).toBe(1);
      expect(replaceMock).toHaveBeenCalledTimes(1);
    });

    it('does not let a push teardown that never answers keep the user from signing out', async () => {
      // Real timers on purpose (fake ones fight testing-library's async helpers): the component gives the push teardown 3 seconds, so this test takes about that long.
      storeLogin();
      pushTeardown.impl = () => new Promise<boolean>(() => undefined); // never settles
      renderTopBar();
      await userEvent.setup().click(screen.getByRole('button', { name: /sign out/i }));
      await new Promise((resolve) => setTimeout(resolve, 300));
      expect(replaceMock).not.toHaveBeenCalled(); // still waiting on the push teardown, not yet given up on
      expect(serverSignOut.calls).toBe(0);
      await waitFor(() => expect(replaceMock).toHaveBeenCalledWith('/login'), { timeout: 5000 });
      expect(serverSignOut.calls).toBe(1); // it moved on and still asked the server
      expect(window.localStorage.getItem(AUTH_TOKEN_KEY)).toBeNull();
    }, 10000);
  });
});

