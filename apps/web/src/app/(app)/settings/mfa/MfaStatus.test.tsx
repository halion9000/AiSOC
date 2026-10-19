import { beforeEach, describe, expect, it, vi } from 'vitest';
import { render, screen, waitFor } from '@testing-library/react';
import userEvent from '@testing-library/user-event';

const authFetch = vi.hoisted(() => vi.fn());
vi.mock('@/lib/auth-session', () => ({ authFetch }));

import { MfaStatus, coveragePercent } from './MfaStatus';

const reply = (body: unknown, ok = true) => ({ ok, status: ok ? 200 : 500, json: () => Promise.resolve(body) });
const client = (over: Record<string, unknown> = {}) => ({ client_id: 'c1', client_name: 'Acme Dental', people: 20, with_mfa: 15, not_required: 2, without_mfa: 3, admins_without_mfa: 1, refreshed_at: '2026-10-19T10:00:00Z', ...over });

beforeEach(() => authFetch.mockReset());

describe('coveragePercent', () => {
  it('is the share of people with a required second factor, or a dash when there are none', () => {
    expect(coveragePercent({ people: 20, with_mfa: 15 })).toBe('75%');
    expect(coveragePercent({ people: 0, with_mfa: 0 })).toBe('—');
  });
});

describe('MfaStatus', () => {
  it('lists each client with its counts and a total line', async () => {
    authFetch.mockResolvedValue(reply([client(), client({ client_id: 'c2', client_name: 'Birch Law', people: 10, with_mfa: 10, not_required: 0, without_mfa: 0, admins_without_mfa: 0 })]));
    render(<MfaStatus />);
    expect(await screen.findByTestId('totals')).toHaveTextContent('30 people across 2 clients: 3 with no second factor, 1 of them administrators.');
    const rows = screen.getAllByTestId('client-row');
    expect(rows[0]).toHaveTextContent('Acme Dental');
    expect(rows[0]).toHaveTextContent('75%');
    expect(rows[1]).toHaveTextContent('100%');
  });

  it('opens a client to name the people with no second factor, administrators marked', async () => {
    authFetch.mockImplementation((url?: string) =>
      Promise.resolve(
        (url ?? '').includes('/mfa-users')
          ? reply([
              { upn: 'admin@acme.com', display_name: 'The Admin', admin: true, registered: false, required: false, methods: null },
              { upn: 'bob@acme.com', display_name: null, admin: false, registered: false, required: false, methods: null },
            ])
          : reply([client()]),
      ),
    );
    render(<MfaStatus />);
    await userEvent.click(await screen.findByRole('button', { name: '3' }));
    const list = await screen.findByTestId('people-without');
    expect(list).toHaveTextContent('admin@acme.com');
    expect(list).toHaveTextContent('administrator');
    expect(list).toHaveTextContent('bob@acme.com');
    expect(authFetch).toHaveBeenCalledWith('/api/v1/identity/mfa-users?client_id=c1&which=without');
  });

  it('can show the people who registered a second factor that nothing requires', async () => {
    authFetch.mockImplementation((url?: string) => Promise.resolve((url ?? '').includes('/mfa-users') ? reply([]) : reply([client()])));
    render(<MfaStatus />);
    await userEvent.click(await screen.findByRole('button', { name: '2' }));
    await waitFor(() => expect(authFetch).toHaveBeenCalledWith('/api/v1/identity/mfa-users?client_id=c1&which=not_required'));
    expect(await screen.findByText('Nobody.')).toBeInTheDocument();
  });

  it('says what to do when there is nothing yet, and shows an error plainly', async () => {
    authFetch.mockResolvedValue(reply([]));
    const { unmount } = render(<MfaStatus />);
    expect(await screen.findByTestId('none')).toHaveTextContent('Nothing yet');
    unmount();
    authFetch.mockResolvedValue(reply({}, false));
    render(<MfaStatus />);
    expect(await screen.findByRole('alert')).toHaveTextContent('The API answered 500');
  });
});
