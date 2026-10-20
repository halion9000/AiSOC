import { beforeEach, describe, expect, it, vi } from 'vitest';
import { render, screen, waitFor } from '@testing-library/react';
import userEvent from '@testing-library/user-event';

const authFetch = vi.hoisted(() => vi.fn());
vi.mock('@/lib/auth-session', () => ({ authFetch }));
const routerParams = vi.hoisted(() => ({ current: new URLSearchParams('') }));
vi.mock('next/navigation', () => ({ useSearchParams: () => routerParams.current }));

import { MfaStatus, coveragePercent, visibleClients } from './MfaStatus';

const reply = (body: unknown, ok = true) => ({ ok, status: ok ? 200 : 500, json: () => Promise.resolve(body) });
const client = (over: Record<string, unknown> = {}) => ({ client_id: 'c1', client_name: 'Acme Dental', people: 20, with_mfa: 15, not_required: 2, without_mfa: 3, admins_without_mfa: 1, refreshed_at: '2026-10-19T10:00:00Z', ...over });

beforeEach(() => {
  authFetch.mockReset();
  routerParams.current = new URLSearchParams('');
});

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
    expect(await screen.findByTestId('totals')).toHaveTextContent('30 people across 2 clients: 3 with no Multi-Factor, 1 of them administrators.');
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

  it('can narrow the list to clients whose administrators have no second factor', async () => {
    authFetch.mockResolvedValue(reply([client(), client({ client_id: 'c2', client_name: 'Birch Law', admins_without_mfa: 0 })]));
    render(<MfaStatus />);
    await screen.findByTestId('totals');
    expect(screen.getAllByTestId('client-row')).toHaveLength(2);
    await userEvent.click(screen.getByTestId('admins-only'));
    const rows = screen.getAllByTestId('client-row');
    expect(rows).toHaveLength(1);
    expect(rows[0]).toHaveTextContent('Acme Dental');
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

describe('finding a client', () => {
  const many = [client({ client_id: 'z', client_name: 'Zeta Law' }), client({ client_id: 'a', client_name: 'acme dental' }), client({ client_id: 'b', client_name: 'Birch Vet', admins_without_mfa: 0 })];

  it('lists the clients A to Z whatever order the API gave them in, ignoring case', async () => {
    authFetch.mockResolvedValue(reply(many));
    render(<MfaStatus />);
    await screen.findByTestId('totals');
    expect(screen.getAllByTestId('client-row').map((r) => r.textContent?.slice(0, 10))).toEqual(['acme denta', 'Birch Vet2', 'Zeta Law20']);
  });

  it('narrows the list as you type in the search box, and says when nothing matches', async () => {
    authFetch.mockResolvedValue(reply(many));
    render(<MfaStatus />);
    await screen.findByTestId('totals');
    await userEvent.type(screen.getByLabelText('Search clients'), 'bir');
    expect(screen.getAllByTestId('client-row')).toHaveLength(1);
    expect(screen.getByTestId('client-row')).toHaveTextContent('Birch Vet');
    await userEvent.clear(screen.getByLabelText('Search clients'));
    await userEvent.type(screen.getByLabelText('Search clients'), 'zzz');
    expect(screen.getByTestId('no-match')).toBeInTheDocument();
  });

  it('a link that names a client and a list opens the list for that client straight away, and Show all brings the others back', async () => {
    routerParams.current = new URLSearchParams('client=b&which=without');
    authFetch.mockImplementation((url?: string) => Promise.resolve((url ?? '').includes('/mfa-users') ? reply([{ upn: 'bob@birch.com', display_name: null, admin: false, registered: false, required: false, methods: null }]) : reply(many)));
    render(<MfaStatus />);
    expect(await screen.findByTestId('people-without')).toHaveTextContent('bob@birch.com');
    expect(authFetch).toHaveBeenCalledWith('/api/v1/identity/mfa-users?client_id=b&which=without');
    expect(screen.getAllByTestId('client-row')).toHaveLength(1);
    await userEvent.click(screen.getByTestId('show-all-clients'));
    expect(screen.getAllByTestId('client-row')).toHaveLength(3);
  });

  it('uses the words Multi-Factor, not "second factor"', async () => {
    authFetch.mockResolvedValue(reply(many));
    const { container } = render(<MfaStatus />);
    await screen.findByTestId('totals');
    expect(container.textContent).toContain('No Multi-Factor');
    expect(container.textContent?.toLowerCase()).not.toContain('second factor');
    expect(container.textContent?.toLowerCase()).not.toContain('second sign-in factor');
  });
});

describe('visibleClients', () => {
  const cs = [client({ client_id: 'x', client_name: 'Bee' }), client({ client_id: 'y', client_name: 'Ant', admins_without_mfa: 0 })];
  it('sorts, searches, filters to administrators and to one client', () => {
    expect(visibleClients(cs, {}).map((c) => c.client_id)).toEqual(['y', 'x']);
    expect(visibleClients(cs, { query: ' BE ' }).map((c) => c.client_id)).toEqual(['x']);
    expect(visibleClients(cs, { adminsOnly: true }).map((c) => c.client_id)).toEqual(['x']);
    expect(visibleClients(cs, { onlyClient: 'y' }).map((c) => c.client_id)).toEqual(['y']);
  });
});
