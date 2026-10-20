import { beforeEach, describe, expect, it, vi } from 'vitest';
import { render, screen, waitFor } from '@testing-library/react';
import userEvent from '@testing-library/user-event';

const authFetch = vi.hoisted(() => vi.fn());
vi.mock('@/lib/auth-session', () => ({ authFetch }));

import { ClientCleanup } from './ClientCleanup';

const reply = (body: unknown, ok = true) => ({ ok, status: ok ? 200 : 500, json: () => Promise.resolve(body) });
const empty = (id: string, name: string) => ({ id, name, devices: 0, alerts: 0, cases: 0, tool_clients: 0 });

beforeEach(() => authFetch.mockReset());

describe('ClientCleanup', () => {
  it('lists the empty clients and how many were checked', async () => {
    authFetch.mockResolvedValue(reply({ checked: 12, empty: [empty('a', 'Old Dental'), empty('b', 'Test Co')] }));
    render(<ClientCleanup />);
    expect(await screen.findByTestId('checked')).toHaveTextContent('12 clients checked, 2 empty.');
    expect(screen.getAllByTestId('empty-client')).toHaveLength(2);
  });

  it('asks before archiving, archives only that client, then reloads the list', async () => {
    let archived = false;
    authFetch.mockImplementation((url: string, init?: { method?: string }) => {
      if (init?.method === 'POST') {
        archived = true;
        return Promise.resolve(reply({ removed: true, name: 'Old Dental (archived)', reason: null }));
      }
      return Promise.resolve(reply({ checked: 12, empty: archived ? [empty('b', 'Test Co')] : [empty('a', 'Old Dental'), empty('b', 'Test Co')] }));
    });
    render(<ClientCleanup />);
    await screen.findAllByTestId('empty-client');
    await userEvent.click(screen.getAllByRole('button', { name: 'Archive' })[0]);
    expect(authFetch).not.toHaveBeenCalledWith(expect.stringContaining('/archive'), expect.anything());
    await userEvent.click(screen.getByRole('button', { name: 'Archive Old Dental' }));
    await waitFor(() => expect(authFetch).toHaveBeenCalledWith('/api/v1/mssp/tenants/a/archive', { method: 'POST' }));
    await waitFor(() => expect(screen.getAllByTestId('empty-client')).toHaveLength(1));
    expect(screen.getByTestId('empty-client')).toHaveTextContent('Test Co');
  });

  it('can be cancelled without archiving', async () => {
    authFetch.mockResolvedValue(reply({ checked: 1, empty: [empty('a', 'Old Dental')] }));
    render(<ClientCleanup />);
    await userEvent.click(await screen.findByRole('button', { name: 'Archive' }));
    await userEvent.click(screen.getByRole('button', { name: 'Cancel' }));
    expect(screen.getByRole('button', { name: 'Archive' })).toBeInTheDocument();
    expect(authFetch).toHaveBeenCalledTimes(1);
  });

  it('says so when nothing is empty, and shows an error plainly', async () => {
    authFetch.mockResolvedValue(reply({ checked: 5, empty: [] }));
    const { unmount } = render(<ClientCleanup />);
    expect(await screen.findByTestId('none')).toHaveTextContent('Every client has something in it.');
    unmount();
    authFetch.mockResolvedValue(reply({}, false));
    render(<ClientCleanup />);
    expect(await screen.findByRole('alert')).toHaveTextContent('The API answered 500');
  });
});
