import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { act, render, screen, waitFor } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { SWRConfig, mutate } from 'swr';

const authFetch = vi.hoisted(() => vi.fn());
vi.mock('@/lib/auth-session', () => ({ authFetch }));

import { RBACView } from './RBACView';

const json = (status: number, body: unknown) => new Response(JSON.stringify(body), { status, headers: { 'content-type': 'application/json' } });
const perm = { id: 'p1', name: 'alerts:read', description: null, category: 'alerts' };
const analyst = { id: 'r1', tenant_id: 't1', name: 'Analyst', description: 'Works alerts', is_system: false, permissions: [perm] };
const admin = { id: 'r2', tenant_id: 't1', name: 'Administrator', description: 'Everything', is_system: true, permissions: [perm] };

// The default cache on purpose (the view calls SWR's global mutate), but with no de-duplication window: SWR otherwise hands a test the response of an identical request made less than 2s earlier.
const view = () => (
  <SWRConfig value={{ dedupingInterval: 0, shouldRetryOnError: false }}>
    <RBACView />
  </SWRConfig>
);

let rolesResponse: () => Response | Promise<Response>;
let deleteResponse: () => Response | Promise<Response>;

beforeEach(async () => {
  await mutate(() => true, undefined, { revalidate: false }); // this view uses SWR's global cache: start every test empty
  authFetch.mockReset();
  rolesResponse = () => json(200, [analyst, admin]);
  deleteResponse = () => new Response(null, { status: 204 });
  authFetch.mockImplementation(async (url: string, init?: { method?: string }) => {
    if (init?.method === 'DELETE') return deleteResponse();
    if (url === '/api/v1/rbac/roles') return rolesResponse();
    if (url === '/api/v1/rbac/permissions') return json(200, [perm]);
    return json(404, {});
  });
  vi.spyOn(window, 'confirm').mockReturnValue(true);
});
afterEach(() => vi.restoreAllMocks());

// When the roles request failed the page said "RBAC API unreachable, showing demo roles so you can explore access control". No demo roles ever existed: it was a false sentence on the screen where access is managed,
// with nothing underneath. And a refused role delete (a system role, or no permission) was ignored entirely, so nothing at all told the admin it had failed.
describe('loading the roles', () => {
  it('shows the real roles, with no demo wording', async () => {
    const { container } = render(view());
    expect(await screen.findByText('Analyst')).toBeInTheDocument();
    expect(screen.getByText('Administrator')).toBeInTheDocument();
    expect(container.textContent).not.toMatch(/demo/i);
  });

  it('says it could not load them, with the reason and a Retry that works, and does not claim there are no roles', async () => {
    rolesResponse = () => json(503, {});
    const { container } = render(view());
    expect(await screen.findByText("Couldn't load roles")).toBeInTheDocument();
    expect(screen.getByText(/HTTP 503/)).toBeInTheDocument();
    expect(container.textContent).not.toMatch(/demo/i);
    expect(screen.queryByText('No roles defined yet')).not.toBeInTheDocument();

    rolesResponse = () => json(200, [analyst]);
    await userEvent.setup().click(screen.getByRole('button', { name: 'Retry' }));
    expect(await screen.findByText('Analyst')).toBeInTheDocument();
    expect(screen.queryByText("Couldn't load roles")).not.toBeInTheDocument();
  });

  it('keeps showing the last loaded roles, and says the refresh failed, when a later refresh fails', async () => {
    render(view());
    await screen.findByText('Analyst');
    rolesResponse = () => json(500, {});
    await act(async () => { await mutate('/api/v1/rbac/roles'); });
    expect(await screen.findByText(/Couldn.t refresh roles; showing what was last loaded/)).toBeInTheDocument();
    expect(screen.getByText('Analyst')).toBeInTheDocument();
    expect(screen.queryByText("Couldn't load roles")).not.toBeInTheDocument();
  });

  it('still says a workspace with no roles has none', async () => {
    rolesResponse = () => json(200, []);
    render(view());
    expect(await screen.findByText('No roles defined yet')).toBeInTheDocument();
    expect(screen.queryByText("Couldn't load roles")).not.toBeInTheDocument();
  });
});

describe('deleting a role', () => {
  it('sends the delete and shows no error when it works', async () => {
    render(view());
    await screen.findByText('Analyst');
    await userEvent.setup().click(screen.getByRole('button', { name: 'Delete' }));
    await waitFor(() => expect(authFetch).toHaveBeenCalledWith('/api/v1/rbac/roles/r1', { method: 'DELETE' }));
    expect(screen.queryByRole('alert')).not.toBeInTheDocument();
  });

  it("says why when the server refuses, using the server's own reason", async () => {
    deleteResponse = () => json(403, { detail: 'Permission denied: roles:admin' });
    render(view());
    await screen.findByText('Analyst');
    await userEvent.setup().click(screen.getByRole('button', { name: 'Delete' }));
    expect(await screen.findByRole('alert')).toHaveTextContent('Could not delete "Analyst": Permission denied: roles:admin');
  });

  it('says so when the network fails', async () => {
    deleteResponse = () => { throw new Error('network down'); };
    render(view());
    await screen.findByText('Analyst');
    await userEvent.setup().click(screen.getByRole('button', { name: 'Delete' }));
    expect(await screen.findByRole('alert')).toHaveTextContent('Could not delete "Analyst": network down');
  });

  it('does nothing when the confirmation is declined', async () => {
    vi.spyOn(window, 'confirm').mockReturnValue(false);
    render(view());
    await screen.findByText('Analyst');
    await userEvent.setup().click(screen.getByRole('button', { name: 'Delete' }));
    expect(authFetch.mock.calls.some(([, init]) => init?.method === 'DELETE')).toBe(false);
  });

  it('offers no Delete for a system role', async () => {
    rolesResponse = () => json(200, [admin]);
    render(view());
    await screen.findByText('Administrator');
    expect(screen.queryByRole('button', { name: 'Delete' })).not.toBeInTheDocument();
  });
});
