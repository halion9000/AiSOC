import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { act, render, screen, waitFor, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { SWRConfig, mutate } from 'swr';

const authFetch = vi.hoisted(() => vi.fn());
vi.mock('@/lib/auth-session', () => ({ authFetch }));

import { RBACView, orderPermissions } from './RBACView';

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


describe('the permission picker', () => {
  const many = [
    { id: 'c-d', name: 'cases:delete', description: null, category: 'cases' },
    { id: 'c-w', name: 'cases:write', description: null, category: 'cases' },
    { id: 'c-k', name: 'cases:work', description: null, category: 'cases' },
    { id: 'c-r', name: 'cases:read', description: null, category: 'cases' },
    { id: 'k-w', name: 'connectors:write', description: null, category: 'connectors' },
    { id: 'k-v', name: 'connectors:view', description: null, category: 'connectors' },
    { id: 'k-r', name: 'connectors:read', description: null, category: 'connectors' },
  ];

  it('orders every category read, write, delete, then the rest by name', () => {
    expect(orderPermissions(many.filter((p) => p.category === 'cases')).map((p) => p.name)).toEqual(['cases:read', 'cases:write', 'cases:delete', 'cases:work']);
    expect(orderPermissions(many.filter((p) => p.category === 'connectors')).map((p) => p.name)).toEqual(['connectors:read', 'connectors:write', 'connectors:view']);
  });

  async function openForm() {
    authFetch.mockImplementation(async (url: string) => (url === '/api/v1/rbac/roles' ? json(200, [analyst]) : url === '/api/v1/rbac/permissions' ? json(200, many) : json(404, {})));
    render(view());
    await screen.findByText('Analyst');
    await userEvent.click(screen.getAllByRole('button', { name: /New Role/ })[0]);
    return screen.findByText('Create Role');
  }

  it('shows the permissions in that order in the form', async () => {
    await openForm();
    const names = screen.getAllByRole('checkbox').map((c) => c.closest('label')?.textContent ?? '').filter((t) => t.includes(':'));
    expect(names).toEqual(['cases:read', 'cases:write', 'cases:delete', 'cases:work', 'connectors:read', 'connectors:write', 'connectors:view']);
  });

  it('puts a tick next to each category name that selects or clears all of its permissions', async () => {
    await openForm();
    const all = screen.getByRole('checkbox', { name: 'Select all cases permissions' });
    expect(all.closest('label')).toHaveTextContent('cases');
    await userEvent.click(screen.getByRole('checkbox', { name: 'cases:read' }));
    expect((all as HTMLInputElement).indeterminate).toBe(true);
    await userEvent.click(all);
    expect(screen.getAllByRole('checkbox', { checked: true }).filter((c) => /^cases:/.test(c.closest('label')?.textContent ?? ''))).toHaveLength(4);
    expect(screen.getByText("Permissions (4 selected)")).toBeInTheDocument();
    await userEvent.click(all);
    expect(screen.getByText('Permissions (0 selected)')).toBeInTheDocument();
    expect(screen.getByRole('checkbox', { name: 'connectors:read' })).not.toBeChecked();
  });

  it('shows what you type in dark text, not the page text colour', async () => {
    await openForm();
    const dialog = screen.getByText('Create Role').closest('div')!.parentElement!;
    expect(within(dialog).getByPlaceholderText('Optional description').className).toMatch(/text-gray-900/);
    expect(within(dialog).getByPlaceholderText('e.g. threat-hunter').className).toMatch(/text-gray-900/);
  });
});

describe('hiding parts of the console from a role', () => {
  const perms = [
    { id: 'a-r', name: 'alerts:read', description: null, category: 'alerts' },
    { id: 'a-w', name: 'alerts:write', description: null, category: 'alerts' },
    { id: 'c-r', name: 'cases:read', description: null, category: 'cases' },
  ];

  function open(roles: unknown[] = [analyst]) {
    const posts: Array<{ url: string; method?: string; body: Record<string, unknown> }> = [];
    authFetch.mockImplementation(async (url: string, init?: { method?: string; body?: string }) => {
      if (init?.method === 'POST' || init?.method === 'PATCH') {
        posts.push({ url, method: init.method, body: JSON.parse(String(init.body)) });
        return json(201, { ...analyst, id: 'new' });
      }
      if (url === '/api/v1/rbac/roles') return json(200, roles);
      if (url === '/api/v1/rbac/permissions') return json(200, perms);
      return json(404, {});
    });
    return posts;
  }

  async function openForm() {
    render(view());
    await screen.findByText('Analyst');
    await userEvent.click(screen.getAllByRole('button', { name: /New Role/ })[0]);
    await screen.findByText('Create Role');
  }

  it('saves what was unticked as the role\'s hidden sections and pages', async () => {
    const posts = open();
    await openForm();
    await userEvent.type(screen.getByPlaceholderText('e.g. threat-hunter'), 'l2-tech');
    await userEvent.click(screen.getByRole('checkbox', { name: 'Show the Automation section' }));
    await userEvent.click(screen.getByRole('checkbox', { name: 'Show Client Posture' }));
    await userEvent.click(screen.getByRole('button', { name: 'Create' }));
    await waitFor(() => expect(posts).toHaveLength(1));
    expect(posts[0].body.hidden_nav).toEqual(expect.arrayContaining(['section:Automation', '/settings/client-posture']));
    expect(posts[0].body.hidden_nav as string[]).toHaveLength(2);
  });

  it('can hide one sub-page without hiding the section it is in', async () => {
    const posts = open();
    await openForm();
    await userEvent.type(screen.getByPlaceholderText('e.g. threat-hunter'), 'x');
    await userEvent.click(screen.getByRole('checkbox', { name: 'Show Client Posture' }));
    expect(screen.getByRole('checkbox', { name: 'Show the Client Security section' })).toBeChecked();
    expect(screen.getByRole('checkbox', { name: 'Show Multi-Factor' })).toBeChecked();
    await userEvent.click(screen.getByRole('button', { name: 'Create' }));
    await waitFor(() => expect(posts[0].body.hidden_nav).toEqual(['/settings/client-posture']));
  });

  it('greys out the pages of a hidden section, and offers no way to hide the roles page or the home page', async () => {
    open();
    await openForm();
    await userEvent.click(screen.getByRole('checkbox', { name: 'Show the Automation section' }));
    expect(screen.getByRole('checkbox', { name: 'Show Playbooks' })).toBeDisabled();
    expect(screen.getByRole('checkbox', { name: 'Show Dashboard' })).toBeDisabled();
    expect(screen.getByRole('checkbox', { name: 'Show Dashboard' })).toBeChecked();
    const rbac = screen.getAllByRole('checkbox').find((c) => (c as HTMLInputElement).disabled && /Roles/.test(c.getAttribute('aria-label') ?? ''));
    expect(rbac).toBeTruthy();
  });

  it('a starting point fills in the permissions and what is hidden but saves nothing until Create', async () => {
    const posts = open();
    await openForm();
    await userEvent.click(screen.getByRole('button', { name: 'Read-only analyst' }));
    expect(posts).toHaveLength(0);
    expect(screen.getByText('Permissions (2 selected)')).toBeInTheDocument();
    expect(screen.getByRole('checkbox', { name: 'alerts:write' })).not.toBeChecked();
    expect(screen.getByRole('checkbox', { name: 'Show the Automation section' })).not.toBeChecked();
    expect(screen.getByRole('checkbox', { name: 'Show the Platform section' })).not.toBeChecked();
    await userEvent.click(screen.getByRole('button', { name: 'Create' }));
    await waitFor(() => expect(posts).toHaveLength(1));
    expect(posts[0].body.name).toBe('Read-only analyst');
    expect(posts[0].body.permission_ids).toEqual(expect.arrayContaining(['a-r', 'c-r']));
  });

  it('shows what a role hides on its card, and loads it into the editor', async () => {
    open([{ ...analyst, hidden_nav: ['section:Automation', '/settings/mfa'] }]);
    render(view());
    expect(await screen.findByText('Hides: Automation, /settings/mfa')).toBeInTheDocument();
    await userEvent.click(screen.getByRole('button', { name: 'Edit' }));
    expect(await screen.findByRole('checkbox', { name: 'Show the Automation section' })).not.toBeChecked();
    expect(screen.getByRole('checkbox', { name: 'Show Multi-Factor' })).not.toBeChecked();
    expect(screen.getByRole('checkbox', { name: 'Show Client Posture' })).toBeChecked();
  });
});
