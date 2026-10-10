import { beforeEach, describe, expect, it, vi } from 'vitest';
import { render, screen, waitFor, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { axe } from 'vitest-axe';
import { SWRConfig } from 'swr';

const tenantAccessApi = vi.hoisted(() => ({ manageable: vi.fn(), list: vi.fn(), grant: vi.fn(), revoke: vi.fn(), listAll: vi.fn(), grantAll: vi.fn(), revokeAll: vi.fn() }));
vi.mock('@/lib/api', async (original) => ({ ...(await original<typeof import('@/lib/api')>()), tenantAccessApi }));
const tenantState = vi.hoisted(() => vi.fn());
vi.mock('@/components/layout/TenantProvider', () => ({ useTenant: () => tenantState() }));
const toastSuccess = vi.hoisted(() => vi.fn());
vi.mock('react-hot-toast', () => ({ __esModule: true, default: { success: toastSuccess, error: vi.fn() } }));
vi.mock('date-fns', async () => ({ ...(await vi.importActual<typeof import('date-fns')>('date-fns')), formatDistanceToNow: () => '3 months ago' }));

import { ApiError } from '@/lib/api';
import { TenantAccessPanel, levelLabel } from './TenantAccessPanel';

const HOME = { id: 'home', name: 'Live Oak IT', slug: 'lo', relationship: 'self' as const };
const CUSTOMER = { id: 'c1', name: 'Customer A', slug: 'a', relationship: 'child' as const };
const grant = (over: Record<string, unknown>) => ({ tenant_id: 'c1', user_id: 'u1', account_name: 'tech.one', email: 'tech@msp.example', username: null, home_tenant_id: 'home', access: 'view', granted_by: 'hal@msp.example', created_at: '2026-09-01T00:00:00Z', ...over });
const allGrant = (over: Record<string, unknown>) => ({ user_id: 'u9', account_name: 'ops.all', email: null, username: null, home_tenant_id: 'home', access: 'full', granted_by: 'hal@msp.example', created_at: '2026-09-01T00:00:00Z', ...over });
const refusal = (status: number, detail: string) => new ApiError(`API ${status} - /x`, status, JSON.stringify({ detail }));

let grantsByTenant: Record<string, unknown[]>;
beforeEach(() => {
  Object.values(tenantAccessApi).forEach((f) => f.mockReset());
  toastSuccess.mockReset();
  tenantState.mockReturnValue({ viewingOther: false, home: { name: 'Live Oak IT' } });
  grantsByTenant = { home: [], c1: [grant({}), grant({ user_id: 'u2', account_name: 'tech.two', email: null, access: 'full' })] };
  tenantAccessApi.manageable.mockResolvedValue({ home_tenant_id: 'home', tenants: [HOME, CUSTOMER] });
  tenantAccessApi.list.mockImplementation(async (id: string) => grantsByTenant[id] ?? []);
  tenantAccessApi.grant.mockResolvedValue(grant({}));
  tenantAccessApi.revoke.mockResolvedValue(undefined);
  tenantAccessApi.listAll.mockResolvedValue([allGrant({})]);
  tenantAccessApi.grantAll.mockResolvedValue(allGrant({}));
  tenantAccessApi.revokeAll.mockResolvedValue(undefined);
});

function renderPanel(canGrantAll = false) {
  return render(
    <SWRConfig value={{ provider: () => new Map(), dedupingInterval: 0 }}>
      <TenantAccessPanel canGrantAll={canGrantAll} />
    </SWRConfig>,
  );
}
async function openCustomer() {
  const user = userEvent.setup();
  renderPanel();
  await user.selectOptions(await screen.findByLabelText('Tenant'), 'c1');
  await screen.findByText('tech.one');
  return user;
}

describe('TenantAccessPanel', () => {
  it('says what a level means in the words on screen', () => {
    expect([levelLabel('view'), levelLabel('full')]).toEqual(['Read-only', 'Full access']);
  });

  it('while viewing another tenant it offers nothing and asks for no data, and says how to get back', async () => {
    tenantState.mockReturnValue({ viewingOther: true, home: { name: 'Live Oak IT' } });
    renderPanel(true);
    expect(await screen.findByTestId('viewing-other-notice')).toHaveTextContent('Return to Live Oak IT');
    expect(screen.queryByRole('button', { name: 'Grant access' })).toBeNull();
    expect(tenantAccessApi.manageable).not.toHaveBeenCalled();
  });

  it('says so when the person cannot manage anyone', async () => {
    tenantAccessApi.manageable.mockResolvedValue({ home_tenant_id: 'home', tenants: [] });
    renderPanel();
    expect(await screen.findByText(/cannot manage anyone/i)).toBeInTheDocument();
  });

  it('shows a refusal to load the tenants in the API\'s own words', async () => {
    tenantAccessApi.manageable.mockRejectedValue(refusal(403, 'Not allowed for your role'));
    renderPanel();
    expect(await screen.findByRole('alert')).toHaveTextContent('Not allowed for your role');
  });

  it('with one tenant to manage there is no picker, only its name', async () => {
    tenantAccessApi.manageable.mockResolvedValue({ home_tenant_id: 'home', tenants: [HOME] });
    renderPanel();
    expect(await screen.findByText('Live Oak IT')).toBeInTheDocument();
    expect(screen.queryByLabelText('Tenant')).toBeNull();
  });

  it('offers every tenant the person may manage, their own marked, and loads the chosen one', async () => {
    const user = userEvent.setup();
    renderPanel();
    const picker = await screen.findByLabelText('Tenant');
    expect(within(picker).getAllByRole('option').map((o) => o.textContent)).toEqual(['Live Oak IT (yours)', 'Customer A']);
    await waitFor(() => expect(tenantAccessApi.list).toHaveBeenCalledWith('home'));
    await user.selectOptions(picker, 'c1');
    await waitFor(() => expect(tenantAccessApi.list).toHaveBeenCalledWith('c1'));
  });

  it('lists who has access: the person, where they belong, the level, and who granted it', async () => {
    await openCustomer();
    const [first, second] = screen.getAllByTestId('access-row');
    expect(first).toHaveTextContent('tech.one');
    expect(first).toHaveTextContent('tech@msp.example');
    expect(first).toHaveTextContent('Live Oak IT');
    expect(within(first).getByTestId('access-level')).toHaveAttribute('data-level', 'view');
    expect(first).toHaveTextContent('hal@msp.example');
    expect(within(second).getByTestId('access-level')).toHaveAttribute('data-level', 'full');
    expect(second).toHaveTextContent('Full access');
  });

  it('says so when nobody from another tenant has access', async () => {
    renderPanel();
    expect(await screen.findByText('Nobody from another tenant has access')).toBeInTheDocument();
  });

  it('granting read-only is the default and happens at once, without a prompt, then the form is cleared and the list reloads', async () => {
    const user = userEvent.setup();
    renderPanel();
    await screen.findByLabelText('Tenant');
    await user.type(screen.getByLabelText('Account name'), '  tech.new ');
    expect(screen.getByLabelText('Access level')).toHaveValue('view');
    const before = tenantAccessApi.list.mock.calls.length;
    await user.click(screen.getByRole('button', { name: 'Grant access' }));
    await waitFor(() => expect(tenantAccessApi.grant).toHaveBeenCalledWith('home', 'tech.new', 'view'));
    expect(screen.queryByRole('alertdialog')).toBeNull();
    await waitFor(() => expect(screen.getByLabelText('Account name')).toHaveValue(''));
    await waitFor(() => expect(tenantAccessApi.list.mock.calls.length).toBeGreaterThan(before));
    expect(toastSuccess).toHaveBeenCalledWith('tech.new: read-only');
  });

  it('choosing full access shows what it means, and granting asks first; cancelling grants nothing', async () => {
    const user = userEvent.setup();
    renderPanel();
    await screen.findByLabelText('Tenant');
    await user.type(screen.getByLabelText('Account name'), 'tech.new');
    await user.selectOptions(screen.getByLabelText('Access level'), 'full');
    expect(screen.getByText(/never more\. They still cannot manage users, API keys or who has access/)).toBeInTheDocument();
    await user.click(screen.getByRole('button', { name: 'Grant access' }));
    const dialog = await screen.findByRole('alertdialog');
    expect(dialog).toHaveTextContent('Give tech.new full access to Live Oak IT?');
    expect(dialog).toHaveTextContent(/recorded in this tenant's audit log/);
    await user.click(within(dialog).getByRole('button', { name: 'Cancel' }));
    expect(tenantAccessApi.grant).not.toHaveBeenCalled();
    expect(screen.queryByRole('alertdialog')).toBeNull();
  });

  it('confirming full access grants it at that level', async () => {
    const user = userEvent.setup();
    renderPanel();
    await screen.findByLabelText('Tenant');
    await user.type(screen.getByLabelText('Account name'), 'tech.new');
    await user.selectOptions(screen.getByLabelText('Access level'), 'full');
    await user.click(screen.getByRole('button', { name: 'Grant access' }));
    await user.click(within(await screen.findByRole('alertdialog')).getByRole('button', { name: 'Give full access' }));
    await waitFor(() => expect(tenantAccessApi.grant).toHaveBeenCalledWith('home', 'tech.new', 'full'));
  });

  it('an empty account name is refused on the spot and nothing is sent', async () => {
    const user = userEvent.setup();
    renderPanel();
    await screen.findByLabelText('Tenant');
    await user.click(screen.getByRole('button', { name: 'Grant access' }));
    expect(await screen.findByTestId('access-error')).toHaveTextContent('Type the account name');
    expect(tenantAccessApi.grant).not.toHaveBeenCalled();
  });

  it("shows the server's own reason when a grant is refused and keeps what was typed", async () => {
    tenantAccessApi.grant.mockRejectedValue(refusal(404, 'No account with that name'));
    const user = userEvent.setup();
    renderPanel();
    await screen.findByLabelText('Tenant');
    await user.type(screen.getByLabelText('Account name'), 'nobody');
    await user.click(screen.getByRole('button', { name: 'Grant access' }));
    expect(await screen.findByTestId('access-error')).toHaveTextContent('No account with that name');
    expect(screen.getByLabelText('Account name')).toHaveValue('nobody');
  });

  it('falls back to a plain sentence when the refusal carries no explanation', async () => {
    tenantAccessApi.grant.mockRejectedValue(new Error('network down'));
    const user = userEvent.setup();
    renderPanel();
    await screen.findByLabelText('Tenant');
    await user.type(screen.getByLabelText('Account name'), 'someone');
    await user.click(screen.getByRole('button', { name: 'Grant access' }));
    expect(await screen.findByTestId('access-error')).toHaveTextContent('The access could not be changed.');
  });

  it('revoking asks first, naming the person and the tenant; cancelling removes nothing', async () => {
    const user = await openCustomer();
    await user.click(within(screen.getAllByTestId('access-row')[0]).getByRole('button', { name: 'Revoke' }));
    const dialog = await screen.findByRole('alertdialog');
    expect(dialog).toHaveTextContent('tech.one will no longer be able to work in Customer A');
    await user.click(within(dialog).getByRole('button', { name: 'Cancel' }));
    expect(tenantAccessApi.revoke).not.toHaveBeenCalled();
  });

  it('confirming revokes in that tenant and reloads the list', async () => {
    const user = await openCustomer();
    const before = tenantAccessApi.list.mock.calls.length;
    await user.click(within(screen.getAllByTestId('access-row')[0]).getByRole('button', { name: 'Revoke' }));
    await user.click(within(await screen.findByRole('alertdialog')).getByRole('button', { name: 'Remove access' }));
    await waitFor(() => expect(tenantAccessApi.revoke).toHaveBeenCalledWith('c1', 'tech.one'));
    await waitFor(() => expect(tenantAccessApi.list.mock.calls.length).toBeGreaterThan(before));
  });

  it('lowering access to read-only happens at once; raising it to full asks first', async () => {
    const user = await openCustomer();
    await user.click(within(screen.getAllByTestId('access-row')[1]).getByRole('button', { name: 'Make read-only' }));
    await waitFor(() => expect(tenantAccessApi.grant).toHaveBeenCalledWith('c1', 'tech.two', 'view'));
    expect(screen.queryByRole('alertdialog')).toBeNull();
    tenantAccessApi.grant.mockClear();
    await user.click(within(screen.getAllByTestId('access-row')[0]).getByRole('button', { name: 'Give full access' }));
    expect(tenantAccessApi.grant).not.toHaveBeenCalled();
    await user.click(within(await screen.findByRole('alertdialog')).getByRole('button', { name: 'Give full access' }));
    await waitFor(() => expect(tenantAccessApi.grant).toHaveBeenCalledWith('c1', 'tech.one', 'full'));
  });

  it('has no accessibility violations', async () => {
    const { container } = renderPanel(true);
    await screen.findByLabelText('Tenant');
    expect(await axe(container, { rules: { 'color-contrast': { enabled: false } } })).toHaveNoViolations();
  });
});

describe('TenantAccessPanel: every tenant (platform administrators only)', () => {
  it('is not offered, and not even requested, without the capability', async () => {
    renderPanel(false);
    await screen.findByLabelText('Tenant');
    expect(screen.queryByText('Every tenant')).toBeNull();
    expect(tenantAccessApi.listAll).not.toHaveBeenCalled();
  });

  it('lists who holds every tenant, at which level', async () => {
    renderPanel(true);
    const row = await screen.findByTestId('all-access-row');
    expect(row).toHaveTextContent('ops.all');
    expect(within(row).getByTestId('access-level')).toHaveAttribute('data-level', 'full');
  });

  it('has no default level: nothing is granted until one is chosen on purpose', async () => {
    const user = userEvent.setup();
    renderPanel(true);
    await screen.findByText('Every tenant');
    expect(screen.getByLabelText('Access level for every tenant')).toHaveValue('');
    await user.type(screen.getByLabelText('Account name for every tenant'), 'tech.x');
    await user.click(screen.getByRole('button', { name: 'Grant every tenant' }));
    expect(await screen.findByTestId('all-access-error')).toHaveTextContent('Choose a level');
    expect(tenantAccessApi.grantAll).not.toHaveBeenCalled();
    expect(screen.queryByRole('alertdialog')).toBeNull();
  });

  it('always asks, even for read-only, and says it covers tenants created later', async () => {
    const user = userEvent.setup();
    renderPanel(true);
    await screen.findByText('Every tenant');
    await user.type(screen.getByLabelText('Account name for every tenant'), 'tech.x');
    await user.selectOptions(screen.getByLabelText('Access level for every tenant'), 'view');
    await user.click(screen.getByRole('button', { name: 'Grant every tenant' }));
    const dialog = await screen.findByRole('alertdialog');
    expect(dialog).toHaveTextContent('EVERY tenant, including ones created later');
    await user.click(within(dialog).getByRole('button', { name: 'Give access' }));
    await waitFor(() => expect(tenantAccessApi.grantAll).toHaveBeenCalledWith('tech.x', 'view'));
  });

  it('full access to every tenant spells out what full means before it is confirmed', async () => {
    const user = userEvent.setup();
    renderPanel(true);
    await screen.findByText('Every tenant');
    await user.type(screen.getByLabelText('Account name for every tenant'), 'tech.x');
    await user.selectOptions(screen.getByLabelText('Access level for every tenant'), 'full');
    await user.click(screen.getByRole('button', { name: 'Grant every tenant' }));
    const dialog = await screen.findByRole('alertdialog');
    expect(dialog).toHaveTextContent('Give tech.x full access to EVERY tenant');
    expect(dialog).toHaveTextContent(/never more/);
    await user.click(within(dialog).getByRole('button', { name: 'Give full access' }));
    await waitFor(() => expect(tenantAccessApi.grantAll).toHaveBeenCalledWith('tech.x', 'full'));
  });

  it('revoking every-tenant access asks first and then removes it', async () => {
    const user = userEvent.setup();
    renderPanel(true);
    await user.click(within(await screen.findByTestId('all-access-row')).getByRole('button', { name: 'Revoke' }));
    const dialog = await screen.findByRole('alertdialog');
    expect(dialog).toHaveTextContent('ops.all will no longer be able to work in EVERY tenant');
    await user.click(within(dialog).getByRole('button', { name: 'Remove access' }));
    await waitFor(() => expect(tenantAccessApi.revokeAll).toHaveBeenCalledWith('ops.all'));
  });

  it("shows the server's reason when it refuses, in that section", async () => {
    tenantAccessApi.grantAll.mockRejectedValue(refusal(403, 'Platform administrators only'));
    const user = userEvent.setup();
    renderPanel(true);
    await screen.findByText('Every tenant');
    await user.type(screen.getByLabelText('Account name for every tenant'), 'tech.x');
    await user.selectOptions(screen.getByLabelText('Access level for every tenant'), 'view');
    await user.click(screen.getByRole('button', { name: 'Grant every tenant' }));
    await user.click(within(await screen.findByRole('alertdialog')).getByRole('button', { name: 'Give access' }));
    expect(await screen.findByTestId('all-access-error')).toHaveTextContent('Platform administrators only');
  });
});
