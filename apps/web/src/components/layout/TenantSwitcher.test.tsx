import { describe, expect, it, beforeEach, vi } from 'vitest';
import { render, screen, waitFor } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { TenantSwitcher, accessLabel } from './TenantSwitcher';
import { TenantProvider } from './TenantProvider';

const currentUserMock = vi.fn();
const isAuthenticatedMock = vi.fn();
const viewableMock = vi.fn();
const getViewedTenantIdMock = vi.fn((): string | null => null);
const setActiveTenantIdMock = vi.fn();

vi.mock('@/lib/api', () => ({
  authApi: {
    currentUser: () => currentUserMock(),
    isAuthenticated: () => isAuthenticatedMock(),
  },
  tenantsApi: {
    viewable: () => viewableMock(),
  },
  getViewedTenantId: () => getViewedTenantIdMock(),
  setActiveTenantId: (id: string | null) => setActiveTenantIdMock(id),
}));

beforeEach(() => {
  currentUserMock.mockReset();
  isAuthenticatedMock.mockReset();
  viewableMock.mockReset();
  getViewedTenantIdMock.mockReset();
  getViewedTenantIdMock.mockReturnValue(null);
  setActiveTenantIdMock.mockReset();
});

/** What `GET /tenants/viewable` answers: the person's own tenant first, then the rest. */
const viewable = (home: { id: string; name: string }, others: { id: string; name: string; relationship: 'granted' | 'platform'; access?: 'view' | 'full' }[] = []) =>
  viewableMock.mockResolvedValue({
    home_tenant_id: home.id,
    tenants: [{ ...home, slug: home.id, relationship: 'self' }, ...others.map((o) => ({ ...o, slug: o.id }))],
  });

function renderSwitcher() {
  return render(
    <TenantProvider>
      <TenantSwitcher />
    </TenantProvider>,
  );
}

describe('TenantSwitcher', () => {
  it('renders nothing when the user is not authenticated', async () => {
    currentUserMock.mockReturnValue(null);
    isAuthenticatedMock.mockReturnValue(false);

    const { container } = renderSwitcher();
    // First paint shows the loading pill; once loading resolves, the unauth
    // branch returns null.
    await waitFor(() => {
      expect(container.querySelector('button')).toBeNull();
    });
  });

  it('renders a read-only pill for a standalone tenant', async () => {
    currentUserMock.mockReturnValue({
      id: 'u1',
      email: 'a@b.com',
      role: 'analyst',
      tenant_id: 't1',
    });
    isAuthenticatedMock.mockReturnValue(true);
    viewable({ id: 't1', name: 'Acme Corp' });

    renderSwitcher();

    await waitFor(() => {
      expect(screen.getByText('Acme Corp')).toBeInTheDocument();
    });
    // The read-only pill has no aria-haspopup trigger.
    expect(screen.queryByRole('button', { name: /Active tenant/i })).toBeNull();
  });

  it('renders a switcher button for an MSSP parent', async () => {
    currentUserMock.mockReturnValue({
      id: 'u1',
      email: 'a@mssp.com',
      role: 'mssp-admin',
      tenant_id: 'parent-t',
    });
    isAuthenticatedMock.mockReturnValue(true);
    viewable({ id: 'parent-t', name: 'MSSP Holdings' }, [
      { id: 'c1', name: 'Customer A', relationship: 'granted' },
      { id: 'c2', name: 'Customer B', relationship: 'granted' },
    ]);

    renderSwitcher();

    const trigger = await screen.findByRole('button', { name: /Active tenant/i });
    expect(trigger).toHaveTextContent('MSSP Holdings');

    await userEvent.click(trigger);

    // Dropdown opens with all 3 tenants visible.
    const list = screen.getByRole('listbox', { name: /Tenants/i });
    const options = await screen.findAllByRole('option');
    expect(options).toHaveLength(3);
    expect(list).toHaveTextContent('MSSP Holdings');
    expect(list).toHaveTextContent('Customer A');
    expect(list).toHaveTextContent('Customer B');
  });

  it('switches tenants on click', async () => {
    currentUserMock.mockReturnValue({
      id: 'u1',
      email: 'a@mssp.com',
      role: 'mssp-admin',
      tenant_id: 'parent-t',
    });
    isAuthenticatedMock.mockReturnValue(true);
    viewable({ id: 'parent-t', name: 'MSSP Holdings' }, [{ id: 'c1', name: 'Customer A', relationship: 'granted' }]);

    // Stub out window.location.reload so the test runner doesn't bomb out.
    const reloadSpy = vi.fn();
    Object.defineProperty(window, 'location', {
      configurable: true,
      value: { ...window.location, reload: reloadSpy },
    });

    renderSwitcher();

    const trigger = await screen.findByRole('button', { name: /Active tenant/i });
    await userEvent.click(trigger);

    const customer = await screen.findByRole('option', { name: /Customer A/i });
    await userEvent.click(customer);

    expect(setActiveTenantIdMock).toHaveBeenCalledWith('c1');
    expect(reloadSpy).toHaveBeenCalledTimes(1);
  });

  it('disables the active tenant in the dropdown', async () => {
    currentUserMock.mockReturnValue({
      id: 'u1',
      email: 'a@mssp.com',
      role: 'mssp-admin',
      tenant_id: 'parent-t',
    });
    isAuthenticatedMock.mockReturnValue(true);
    viewable({ id: 'parent-t', name: 'MSSP Holdings' }, [{ id: 'c1', name: 'Customer A', relationship: 'granted' }]);

    renderSwitcher();

    const trigger = await screen.findByRole('button', { name: /Active tenant/i });
    await userEvent.click(trigger);

    const active = await screen.findByRole('option', { name: /MSSP Holdings/i });
    expect(active).toBeDisabled();
    expect(active).toHaveAttribute('aria-selected', 'true');
  });

  it('closes on Escape', async () => {
    currentUserMock.mockReturnValue({
      id: 'u1',
      email: 'a@mssp.com',
      role: 'mssp-admin',
      tenant_id: 'parent-t',
    });
    isAuthenticatedMock.mockReturnValue(true);
    viewable({ id: 'parent-t', name: 'MSSP Holdings' }, [{ id: 'c1', name: 'Customer A', relationship: 'granted' }]);

    renderSwitcher();

    const trigger = await screen.findByRole('button', { name: /Active tenant/i });
    await userEvent.click(trigger);
    expect(screen.getByRole('dialog', { name: /Switch tenant/i })).toBeInTheDocument();
    await userEvent.keyboard('{Escape}');
    expect(screen.queryByRole('dialog', { name: /Switch tenant/i })).not.toBeInTheDocument();
  });
  it('labels each entry for what it is: your own tenant, one you were granted, and a platform view', async () => {
    currentUserMock.mockReturnValue({ id: 'u1', email: 'a@mssp.com', role: 'mssp-admin', tenant_id: 'parent-t' });
    isAuthenticatedMock.mockReturnValue(true);
    viewable({ id: 'parent-t', name: 'MSSP Holdings' }, [{ id: 'c1', name: 'Customer A', relationship: 'granted' }]);
    renderSwitcher();
    await userEvent.click(await screen.findByRole('button', { name: /Active tenant/i }));
    const [own, granted] = await screen.findAllByRole('option');
    expect(own).toHaveTextContent('Your tenant');
    expect(granted).toHaveTextContent('Granted: read-only');
  });

  it('labels the other tenants a platform admin may view as a platform view, not as your own', async () => {
    currentUserMock.mockReturnValue({ id: 'u1', email: 'p@x.com', role: 'platform_admin', tenant_id: 'pl' });
    isAuthenticatedMock.mockReturnValue(true);
    viewable({ id: 'pl', name: 'Platform' }, [{ id: 'x', name: 'Tenant X', relationship: 'platform' }]);
    renderSwitcher();
    await userEvent.click(await screen.findByRole('button', { name: /Active tenant/i }));
    const options = await screen.findAllByRole('option');
    expect(options[0]).toHaveTextContent('Your tenant');
    expect(options[1]).toHaveTextContent('Platform: read-only');
  });

  it('shows the tenant being viewed as active, and offers the own tenant as a choice', async () => {
    currentUserMock.mockReturnValue({ id: 'u1', email: 'a@mssp.com', role: 'mssp-admin', tenant_id: 'parent-t' });
    isAuthenticatedMock.mockReturnValue(true);
    getViewedTenantIdMock.mockReturnValue('c1');
    viewable({ id: 'parent-t', name: 'MSSP Holdings' }, [{ id: 'c1', name: 'Customer A', relationship: 'granted' }]);
    renderSwitcher();
    const trigger = await screen.findByRole('button', { name: /Active tenant/i });
    expect(trigger).toHaveTextContent('Customer A');
    await userEvent.click(trigger);
    expect(await screen.findByRole('option', { name: /Customer A/i })).toBeDisabled();
    expect(screen.getByRole('option', { name: /MSSP Holdings/i })).toBeEnabled();
  });
});


describe('accessLabel: each entry says what the person may do there', () => {
  it.each([
    ['self', 'full', 'Your tenant'],
    ['self', 'view', 'Your tenant'],
    ['self', null, 'Your tenant'],
    ['granted', 'view', 'Granted: read-only'],
    ['granted', 'full', 'Granted: full access'],
    ['granted', null, 'Granted: access unknown'],
    ['platform', 'view', 'Platform: read-only'],
    ['platform', 'full', 'Platform: full access'],
    ['platform', null, 'Platform: access unknown'],
  ] as const)('%s / %s reads "%s"', (relationship, access, expected) => {
    expect(accessLabel({ relationship, access })).toBe(expected);
  });

  it('is shown in the list, so nobody mistakes a tenant they can change for one they can only look at', async () => {
    currentUserMock.mockReturnValue({ id: 'u1', email: 'tech@x.com', role: 'admin', tenant_id: 'home-t' });
    isAuthenticatedMock.mockReturnValue(true);
    viewable({ id: 'home-t', name: 'MSP' }, [
      { id: 'c1', name: 'Customer A', relationship: 'granted', access: 'full' },
      { id: 'c2', name: 'Customer B', relationship: 'granted', access: 'view' },
    ]);
    renderSwitcher();
    await userEvent.click(await screen.findByRole('button', { name: /Active tenant/i }));
    const [own, working, looking] = await screen.findAllByRole('option');
    expect(own).toHaveTextContent('Your tenant');
    expect(working).toHaveTextContent('Customer A');
    expect(working).toHaveTextContent('Granted: full access');
    expect(looking).toHaveTextContent('Customer B');
    expect(looking).toHaveTextContent('Granted: read-only');
  });
});
