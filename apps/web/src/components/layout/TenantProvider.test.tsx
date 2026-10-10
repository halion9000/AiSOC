import { describe, expect, it, beforeEach, afterEach, vi } from 'vitest';
import { act, render, renderHook, screen, waitFor } from '@testing-library/react';
import { TenantProvider, useTenant } from './TenantProvider';

// `@/lib/api` is mocked end-to-end so the provider can be exercised in isolation from the real network and localStorage helpers.
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

function wrapper({ children }: { children: React.ReactNode }) {
  return <TenantProvider>{children}</TenantProvider>;
}

const originalLocation = window.location;
let reloadSpy: ReturnType<typeof vi.fn>;

beforeEach(() => {
  currentUserMock.mockReset();
  isAuthenticatedMock.mockReset();
  viewableMock.mockReset();
  getViewedTenantIdMock.mockReset();
  getViewedTenantIdMock.mockReturnValue(null);
  setActiveTenantIdMock.mockReset();
  // jsdom cannot navigate: `window.location.reload()` is intentional in the provider, so count it instead.
  reloadSpy = vi.fn();
  Object.defineProperty(window, 'location', { configurable: true, value: { ...originalLocation, reload: reloadSpy } });
});

afterEach(() => {
  Object.defineProperty(window, 'location', { configurable: true, value: originalLocation });
});

const signedIn = (tenant_id: string, role = 'analyst') => {
  currentUserMock.mockReturnValue({ id: 'u1', email: 'a@b.com', role, tenant_id });
  isAuthenticatedMock.mockReturnValue(true);
};

/** What `GET /tenants/viewable` answers: the person's own tenant first, then the rest. */
const viewable = (home: { id: string; name: string }, others: { id: string; name: string; relationship: 'granted' | 'platform'; access?: 'view' | 'full' }[] = []) =>
  viewableMock.mockResolvedValue({
    home_tenant_id: home.id,
    tenants: [{ ...home, slug: home.id, relationship: 'self' }, ...others.map((o) => ({ ...o, slug: o.id }))],
  });

const PARENT = { id: 'parent-t', name: 'MSSP Holdings' };
const CHILDREN = [
  { id: 'c1', name: 'Customer A', relationship: 'granted' as const },
  { id: 'c2', name: 'Customer B', relationship: 'granted' as const },
];

describe('TenantProvider', () => {
  it('exits loading=false when the user is not authenticated', async () => {
    currentUserMock.mockReturnValue(null);
    isAuthenticatedMock.mockReturnValue(false);

    const { result } = renderHook(() => useTenant(), { wrapper });

    await waitFor(() => expect(result.current.loading).toBe(false));
    expect(result.current.current).toBeNull();
    expect(result.current.home).toBeNull();
    expect(result.current.available).toEqual([]);
    expect(result.current.viewingOther).toBe(false);
    expect(viewableMock).not.toHaveBeenCalled();
  });

  it('loads the current tenant for a standalone user', async () => {
    signedIn('t1');
    viewable({ id: 't1', name: 'Acme Corp' });

    const { result } = renderHook(() => useTenant(), { wrapper });

    await waitFor(() => expect(result.current.loading).toBe(false));
    expect(result.current.userRole).toBe('analyst');
    expect(result.current.current).toEqual({ id: 't1', name: 'Acme Corp', relationship: 'self', access: 'full' });
    expect(result.current.home).toEqual(result.current.current);
    expect(result.current.available).toHaveLength(1);
    expect(result.current.viewingOther).toBe(false);
  });

  it('lists the own tenant first and then the tenants the person was granted, as the server says', async () => {
    signedIn('parent-t', 'mssp-admin');
    viewable(PARENT, CHILDREN);

    const { result } = renderHook(() => useTenant(), { wrapper });

    await waitFor(() => expect(result.current.loading).toBe(false));
    expect(result.current.available.map((t) => t.id)).toEqual(['parent-t', 'c1', 'c2']);
    expect(result.current.available.map((t) => t.relationship)).toEqual(['self', 'granted', 'granted']);
    expect(result.current.current?.id).toBe('parent-t');
    expect(result.current.viewingOther).toBe(false);
  });

  it("a platform admin's own tenant is 'self' and every other tenant is 'platform'", async () => {
    signedIn('pl', 'platform_admin');
    viewable({ id: 'pl', name: 'Platform' }, [{ id: 'x', name: 'Tenant X', relationship: 'platform' }]);

    const { result } = renderHook(() => useTenant(), { wrapper });

    await waitFor(() => expect(result.current.loading).toBe(false));
    expect(result.current.available.map((t) => [t.id, t.relationship])).toEqual([
      ['pl', 'self'],
      ['x', 'platform'],
    ]);
  });

  it('shows the tenant being viewed when the stored choice is one the server lists', async () => {
    signedIn('parent-t', 'mssp-admin');
    viewable(PARENT, CHILDREN);
    getViewedTenantIdMock.mockReturnValue('c2');

    const { result } = renderHook(() => useTenant(), { wrapper });

    await waitFor(() => expect(result.current.loading).toBe(false));
    expect(result.current.current?.id).toBe('c2');
    expect(result.current.current?.name).toBe('Customer B');
    expect(result.current.home?.id).toBe('parent-t');
    expect(result.current.viewingOther).toBe(true);
    expect(setActiveTenantIdMock).not.toHaveBeenCalled();
    expect(reloadSpy).not.toHaveBeenCalled();
  });

  it('nothing chosen: no choice is cleared and the page is not reloaded', async () => {
    signedIn('parent-t', 'mssp-admin');
    viewable(PARENT, CHILDREN);

    const { result } = renderHook(() => useTenant(), { wrapper });

    await waitFor(() => expect(result.current.loading).toBe(false));
    expect(setActiveTenantIdMock).not.toHaveBeenCalled();
    expect(reloadSpy).not.toHaveBeenCalled();
  });

  it('a stored choice the server does not list is cleared and the page reloads onto the own tenant', async () => {
    signedIn('parent-t', 'mssp-admin');
    viewable(PARENT, []);
    getViewedTenantIdMock.mockReturnValue('deleted-child');

    const { result } = renderHook(() => useTenant(), { wrapper });

    await waitFor(() => expect(result.current.loading).toBe(false));
    expect(setActiveTenantIdMock).toHaveBeenCalledWith(null);
    expect(reloadSpy).toHaveBeenCalledTimes(1);
    expect(result.current.current?.id).toBe('parent-t');
    expect(result.current.viewingOther).toBe(false);
  });

  it('still renders a fallback tenant when the list cannot be read', async () => {
    signedIn('t1');
    viewableMock.mockRejectedValue(new Error('boom'));

    const { result } = renderHook(() => useTenant(), { wrapper });

    await waitFor(() => expect(result.current.loading).toBe(false));
    expect(result.current.error).toBe('boom');
    expect(result.current.current).toEqual({ id: 't1', name: 'My tenant', relationship: 'self', access: 'full' });
    expect(result.current.available).toHaveLength(1);
    expect(result.current.viewingOther).toBe(false);
  });

  it('never claims "your own tenant" while a view is in force and the list cannot be read', async () => {
    signedIn('parent-t', 'mssp-admin');
    viewableMock.mockRejectedValue(new Error('403'));
    getViewedTenantIdMock.mockReturnValue('c1');

    const { result } = renderHook(() => useTenant(), { wrapper });

    await waitFor(() => expect(result.current.loading).toBe(false));
    // Requests still carry the view, so the console must say another tenant is being viewed (and offer the way back), not show the own tenant.
    expect(result.current.viewingOther).toBe(true);
    expect(result.current.current).toEqual({ id: 'c1', name: 'Another tenant', relationship: 'granted', access: null }); // named for what is known: a tenant other than their own, reached by a grant
    expect(result.current.home).toEqual({ id: 'parent-t', name: 'My tenant', relationship: 'self', access: 'full' });
    expect(result.current.available).toEqual([result.current.home]); // nothing else is offered: the list could not be read
    expect(setActiveTenantIdMock).not.toHaveBeenCalled();
  });

  it('a person with no grants has only their own tenant to switch to', async () => {
    signedIn('parent-t', 'mssp-admin');
    viewable(PARENT, []);

    const { result } = renderHook(() => useTenant(), { wrapper });

    await waitFor(() => expect(result.current.loading).toBe(false));
    expect(result.current.error).toBeNull();
    expect(result.current.available).toHaveLength(1);
    expect(result.current.available[0].relationship).toBe('self');
  });

  it('throws when useTenant() is called outside the provider', () => {
    const err = vi.spyOn(console, 'error').mockImplementation(() => {});
    expect(() => renderHook(() => useTenant())).toThrow(/useTenant\(\) must be used inside <TenantProvider>/);
    err.mockRestore();
  });

  it('setTenant() to a customer persists the choice, dispatches an event and reloads', async () => {
    signedIn('parent-t', 'mssp-admin');
    viewable(PARENT, [CHILDREN[0]]);

    const switchedEvents: CustomEvent[] = [];
    const handler = (e: Event) => switchedEvents.push(e as CustomEvent);
    window.addEventListener('aisoc:tenant-switched', handler as EventListener);

    const { result } = renderHook(() => useTenant(), { wrapper });
    await waitFor(() => expect(result.current.loading).toBe(false));

    await act(async () => {
      result.current.setTenant('c1');
    });

    expect(setActiveTenantIdMock).toHaveBeenCalledWith('c1');
    expect(reloadSpy).toHaveBeenCalledTimes(1);
    expect(switchedEvents).toHaveLength(1);
    expect((switchedEvents[0].detail as { tenantId: string }).tenantId).toBe('c1');
    expect(result.current.current?.id).toBe('c1');
    expect(result.current.viewingOther).toBe(true);

    window.removeEventListener('aisoc:tenant-switched', handler as EventListener);
  });

  it("setTenant() to the person's OWN tenant clears the view instead of storing it", async () => {
    signedIn('parent-t', 'mssp-admin');
    viewable(PARENT, [CHILDREN[0]]);
    getViewedTenantIdMock.mockReturnValue('c1');

    const { result } = renderHook(() => useTenant(), { wrapper });
    await waitFor(() => expect(result.current.loading).toBe(false));

    await act(async () => {
      result.current.setTenant('parent-t');
    });

    expect(setActiveTenantIdMock).toHaveBeenCalledWith(null);
    expect(setActiveTenantIdMock).not.toHaveBeenCalledWith('parent-t');
    expect(reloadSpy).toHaveBeenCalledTimes(1);
  });

  it('returnToHome() leaves the view and reloads', async () => {
    signedIn('parent-t', 'mssp-admin');
    viewable(PARENT, [CHILDREN[0]]);
    getViewedTenantIdMock.mockReturnValue('c1');

    const { result } = renderHook(() => useTenant(), { wrapper });
    await waitFor(() => expect(result.current.viewingOther).toBe(true));

    await act(async () => {
      result.current.returnToHome();
    });

    expect(setActiveTenantIdMock).toHaveBeenCalledWith(null);
    expect(reloadSpy).toHaveBeenCalledTimes(1);
    expect(result.current.current?.id).toBe('parent-t');
    expect(result.current.viewingOther).toBe(false);
  });
});

describe('TenantProvider integration with consumers', () => {
  it('exposes current/available/userRole to nested consumers', async () => {
    signedIn('t1', 'analyst-lead');
    viewable({ id: 't1', name: 'Acme' });

    function Probe() {
      const { current, available, userRole } = useTenant();
      return (
        <ul>
          <li data-testid="role">{userRole ?? ''}</li>
          <li data-testid="current">{current?.name ?? ''}</li>
          <li data-testid="count">{available.length}</li>
        </ul>
      );
    }

    render(
      <TenantProvider>
        <Probe />
      </TenantProvider>,
    );

    expect(screen.getByTestId('role')).toHaveTextContent('analyst-lead');
    await waitFor(() => {
      expect(screen.getByTestId('current')).toHaveTextContent('Acme');
      expect(screen.getByTestId('count')).toHaveTextContent('1');
    });
  });
});


describe('TenantProvider: what the person may do in each tenant', () => {
  it('carries the level the server states for each tenant', async () => {
    signedIn('parent-t', 'admin');
    viewable(PARENT, [
      { id: 'c1', name: 'Customer A', relationship: 'granted', access: 'full' },
      { id: 'c2', name: 'Customer B', relationship: 'granted', access: 'view' },
      { id: 'pl', name: 'Tenant P', relationship: 'platform', access: 'full' },
    ]);
    const { result } = renderHook(() => useTenant(), { wrapper });
    await waitFor(() => expect(result.current.loading).toBe(false));
    expect(result.current.available.map((t) => [t.id, t.relationship, t.access])).toEqual([
      ['parent-t', 'self', 'full'],
      ['c1', 'granted', 'full'],
      ['c2', 'granted', 'view'],
      ['pl', 'platform', 'full'],
    ]);
  });

  it('when an older API sends no level, their own tenant is full and every other tenant is read-only until the server says otherwise', async () => {
    signedIn('parent-t', 'admin');
    viewable(PARENT, CHILDREN);
    const { result } = renderHook(() => useTenant(), { wrapper });
    await waitFor(() => expect(result.current.loading).toBe(false));
    expect(result.current.available.map((t) => t.access)).toEqual(['full', 'view', 'view']);
  });

  it('the tenant being worked in carries its own level, so the banner can say working or viewing', async () => {
    signedIn('parent-t', 'admin');
    getViewedTenantIdMock.mockReturnValue('c1');
    viewable(PARENT, [
      { id: 'c1', name: 'Customer A', relationship: 'granted', access: 'full' },
      { id: 'c2', name: 'Customer B', relationship: 'granted', access: 'view' },
    ]);
    const { result } = renderHook(() => useTenant(), { wrapper });
    await waitFor(() => expect(result.current.loading).toBe(false));
    expect(result.current.viewingOther).toBe(true);
    expect(result.current.current).toMatchObject({ id: 'c1', access: 'full' });
    expect(result.current.home).toMatchObject({ id: 'parent-t', access: 'full' });
  });

  it('a level the server does not recognise is read-only, never full', async () => {
    signedIn('parent-t', 'admin');
    viewableMock.mockResolvedValue({ home_tenant_id: 'parent-t', tenants: [{ ...PARENT, slug: 'p', relationship: 'self' }, { id: 'c1', name: 'Customer A', slug: 'c1', relationship: 'granted', access: undefined }] });
    const { result } = renderHook(() => useTenant(), { wrapper });
    await waitFor(() => expect(result.current.loading).toBe(false));
    expect(result.current.available[1].access).toBe('view');
  });
});
