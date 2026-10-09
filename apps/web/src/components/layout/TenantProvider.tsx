'use client';

import {
  createContext,
  useCallback,
  useContext,
  useEffect,
  useMemo,
  useState,
  type ReactNode,
} from 'react';
import {
  authApi,
  getViewedTenantId,
  setActiveTenantId,
  tenantsApi,
  type AuthUser,
  type ViewableTenant,
} from '@/lib/api';

export interface TenantOption {
  /** Stable tenant UUID: what `X-View-As-Tenant` carries while this tenant is being viewed. */
  id: string;
  /** Human-readable display name. */
  name: string;
  /** What kind of tenant this is (parent / child / standalone), for the label in the switcher. */
  role: 'parent' | 'child' | 'standalone';
  /** How the signed-in person relates to it: their own, a customer of their MSSP, or any tenant (platform admin). */
  relationship: ViewableTenant['relationship'];
}

interface TenantContextValue {
  /** The tenant the console is showing: the one being viewed, else the person's own. */
  current: TenantOption | null;
  /** The signed-in person's OWN tenant. */
  home: TenantOption | null;
  /** Every tenant the person may view (incl. their own), as the server will honour it. */
  available: TenantOption[];
  /** The signed-in user's *org-level* role (analyst / responder / admin / …). */
  userRole: string | null;
  /** True while viewing a tenant other than their own: read-only, the server refuses writes. */
  viewingOther: boolean;
  /** View another tenant (or go back to your own). Reloads the page: every cache key has the old tenant's data in it. */
  setTenant: (tenantId: string) => void;
  /** Back to the person's own tenant. */
  returnToHome: () => void;
  /** True while we're loading the tenant list (e.g. on first paint). */
  loading: boolean;
  /** Last error, if any, surfaced through the TopBar role badge tooltip. */
  error: string | null;
}

const TenantContext = createContext<TenantContextValue | null>(null);

function toOption(t: ViewableTenant, hasChildren: boolean): TenantOption {
  // "MSSP parent" only for a tenant that actually has children; a platform admin's own tenant, listed beside every other tenant, is not one.
  const role: TenantOption['role'] =
    t.relationship === 'child' ? 'child' : t.relationship === 'self' && hasChildren ? 'parent' : 'standalone';
  return { id: t.id, name: t.name, role, relationship: t.relationship };
}

/**
 * Tracks the tenant the console is showing and every tenant the person may view.
 *
 * What may be viewed comes from the SERVER (`GET /tenants/viewable`, the same rule it applies to `X-View-As-Tenant`), so the switcher can only offer what will be
 * honoured. Viewing is read-only: the API refuses writes while another tenant is being viewed, and a banner says so.
 *
 * The choice is kept by `setActiveTenantId` and sent with every API call by `authFetch`. A stored choice the server no longer lists (the relationship ended, or the
 * list could not be read and it is not known to be valid) is never silently dropped or silently shown as "your own tenant": a choice that is not listed is
 * cleared and the page reloads onto the person's own tenant; if the list cannot be read at all, the console says it is viewing another tenant and offers the way back.
 */
export function TenantProvider({ children }: { children: ReactNode }) {
  const [current, setCurrent] = useState<TenantOption | null>(null);
  const [home, setHome] = useState<TenantOption | null>(null);
  const [available, setAvailable] = useState<TenantOption[]>([]);
  const [userRole, setUserRole] = useState<string | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    let cancelled = false;

    async function load() {
      // The user record is in localStorage (post-login), so `userRole` is known without waiting on the network.
      const user: AuthUser | null = authApi.currentUser();
      if (!cancelled) setUserRole(user?.role ?? null);

      // No bearer token: don't hit protected endpoints (the demo / logged-out fallback).
      if (!authApi.isAuthenticated()) {
        if (!cancelled) setLoading(false);
        return;
      }

      try {
        const viewable = await tenantsApi.viewable();
        if (cancelled) return;
        const hasChildren = viewable.tenants.some((t) => t.relationship === 'child');
        const list = viewable.tenants.map((t) => toOption(t, hasChildren));
        const homeOption = list.find((t) => t.id === viewable.home_tenant_id) ?? list[0] ?? null;

        const chosen = getViewedTenantId();
        let currentOption = homeOption;
        if (chosen) {
          const match = list.find((t) => t.id === chosen);
          if (match) {
            currentOption = match;
          } else {
            // The server does not list it: the relationship ended, or the choice is stale. Stop sending it and start over on the person's own tenant.
            setActiveTenantId(null);
            if (typeof window !== 'undefined') window.location.reload();
          }
        }

        setAvailable(list);
        setHome(homeOption);
        setCurrent(currentOption);
        setError(null);
      } catch (err) {
        if (cancelled) return;
        setError(err instanceof Error ? err.message : 'Failed to load tenant');
        // Still render something usable, and never claim "your own tenant" while a view is in force (requests would still carry it).
        const chosen = getViewedTenantId();
        if (user) {
          const own: TenantOption = { id: user.tenant_id, name: 'My tenant', role: 'standalone', relationship: 'self' };
          setHome(own);
          setAvailable([own]);
          setCurrent(
            chosen ? { id: chosen, name: 'Another tenant', role: 'child', relationship: 'child' } : own,
          );
        }
      } finally {
        if (!cancelled) setLoading(false);
      }
    }

    void load();
    return () => {
      cancelled = true;
    };
  }, []);

  const setTenant = useCallback(
    (tenantId: string) => {
      // Choosing your own tenant clears the view; anything else is a view of that tenant.
      setActiveTenantId(home && tenantId === home.id ? null : tenantId);
      setCurrent((prev) => available.find((t) => t.id === tenantId) ?? prev);
      if (typeof window !== 'undefined') {
        // A hard reload is deliberate: every SWR cache key holds the previous tenant's data, and re-keying each consumer is a separate piece of work.
        window.dispatchEvent(new CustomEvent('aisoc:tenant-switched', { detail: { tenantId } }));
        window.location.reload();
      }
    },
    [available, home],
  );

  const returnToHome = useCallback(() => {
    if (home) setTenant(home.id);
    else {
      setActiveTenantId(null);
      if (typeof window !== 'undefined') window.location.reload();
    }
  }, [home, setTenant]);

  const viewingOther = current !== null && home !== null && current.id !== home.id;

  const value = useMemo<TenantContextValue>(
    () => ({ current, home, available, userRole, viewingOther, setTenant, returnToHome, loading, error }),
    [current, home, available, userRole, viewingOther, setTenant, returnToHome, loading, error],
  );

  return <TenantContext.Provider value={value}>{children}</TenantContext.Provider>;
}

export function useTenant(): TenantContextValue {
  const ctx = useContext(TenantContext);
  if (!ctx) {
    throw new Error('useTenant() must be used inside <TenantProvider>');
  }
  return ctx;
}
