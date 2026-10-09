/**
 * Which tenant the console is VIEWING, and the header that asks the API for it.
 *
 * The switcher used to store the chosen tenant and send it as `X-Tenant-Id`, which the API never read: an MSSP operator who "switched" to a customer kept
 * seeing their own data under the customer's name. The API now honours `X-View-As-Tenant`, read-only, for a tenant the signed-in person may view (see
 * docs/security/viewing-another-tenant.md). This module owns the console's side of that, with NO imports so that both `auth-session` (which sends the header
 * on every API call) and `api` can use it without a cycle.
 *
 * The header is sent only while the chosen tenant is DIFFERENT from the person's own, and never on account-level routes, which the server answers as the
 * person whatever is requested (sign-in and out, push, passkeys, and the tenant list itself).
 */

/** localStorage key of the chosen tenant. Unchanged from when it fed `X-Tenant-Id`, so a choice made before the upgrade is still honoured. */
export const ACTIVE_TENANT_KEY = 'aisoc.activeTenantId';
export const VIEW_AS_HEADER = 'X-View-As-Tenant';
/** On a refusal: invalid | forbidden | read_only | session_only. */
export const VIEW_AS_ERROR_HEADER = 'X-View-As-Error';
/** The cached signed-in user. The same key as AUTH_USER_KEY in auth-session (a test pins that they agree: this module must not import it). */
export const USER_STORAGE_KEY = 'aisoc.responder.user';

// The same rule as the server (app/services/view_as.py ACCOUNT_LEVEL_PATH).
const ACCOUNT_LEVEL_PATH = /^\/api\/v\d+\/(auth|push|passkeys)(\/|$)|^\/api\/v\d+\/tenants\/viewable$/;

export function isAccountLevelPath(path: string): boolean {
  return ACCOUNT_LEVEL_PATH.test(path);
}

function store(): Storage | null {
  try {
    return typeof window === 'undefined' ? null : window.localStorage;
  } catch {
    return null;
  }
}

/** The tenant the signed-in person belongs to, from the cached user; null when nobody is signed in or the cache is unreadable. */
export function homeTenantId(): string | null {
  try {
    const raw = store()?.getItem(USER_STORAGE_KEY);
    if (!raw) return null;
    const id = (JSON.parse(raw) as { tenant_id?: unknown }).tenant_id;
    return typeof id === 'string' && id ? id : null;
  } catch {
    return null;
  }
}

/** The tenant being viewed, or null when the person is on their own tenant (nothing chosen, or the choice is their own). */
export function getViewedTenantId(): string | null {
  try {
    const chosen = store()?.getItem(ACTIVE_TENANT_KEY);
    if (!chosen) return null;
    return chosen === homeTenantId() ? null : chosen;
  } catch {
    return null;
  }
}

/** Choose a tenant to view; null (or the person's own tenant) goes back to their own. */
export function setViewedTenantId(tenantId: string | null): void {
  try {
    const s = store();
    if (!s) return;
    if (tenantId && tenantId !== homeTenantId()) s.setItem(ACTIVE_TENANT_KEY, tenantId);
    else s.removeItem(ACTIVE_TENANT_KEY);
  } catch {
    /* storage unavailable (private mode): the choice lives only for this page, i.e. not at all */
  }
}

/** The header to add to a request for `path` (a same-origin /api path): empty unless a tenant is being viewed and the route is not account-level. */
export function viewAsHeaders(path: string): Record<string, string> {
  if (isAccountLevelPath(path)) return {};
  const viewed = getViewedTenantId();
  return viewed ? { [VIEW_AS_HEADER]: viewed } : {};
}
