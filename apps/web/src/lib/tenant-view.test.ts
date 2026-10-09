import { beforeEach, describe, expect, it, vi } from 'vitest';
import {
  ACTIVE_TENANT_KEY,
  USER_STORAGE_KEY,
  VIEW_AS_ERROR_HEADER,
  VIEW_AS_HEADER,
  getViewedTenantId,
  homeTenantId,
  isAccountLevelPath,
  setViewedTenantId,
  viewAsHeaders,
} from './tenant-view';
import { AUTH_USER_KEY } from './auth-session';

const signIn = (tenant_id: unknown) => window.localStorage.setItem(USER_STORAGE_KEY, JSON.stringify({ id: 'u1', tenant_id }));

const realStorage = Object.getOwnPropertyDescriptor(window, 'localStorage');
/** A localStorage that genuinely throws on every use (private mode, a blocked cookie policy). Spying on Storage.prototype does not reach this environment's storage. */
function breakStorage() {
  const boom = () => {
    throw new Error('storage denied');
  };
  Object.defineProperty(window, 'localStorage', { configurable: true, get: () => ({ getItem: boom, setItem: boom, removeItem: boom }) });
}

beforeEach(() => {
  if (realStorage) Object.defineProperty(window, 'localStorage', realStorage);
  window.localStorage.clear();
  vi.restoreAllMocks();
});

describe('the constants other code and the server depend on', () => {
  it('uses the storage key the switcher has always used, so a choice made before the upgrade is still honoured', () => {
    expect(ACTIVE_TENANT_KEY).toBe('aisoc.activeTenantId');
  });
  it('names the headers exactly as the API does (app/services/view_as.py)', () => {
    expect(VIEW_AS_HEADER).toBe('X-View-As-Tenant');
    expect(VIEW_AS_ERROR_HEADER).toBe('X-View-As-Error');
  });
  it('reads the cached user from the same key auth-session writes it to (this module cannot import it)', () => {
    expect(USER_STORAGE_KEY).toBe(AUTH_USER_KEY);
  });
});

describe('isAccountLevelPath: the same rule as the server', () => {
  it.each([
    '/api/v1/auth/login', '/api/v1/auth/logout', '/api/v1/auth/me', '/api/v1/auth/me/preferences', '/api/v1/auth/refresh',
    '/api/v1/push/subscribe', '/api/v1/push/test', '/api/v1/passkeys/credentials', '/api/v1/passkeys/register/begin',
    '/api/v1/tenants/viewable', '/api/v2/auth/me',
  ])('%s always acts as the signed-in person', (path) => {
    expect(isAccountLevelPath(path)).toBe(true);
  });
  it.each([
    '/api/v1/tenants/me', '/api/v1/tenants/me/users', '/api/v1/tenants/selectable', '/api/v1/alerts', '/api/v1/cases', '/api/v1/authority',
    '/api/v1/pushy', '/api/v1/passkeysx', '/api/v1/tenants/viewable/extra', '/api/v1/tenants/viewables', '/api/v1/x/auth/me', '/auth/me', '/api/v1/mssp/children',
  ])('%s does not', (path) => {
    expect(isAccountLevelPath(path)).toBe(false);
  });
});

describe('homeTenantId', () => {
  it('is the cached user\'s tenant', () => {
    signIn('t-home');
    expect(homeTenantId()).toBe('t-home');
  });
  it.each([[''], [null], [undefined], [42], [{}]])('is null when the cached tenant is %j', (value) => {
    signIn(value);
    expect(homeTenantId()).toBeNull();
  });
  it('is null when nobody is signed in or the cache is not JSON', () => {
    expect(homeTenantId()).toBeNull();
    window.localStorage.setItem(USER_STORAGE_KEY, '{not json');
    expect(homeTenantId()).toBeNull();
  });
  it('is null, without throwing, when storage cannot be read', () => {
    signIn('t-home'); // there IS a cached user: null can only come from the failure being handled
    expect(homeTenantId()).toBe('t-home');
    breakStorage();
    expect(homeTenantId()).toBeNull();
  });
});

describe('getViewedTenantId', () => {
  it('is null when nothing is chosen', () => {
    signIn('t-home');
    expect(getViewedTenantId()).toBeNull();
  });
  it('is the chosen tenant when it is not the person\'s own', () => {
    signIn('t-home');
    window.localStorage.setItem(ACTIVE_TENANT_KEY, 'c1');
    expect(getViewedTenantId()).toBe('c1');
  });
  it('is null when the choice is the person\'s OWN tenant: that is not a view', () => {
    signIn('t-home');
    window.localStorage.setItem(ACTIVE_TENANT_KEY, 't-home');
    expect(getViewedTenantId()).toBeNull();
  });
  it('is the choice when the person\'s own tenant is not known (the server treats naming one\'s own tenant as no change)', () => {
    window.localStorage.setItem(ACTIVE_TENANT_KEY, 'c1');
    expect(getViewedTenantId()).toBe('c1');
  });
  it('is null, without throwing, when storage cannot be read', () => {
    window.localStorage.setItem(ACTIVE_TENANT_KEY, 'c1');
    expect(getViewedTenantId()).toBe('c1');
    breakStorage();
    expect(getViewedTenantId()).toBeNull();
  });
});

describe('setViewedTenantId', () => {
  it('stores a tenant that is not the person\'s own', () => {
    signIn('t-home');
    setViewedTenantId('c1');
    expect(window.localStorage.getItem(ACTIVE_TENANT_KEY)).toBe('c1');
  });
  it('null goes back to the own tenant', () => {
    signIn('t-home');
    window.localStorage.setItem(ACTIVE_TENANT_KEY, 'c1');
    setViewedTenantId(null);
    expect(window.localStorage.getItem(ACTIVE_TENANT_KEY)).toBeNull();
  });
  it('choosing the person\'s own tenant clears the view instead of storing it', () => {
    signIn('t-home');
    window.localStorage.setItem(ACTIVE_TENANT_KEY, 'c1');
    setViewedTenantId('t-home');
    expect(window.localStorage.getItem(ACTIVE_TENANT_KEY)).toBeNull();
  });
  it('does not throw when storage is unavailable, for a view or for going home', () => {
    breakStorage();
    expect(() => setViewedTenantId('c1')).not.toThrow();
    expect(() => setViewedTenantId(null)).not.toThrow();
  });
});

describe('viewAsHeaders', () => {
  it('is empty when no tenant is being viewed', () => {
    signIn('t-home');
    expect(viewAsHeaders('/api/v1/alerts')).toEqual({});
  });
  it('asks for the viewed tenant on an ordinary route', () => {
    signIn('t-home');
    setViewedTenantId('c1');
    expect(viewAsHeaders('/api/v1/alerts')).toEqual({ 'X-View-As-Tenant': 'c1' });
  });
  it.each(['/api/v1/auth/me', '/api/v1/auth/logout', '/api/v1/push/subscribe', '/api/v1/passkeys/credentials', '/api/v1/tenants/viewable'])(
    'is empty on the account-level route %s even while viewing',
    (path) => {
      signIn('t-home');
      setViewedTenantId('c1');
      expect(viewAsHeaders(path)).toEqual({});
    },
  );
});
