/**
 * Session handling for the web console: one place that attaches the login token
 * to API requests and reacts when it stops working.
 *
 * Why this exists. In production AiSOC requires a login (access tokens last
 * 30 minutes). The console used to attach the token in exactly one helper while
 * ~40 call sites used bare fetch() with no token at all, never used its refresh
 * token, and never sent anyone to the login page, so production would have
 * worked for half an hour at most and broken silently after that.
 *
 * Behaviour (same code path in development, where the API never returns 401):
 *  - same-origin /api/* requests get `Authorization: Bearer <token>` unless the
 *    caller set its own
 *  - on a 401, ONE shared check runs no matter how many requests failed at once:
 *    try the refresh token, then ask the API (GET /api/v1/auth/me) whether this
 *    session is really dead. We do not trust the 401 itself: some endpoints pass
 *    an upstream 401 through (e.g. a connector test with bad vendor credentials)
 *    and that must not log you out. Only a 401 from /auth/me means "log in again".
 *  - refreshed -> the original request is retried once; dead -> session cleared
 *    and the browser goes to /login?next=<where you were>; anything else (an
 *    unrelated 401, a network blip) -> the original response is returned as-is.
 */

import { getViewedTenantId, setViewedTenantId, viewAsHeaders, VIEW_AS_ERROR_HEADER, VIEW_AS_HEADER } from './tenant-view';

export const AUTH_TOKEN_KEY = 'aisoc.responder.accessToken';
export const AUTH_REFRESH_KEY = 'aisoc.responder.refreshToken';
export const AUTH_USER_KEY = 'aisoc.responder.user';

/** Replaceable in tests (jsdom cannot intercept window.location.assign). */
export const sessionHooks = {
  redirectToLogin(next: string): void {
    window.location.assign(`/login?next=${encodeURIComponent(next)}`);
  },
  reload(): void {
    window.location.reload();
  },
};

const REFRESH_PATH = '/api/v1/auth/refresh';
const ME_PATH = '/api/v1/auth/me';
const NO_RETRY_PATHS = ['/api/v1/auth/login', REFRESH_PATH];
// Pages that manage their own sign-in; never bounce these to /login.
const OWN_AUTH_PREFIXES = ['/login', '/responder'];

function store(): Storage | null {
  try {
    return typeof window === 'undefined' ? null : window.localStorage;
  } catch {
    return null;
  }
}
const getItem = (key: string): string | null => {
  try {
    return store()?.getItem(key) ?? null;
  } catch {
    return null;
  }
};
const setItem = (key: string, value: string): void => {
  try {
    store()?.setItem(key, value);
  } catch {
    /* storage unavailable */
  }
};

export function clearSession(): void {
  try {
    const s = store();
    s?.removeItem(AUTH_TOKEN_KEY);
    s?.removeItem(AUTH_REFRESH_KEY);
    s?.removeItem(AUTH_USER_KEY);
  } catch {
    /* storage unavailable */
  }
}

const LOGOUT_PATH = '/api/v1/auth/logout';

export interface ServerSignOut {
  /** True when the server revoked the session (or there was no session to revoke). False when it could not, with `message` saying why. */
  ended: boolean;
  message: string | null;
}

/**
 * Ask the server to END this session (revoke the access token and the refresh token), so that a copied or stolen token stops working. Call it BEFORE clearSession():
 * afterwards there is no token left to authorise it with.
 *
 * Signing out used to only clear this browser's copy of the tokens, so a token that had been copied stayed valid until it expired.
 *
 * Never throws and never waits longer than `timeoutMs`, so a slow or unreachable server cannot trap anyone on a signed-in screen: the caller still signs out locally,
 * and uses `ended`/`message` to say honestly that the server did not confirm. A 401 counts as ended (the token was already expired or revoked: nothing is left to end).
 * Plain fetch, not authFetch: a 401 here must not start the refresh-and-redirect machinery.
 */
export async function revokeServerSession(timeoutMs = 4000): Promise<ServerSignOut> {
  const access = getItem(AUTH_TOKEN_KEY);
  if (!access) return { ended: true, message: null };
  const refresh = getItem(AUTH_REFRESH_KEY);
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);
  try {
    const res = await fetch(LOGOUT_PATH, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${access}` },
      body: JSON.stringify(refresh ? { refresh_token: refresh } : {}),
      signal: controller.signal,
    });
    if (res.status === 401) return { ended: true, message: null };
    if (!res.ok) {
      let detail = `HTTP ${res.status}`;
      try {
        const body = await res.json();
        if (body && typeof body.detail === 'string' && body.detail) detail = body.detail;
      } catch {
        /* not JSON */
      }
      return { ended: false, message: detail };
    }
    const body = (await res.json().catch(() => null)) as { revoked?: boolean; detail?: string } | null;
    if (body && body.revoked === false) return { ended: false, message: body.detail ?? 'the server did not revoke it' };
    return { ended: true, message: null };
  } catch (err) {
    const timedOut = err instanceof DOMException && err.name === 'AbortError';
    return { ended: false, message: timedOut ? 'the server did not respond in time' : 'the server could not be reached' };
  } finally {
    clearTimeout(timer);
  }
}

function urlOf(input: RequestInfo | URL): string {
  return typeof input === 'string' ? input : input instanceof URL ? input.href : input.url;
}

/** Same-origin /api/* only: the one place a login token may be sent. */
function apiPathOf(input: RequestInfo | URL): string | null {
  try {
    const u = new URL(urlOf(input), window.location.href);
    return u.origin === window.location.origin && u.pathname.startsWith('/api/') ? u.pathname : null;
  } catch {
    return null;
  }
}

function withBearer(init: RequestInit | undefined, token: string | null): RequestInit | undefined {
  // No token (development, or not logged in): hand the call through untouched,
  // so development behaves exactly as it did before this module existed.
  if (!token) return init;
  const headers = new Headers(init?.headers);
  if (headers.has('Authorization')) return init;
  headers.set('Authorization', `Bearer ${token}`);
  return { ...init, headers };
}

/** Ask for the tenant being viewed (see tenant-view.ts), unless the caller set its own or the route is account-level. */
function withViewAs(init: RequestInit | undefined, path: string): RequestInit | undefined {
  const extra = viewAsHeaders(path);
  const value = extra[VIEW_AS_HEADER];
  if (!value) return init;
  const headers = new Headers(init?.headers);
  if (headers.has(VIEW_AS_HEADER)) return init;
  headers.set(VIEW_AS_HEADER, value);
  return { ...init, headers };
}

/**
 * The server refuses a view the person may not have (`forbidden`: the relationship ended, or the choice is stale) or cannot parse (`invalid`). A choice that
 * is refused must not keep being sent: drop it and reload onto the person's own tenant. `read_only` is NOT this: that is a write attempted while viewing,
 * which is an error for that action, not a reason to leave the view.
 */
function dropRefusedView(res: Response): void {
  const code = res.headers?.get?.(VIEW_AS_ERROR_HEADER);
  if ((code === 'forbidden' || code === 'invalid') && getViewedTenantId() !== null) {
    setViewedTenantId(null);
    sessionHooks.reload();
  }
}

type SessionState = 'refreshed' | 'valid' | 'dead' | 'unknown';
let inflight: Promise<SessionState> | null = null;

async function checkSession(): Promise<SessionState> {
  const refreshToken = getItem(AUTH_REFRESH_KEY);
  let refreshed = false;
  if (refreshToken) {
    try {
      const r = await fetch(REFRESH_PATH, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ refresh_token: refreshToken }),
      });
      if (r.ok) {
        const tokens = (await r.json()) as { access_token?: string; refresh_token?: string };
        if (tokens.access_token) {
          setItem(AUTH_TOKEN_KEY, tokens.access_token);
          if (tokens.refresh_token) setItem(AUTH_REFRESH_KEY, tokens.refresh_token);
          refreshed = true;
        }
      } else if (r.status !== 401) {
        return 'unknown'; // server trouble: do not log anyone out over it
      }
    } catch {
      return 'unknown';
    }
  }
  try {
    const token = getItem(AUTH_TOKEN_KEY);
    const me = await fetch(ME_PATH, { headers: token ? { Authorization: `Bearer ${token}` } : {} });
    if (me.status === 401) return 'dead';
    return refreshed ? 'refreshed' : 'valid';
  } catch {
    return 'unknown';
  }
}

function sharedSessionCheck(): Promise<SessionState> {
  if (!inflight) inflight = checkSession().finally(() => { inflight = null; });
  return inflight;
}

function endSession(): void {
  clearSession();
  if (typeof window === 'undefined') return;
  const here = window.location.pathname;
  if (OWN_AUTH_PREFIXES.some((p) => here === p || here.startsWith(`${p}/`))) return;
  sessionHooks.redirectToLogin(`${here}${window.location.search}`);
}

/**
 * fetch() for AiSOC API calls from the browser. Drop-in replacement: same
 * arguments, same Response. Anything that is not a same-origin /api/* request
 * (or runs on the server) goes straight to fetch().
 */
export async function authFetch(input: RequestInfo | URL, init?: RequestInit): Promise<Response> {
  if (typeof window === 'undefined') return fetch(input, init);
  const path = apiPathOf(input);
  if (path === null) return fetch(input, init);

  const callerSetAuth = new Headers(init?.headers).has('Authorization');
  const replay = input instanceof Request ? input.clone() : input;
  const replayable = !(init?.body instanceof ReadableStream);
  const res = await fetch(input, withViewAs(withBearer(init, getItem(AUTH_TOKEN_KEY)), path));
  dropRefusedView(res);
  if (res.status !== 401 || callerSetAuth || NO_RETRY_PATHS.includes(path) || !replayable) return res;

  const state = await sharedSessionCheck();
  if (state === 'dead') {
    endSession();
    return res;
  }
  if (state === 'refreshed') {
    const again = await fetch(replay, withViewAs(withBearer(init, getItem(AUTH_TOKEN_KEY)), path));
    dropRefusedView(again);
    return again;
  }
  return res; // an unrelated 401 or a network blip: leave the session alone
}
