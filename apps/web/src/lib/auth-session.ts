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

export const AUTH_TOKEN_KEY = 'aisoc.responder.accessToken';
export const AUTH_REFRESH_KEY = 'aisoc.responder.refreshToken';
export const AUTH_USER_KEY = 'aisoc.responder.user';

/** Replaceable in tests (jsdom cannot intercept window.location.assign). */
export const sessionHooks = {
  redirectToLogin(next: string): void {
    window.location.assign(`/login?next=${encodeURIComponent(next)}`);
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
  const res = await fetch(input, withBearer(init, getItem(AUTH_TOKEN_KEY)));
  if (res.status !== 401 || callerSetAuth || NO_RETRY_PATHS.includes(path) || !replayable) return res;

  const state = await sharedSessionCheck();
  if (state === 'dead') {
    endSession();
    return res;
  }
  if (state === 'refreshed') return fetch(replay, withBearer(init, getItem(AUTH_TOKEN_KEY)));
  return res; // an unrelated 401 or a network blip: leave the session alone
}
