import { authFetch } from './auth-session';

/** SWR fetcher for the API. Goes through authFetch: a bare fetch() carries no login token (fine in dev, a 401 in production). */
export async function safeFetcher<T = unknown>(url: string): Promise<T> {
  const r = await authFetch(url);
  if (!r.ok) {
    const body = await r.text().catch(() => '');
    throw new Error(`HTTP ${r.status} ${r.statusText} — ${body.slice(0, 120)}`);
  }
  return r.json();
}
