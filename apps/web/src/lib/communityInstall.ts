import { authFetch } from '@/lib/auth-session';

export type CommunityKind = 'detections' | 'playbooks';
export type InstallOutcome = 'installed' | 'already-installed';

/** The server's own explanation of a failed response (its `detail`), or the bare status when it gave none. */
export async function failureDetail(res: Response): Promise<string> {
  try {
    const body = await res.json();
    if (body && typeof body.detail === 'string' && body.detail) return body.detail;
  } catch {
    /* not JSON: fall through to the status */
  }
  return `HTTP ${res.status}`;
}

/**
 * Install a community detection or playbook into this workspace.
 *
 * Resolves only when the server says it really is installed (or already was: a 409, which is true and harmless to show as installed). Anything else throws an Error
 * carrying the server's reason. The install buttons used to `await authFetch(...)` and mark the item installed whenever the request merely COMPLETED, so a 403,
 * a 400 or a 500 still showed "Installed".
 */
export async function installCommunityItem(kind: CommunityKind, id: string): Promise<InstallOutcome> {
  const res = await authFetch(`/api/v1/community/${kind}/${encodeURIComponent(id)}/install`, { method: 'POST' });
  if (res.status === 409) return 'already-installed';
  if (!res.ok) throw new Error(await failureDetail(res));
  return 'installed';
}
