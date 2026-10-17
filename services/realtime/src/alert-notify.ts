/** Which fused alerts page a responder, and a connection rate limiter that cannot grow without bound. */

export type Pushable = { severity: 'critical' | 'high'; alertId: string; title: string; body: string };

/**
 * The push notification for a fused-alert envelope, or null when none should be sent.
 *
 * Only critical and high alerts page on-call. A duplicate (the alert is already stored, so someone was already paged) and an alert that was not
 * stored (persist_outcome failed/unavailable: the deep link would open a row that does not exist) do not.
 */
export function pushableAlert(event: any): Pushable | null {
  if (String(event?.fusion_decision ?? '').toLowerCase() === 'duplicate') return null;
  const outcome = String(event?.persist_outcome ?? '').toLowerCase();
  if (outcome === 'duplicate' || outcome === 'failed' || outcome === 'unavailable') return null;
  const severity = String(event?.alert?.severity ?? event?.severity ?? '').toLowerCase();
  if (severity !== 'critical' && severity !== 'high') return null;
  const alertId = String(event?.alert?.id ?? event?.alert?.alert_id ?? event?.id ?? 'unknown');
  const title = `${severity === 'critical' ? 'P0' : 'P1'} alert · ${event?.alert?.title ?? event?.title ?? 'New alert'}`;
  const body = String(event?.alert?.summary ?? event?.summary ?? 'Tap to triage in the responder console');
  return { severity, alertId, title, body };
}

export interface RateLimiter {
  /** Count one hit for `key`; true once it has gone over the limit inside the current window. */
  exceeded(key: string): boolean;
  /** Drop every entry whose window has ended. */
  prune(): void;
  size(): number;
}

export function createRateLimiter(opts: { limit: number; windowMs: number; now?: () => number }): RateLimiter {
  const now = opts.now ?? Date.now;
  const entries = new Map<string, { count: number; resetAt: number }>();
  return {
    exceeded(key) {
      const t = now();
      let entry = entries.get(key);
      if (!entry || t > entry.resetAt) {
        entry = { count: 0, resetAt: t + opts.windowMs };
        entries.set(key, entry);
      }
      entry.count += 1;
      return entry.count > opts.limit;
    },
    prune() {
      const t = now();
      for (const [key, entry] of entries) if (t > entry.resetAt) entries.delete(key);
    },
    size: () => entries.size,
  };
}
