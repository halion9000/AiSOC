/**
 * Service-to-service authentication for the realtime service's internal routes.
 *
 * `/internal/push`, `/internal/agent-event` and the push mutation routes (`/v1/push/subscribe|unsubscribe|test`) are called by other
 * services (agents; the API's push gateway on behalf of a logged-in user), never by a browser. The old check let EVERYONE in whenever
 * INTERNAL_TOKEN was unset, compared with `!==` (not constant time), and was never applied to the push routes at all, so anyone who
 * could reach the service could subscribe their own endpoint under any tenant and receive that tenant's push notifications, or push
 * notifications and agent events to every user of a tenant.
 *
 * Now: a configured token is required on every one of those routes, compared in constant time. There is no development mode: with no
 * token configured every one of them answers 503, and CORE generates the token on every build, so a properly set up stack always has one.
 *
 * Two header names are accepted because two callers use different ones: agents send `x-internal-token`, the API sends
 * `X-AiSOC-Internal-Token`.
 */
import crypto from 'crypto';
import type { NextFunction, Request, RequestHandler, Response } from 'express';

export type InternalAuthResult = 'ok' | 'unauthorized' | 'unconfigured';

const HEADER_NAMES = ['x-aisoc-internal-token', 'x-internal-token'] as const;

export function presentedInternalToken(headers: Request['headers']): string {
  for (const name of HEADER_NAMES) {
    const value = headers[name];
    const first = Array.isArray(value) ? value[0] : value;
    if (typeof first === 'string' && first.length > 0) return first;
  }
  return '';
}

function digest(value: string): Buffer {
  // Hash both sides so the comparison is constant-time AND tolerates different lengths (timingSafeEqual throws on unequal lengths).
  return crypto.createHash('sha256').update(value).digest();
}

export function checkInternalToken(configured: string, presented: string): InternalAuthResult {
  const expected = (configured || '').trim();
  if (!expected) return 'unconfigured';
  if (!presented) return 'unauthorized';
  return crypto.timingSafeEqual(digest(presented), digest(expected)) ? 'ok' : 'unauthorized';
}

export interface InternalAuthOptions {
  token?: () => string;
}

export function internalAuth(options: InternalAuthOptions = {}): RequestHandler {
  const token = options.token ?? (() => process.env.INTERNAL_TOKEN || '');
  return (req: Request, res: Response, next: NextFunction): void => {
    const result = checkInternalToken(token(), presentedInternalToken(req.headers));
    if (result === 'ok') {
      next();
      return;
    }
    if (result === 'unconfigured') {
      res.status(503).json({ error: 'internal auth is not configured' });
      return;
    }
    res.status(401).json({ error: 'unauthorized' });
  };
}
