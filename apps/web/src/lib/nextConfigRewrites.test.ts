/**
 * Saved hunt searches are served by the core API, not the agents service.
 *
 * They used to be an in-memory dict in the agents service, lost on every restart and returned to EVERY tenant. The console reaches the agents service through Next.js rewrites that bypass the API, so
 * which rule matches first decides which service answers. Rewrites are first-match-wins: if the generic `/api/v1/hunt/:path*` rule (agents) ever sits above the saved-search rules, saved searches silently
 * go back to the leaking service and nothing errors. This resolves paths against the REAL next.config.js the way Next.js does.
 */
import { createRequire } from 'node:module';

import { describe, expect, it } from 'vitest';

type Rule = { source: string; destination: string };

const API_HOST = process.env.API_URL || 'http://localhost:8000';
const AGENTS_HOST = process.env.AGENTS_URL || 'http://localhost:8001';

async function rules(): Promise<Rule[]> {
  const require = createRequire(import.meta.url);
  const config = require('../../next.config.js');
  const r = await config.rewrites();
  return Array.isArray(r) ? r : [...(r.beforeFiles ?? []), ...(r.afterFiles ?? []), ...(r.fallback ?? [])];
}

/** Next.js path-to-regexp subset used in this config: `:name*` (zero or more segments) and `:name` (one segment). */
function toRegExp(source: string): RegExp {
  const pattern = source
    .replace(/\/:[A-Za-z]+\*/g, '(?:/.*)?')
    .replace(/:[A-Za-z]+/g, '[^/]+')
    .replace(/\//g, '\\/');
  return new RegExp(`^${pattern}$`);
}

async function serviceFor(path: string): Promise<'api' | 'agents' | 'other' | 'unrouted'> {
  for (const rule of await rules()) {
    if (toRegExp(rule.source).test(path)) {
      if (rule.destination.startsWith(API_HOST)) return 'api';
      if (rule.destination.startsWith(AGENTS_HOST)) return 'agents';
      return 'other';
    }
  }
  return 'unrouted';
}

describe('which service answers /api/v1/hunt*', () => {
  it.each(['/api/v1/hunt/saved', '/api/v1/hunt/saved/3f1c2d9e-0000-0000-0000-000000000000'])('%s is served by the core API (persisted, tenant-scoped)', async (path) => {
    expect(await serviceFor(path)).toBe('api');
  });

  it('/api/v1/hunt/search is served by the core API (it searches the tenant\'s own alerts; the agents service has no event store)', async () => {
    expect(await serviceFor('/api/v1/hunt/search')).toBe('api');
  });

  it('nothing under /api/v1/hunt is sent to the agents service any more (it serves nothing there)', async () => {
    for (const path of ['/api/v1/hunt', '/api/v1/hunt/anything']) expect(await serviceFor(path)).not.toBe('agents');
    const all = await rules();
    expect(all.some((r) => r.source === '/api/v1/hunt/:path*' || r.source === '/api/v1/hunt')).toBe(false);
  });

  it('the hunt corpus (/hunts, plural) is untouched by the saved-search rules', async () => {
    expect(await serviceFor('/api/v1/hunts')).not.toBe('agents');
  });

  it('the resolver itself works: an unrelated agents route still resolves to agents', async () => {
    expect(await serviceFor('/api/v1/contextual/action')).toBe('agents');
  });
});
