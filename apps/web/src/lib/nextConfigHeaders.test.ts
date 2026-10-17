import { createRequire } from 'node:module';
import { describe, expect, it } from 'vitest';

// The console sent no hardening headers at all. Only the ones that cannot break a legitimate embed or an inline bootstrap script are set here
// (no X-Frame-Options / CSP: the HUD may frame the console, and the theme bootstrap is an inline script).
describe('next.config.js headers', () => {
  it('sets nosniff and a strict referrer policy on every route', async () => {
    const config = createRequire(import.meta.url)('../../next.config.js');
    const rules = (await config.headers()) as { source: string; headers: { key: string; value: string }[] }[];
    const all = rules.find((r) => r.source === '/:path*');
    expect(all).toBeDefined();
    const headers = Object.fromEntries(all!.headers.map((h) => [h.key.toLowerCase(), h.value]));
    expect(headers['x-content-type-options']).toBe('nosniff');
    expect(headers['referrer-policy']).toBe('strict-origin-when-cross-origin');
  });
});
