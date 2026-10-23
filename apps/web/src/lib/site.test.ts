import { afterEach, describe, expect, it, vi } from 'vitest';
import { DISCOVERY_KEYWORDS, getPublicSiteUrl } from './site';

afterEach(() => vi.unstubAllEnvs());

describe('getPublicSiteUrl', () => {
  it('uses the configured address without a trailing slash', () => {
    vi.stubEnv('NEXT_PUBLIC_SITE_URL', 'https://soc.example.com/');
    expect(getPublicSiteUrl()).toBe('https://soc.example.com');
    vi.stubEnv('NEXT_PUBLIC_SITE_URL', '  https://soc.example.com  ');
    expect(getPublicSiteUrl()).toBe('https://soc.example.com');
  });
  it('falls back to the local demo address when nothing (or only spaces) is set', () => {
    vi.stubEnv('NEXT_PUBLIC_SITE_URL', '');
    expect(getPublicSiteUrl()).toBe('http://localhost:3000');
    vi.stubEnv('NEXT_PUBLIC_SITE_URL', '   ');
    expect(getPublicSiteUrl()).toBe('http://localhost:3000');
  });
});

describe('DISCOVERY_KEYWORDS', () => {
  it('has real entries only: no blanks, no stray spaces, no repeats (case aside)', () => {
    expect(DISCOVERY_KEYWORDS.length).toBeGreaterThan(20);
    for (const k of DISCOVERY_KEYWORDS) {
      expect(k.trim()).toBe(k);
      expect(k.length).toBeGreaterThan(1);
    }
    const lower = DISCOVERY_KEYWORDS.map((k) => k.toLowerCase());
    const dupes = lower.filter((k, i) => lower.indexOf(k) !== i);
    expect(dupes).toEqual([]);
  });
  it('is not so long that search engines would ignore it', () => {
    expect(DISCOVERY_KEYWORDS.join(', ').length).toBeLessThan(4000);
  });
});
