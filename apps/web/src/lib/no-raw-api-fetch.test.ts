/**
 * Guard: browser code must call the API through authFetch (or request()), never
 * a bare fetch() to /api/*. A bare fetch carries no login token, so it works in
 * development (no login) and returns 401 in production. ~40 call sites did
 * exactly that before this guard existed.
 */
import { readdirSync, readFileSync, statSync } from 'node:fs';
import path from 'node:path';
import { describe, expect, it } from 'vitest';

// vitest runs from apps/web (see vitest.config.ts), so resolve from the cwd.
const SRC = path.resolve(process.cwd(), 'src');
// The mobile responder app has its own sign-in and token store.
const EXEMPT = [`lib${path.sep}auth-session.ts`, `lib${path.sep}responder${path.sep}`, `components${path.sep}responder${path.sep}`, `app${path.sep}(responder)${path.sep}`];
const RAW_API_FETCH = /(?<![A-Za-z_.\w])fetch\(\s*(?:[`'"]\/api\/|`\$\{[A-Za-z_]*BASE[A-Za-z_]*\}|\$\{[A-Za-z_]*BASE[A-Za-z_]*\})/;

function walk(dir: string, out: string[] = []): string[] {
  for (const name of readdirSync(dir)) {
    const full = path.join(dir, name);
    if (statSync(full).isDirectory()) walk(full, out);
    else if (/\.(ts|tsx)$/.test(name) && !/\.test\.(ts|tsx)$/.test(name)) out.push(full);
  }
  return out;
}

export function findRawApiFetches(files: { path: string; text: string }[]): string[] {
  const hits: string[] = [];
  for (const f of files) {
    const re = new RegExp(RAW_API_FETCH.source, 'g');
    for (let m = re.exec(f.text); m; m = re.exec(f.text)) {
      const line = f.text.slice(0, m.index).split('\n').length;
      const text = f.text.split('\n')[line - 1].trim();
      if (text.startsWith('//') || text.startsWith('*') || text.startsWith('/*')) continue;
      hits.push(`${f.path}:${line}  ${text.slice(0, 90)}`);
    }
  }
  return hits;
}

describe('no bare fetch() to the API', () => {
  it('every browser API call goes through authFetch', () => {
    const files = walk(SRC)
      .map((p) => ({ path: path.relative(SRC, p), text: readFileSync(p, 'utf-8') }))
      .filter((f) => !EXEMPT.some((e) => f.path.includes(e)));
    expect(files.length).toBeGreaterThan(100); // proves the scan actually found the source tree
    expect(findRawApiFetches(files), 'use authFetch() from @/lib/auth-session').toEqual([]);
  });

  it('the detector flags the patterns that caused the bug', () => {
    const bad = [
      "const r = await fetch('/api/v1/playbooks', { method: 'POST' });",
      'const r = await fetch(`/api/v1/cases/${id}`);',
      'fetch(`${API_BASE}/api/v1/auth/me`)',
      'await fetch(`${AGENTS_BASE}/api/v1/explain`, {})',
    ];
    for (const line of bad) expect(findRawApiFetches([{ path: 'x.ts', text: line }]), line).toHaveLength(1);
    // a call split across lines must be caught too
    expect(findRawApiFetches([{ path: 'x.ts', text: 'const r = await fetch(\n  `${API_BASE}/api/v1/x`,\n  {},\n);' }])).toHaveLength(1);
    const fine = ["await authFetch('/api/v1/cases')", "fetch('https://example.com/data.json')", "// fetch('/api/v1/x') in a comment", "const refetch(`/api/x`)"];
    for (const line of fine) expect(findRawApiFetches([{ path: 'x.ts', text: line }]), line).toHaveLength(0);
  });
});
