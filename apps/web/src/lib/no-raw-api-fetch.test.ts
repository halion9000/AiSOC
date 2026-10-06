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


// ---- broader rule -----------------------------------------------------------------------------------
// The first detector only recognises a literal "/api/..." or a `...BASE` constant right after `fetch(`. It
// missed 27 calls that go through a variable (`fetch(url)` in SWR fetchers), `${API}`, or `${apiBase}`. So:
// ANY bare fetch() in a file that mentions /api/v1 is a violation, unless the file is listed here on purpose.
const BARE_FETCH = /(?<![A-Za-z_.\w])fetch\(/g;
const NO_TOKEN_ON_PURPOSE: Record<string, string> = {
  [path.join('app', '(marketing)', 'waitlist', 'page.tsx')]: 'public marketing signup: the visitor is not logged in',
  [path.join('lib', 'replay.ts')]: 'public share link (/api/v1/r/{slug}) is open to anyone by design',
  [path.join('app', '(app)', 'cases', 'page.tsx')]: 'server component: there is no browser token on the server; the client view reloads with the login',
};

export function findBareFetchInApiFiles(files: { path: string; text: string }[], allow: Record<string, string> = NO_TOKEN_ON_PURPOSE): string[] {
  const hits: string[] = [];
  for (const f of files) {
    if (!f.text.includes('/api/v1') || f.path in allow) continue;
    const lines = f.text.split('\n');
    lines.forEach((line, i) => {
      const t = line.trim();
      if (t.startsWith('//') || t.startsWith('*') || t.startsWith('/*')) return;
      if (new RegExp(BARE_FETCH.source).test(line)) hits.push(`${f.path}:${i + 1}  ${t.slice(0, 90)}`);
    });
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

describe('no bare fetch() in a file that builds API URLs', () => {
  const load = () =>
    walk(SRC)
      .map((p) => ({ path: path.relative(SRC, p), text: readFileSync(p, 'utf-8') }))
      .filter((f) => !EXEMPT.some((e) => f.path.includes(e)));

  it('every console file that talks to the API uses authFetch (except the documented public/server ones)', () => {
    expect(findBareFetchInApiFiles(load()), 'use authFetch() from @/lib/auth-session').toEqual([]);
  });

  it('every exception is still needed (delete it when the file stops needing it)', () => {
    const files = load();
    for (const [rel, reason] of Object.entries(NO_TOKEN_ON_PURPOSE)) {
      const f = files.find((x) => x.path === rel);
      expect(f, `${rel} no longer exists: remove it from NO_TOKEN_ON_PURPOSE`).toBeDefined();
      expect(findBareFetchInApiFiles([f!], {}).length, `${rel} no longer has a bare fetch: remove it from NO_TOKEN_ON_PURPOSE`).toBeGreaterThan(0);
      expect(reason.length).toBeGreaterThan(10);
    }
  });

  it('flags the patterns the first detector missed', () => {
    const bad = [
      "const url = '/api/v1/x';\nconst r = await fetch(url);",
      'const API = process.env.X ?? "";\nawait fetch(`${API}/api/v1/honeytokens`, { method: "DELETE" });',
      "const apiBase = '/api/v1';\nconst res = await fetch(`${apiBase}/investigations/${id}/timeline`);",
      "useSWR('/api/v1/sla', (url) => fetch(url).then((r) => r.json()));",
    ];
    for (const text of bad) expect(findBareFetchInApiFiles([{ path: 'x.tsx', text }], {}), text).toHaveLength(1);
  });

  it('leaves alone what is fine', () => {
    const fine = [
      "const url = '/api/v1/x';\nconst r = await authFetch(url);",                         // the right call
      "// fetch(url) was the old way\nconst r = await authFetch('/api/v1/x');",             // a comment
      " * call fetch() directly for streams, see /api/v1/foo",                               // a doc comment
      "const r = await fetch('https://example.com/data.json');",                            // no API involved
      "const refetch(`/x`)",                                                                 // not fetch(
    ];
    for (const text of fine) expect(findBareFetchInApiFiles([{ path: 'x.tsx', text }], {}), text).toHaveLength(0);
  });

  it('an exception applies to that exact file only', () => {
    const text = "const u = '/api/v1/x';\nawait fetch(u);";
    expect(findBareFetchInApiFiles([{ path: 'a.tsx', text }], { 'a.tsx': 'because' })).toHaveLength(0);
    expect(findBareFetchInApiFiles([{ path: 'b.tsx', text }], { 'a.tsx': 'because' })).toHaveLength(1);
  });
});
