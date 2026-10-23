import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';

let root = '';
let blog: typeof import('./blog');

const post = (fm: Record<string, unknown>, body = 'Body text.') =>
  `---\n${Object.entries(fm).map(([k, v]) => `${k}: ${JSON.stringify(v)}`).join('\n')}\n---\n${body}\n`;
const write = (name: string, text: string, dir = path.join(root, 'content', 'blog')) => {
  fs.mkdirSync(dir, { recursive: true });
  fs.writeFileSync(path.join(dir, name), text);
};
const base = { title: 'A post', author: 'Ada L., Analyst', tags: ['soc'], description: 'About a post.' };

beforeEach(async () => {
  root = fs.mkdtempSync(path.join(os.tmpdir(), 'blog-'));
  vi.resetModules();
  vi.spyOn(process, 'cwd').mockReturnValue(root);
  blog = await import('./blog');
});
afterEach(() => {
  vi.restoreAllMocks();
  fs.rmSync(root, { recursive: true, force: true });
});

describe('listPosts', () => {
  it('is empty when there is no blog folder', () => {
    expect(blog.listPosts()).toEqual([]);
    expect(blog.listPostSlugs()).toEqual([]);
  });

  it('lists posts newest first, by title when the dates match, and ignores files that are not posts', () => {
    write('old.mdx', post({ ...base, title: 'Old', date: '2026-01-01' }));
    write('new.md', post({ ...base, title: 'New', date: '2026-05-01' }));
    write('b-same.mdx', post({ ...base, title: 'Bravo', date: '2026-03-01' }));
    write('a-same.mdx', post({ ...base, title: 'Alpha', date: '2026-03-01' }));
    write('notes.txt', 'not a post');
    expect(blog.listPosts().map((p) => p.frontmatter.title)).toEqual(['New', 'Alpha', 'Bravo', 'Old']);
    expect(blog.listPostSlugs().sort()).toEqual(['a-same', 'b-same', 'new', 'old']);
  });

  it('keeps drafts out of the index unless asked, but still resolves one by its slug', () => {
    write('live.mdx', post({ ...base, date: '2026-02-01' }));
    write('wip.mdx', post({ ...base, title: 'WIP', date: '2026-03-01', draft: true }));
    expect(blog.listPosts().map((p) => p.slug)).toEqual(['live']);
    expect(blog.listPosts(true).map((p) => p.slug)).toEqual(['wip', 'live']);
    expect(blog.getPostBySlug('wip')?.frontmatter.draft).toBe(true);
  });

  it('takes the slug from the file name and carries the body, trimmed', () => {
    write('hello-world.mdx', post({ ...base, date: '2026-02-01' }, '\n\nFirst paragraph.\n\n'));
    const p = blog.listPosts()[0];
    expect(p.slug).toBe('hello-world');
    expect(p.frontmatter.slug).toBe('hello-world');
    expect(p.body).toBe('First paragraph.');
  });

  it('refuses a front-matter slug that disagrees with the file name', () => {
    write('one.mdx', post({ ...base, slug: 'two', date: '2026-02-01' }));
    expect(() => blog.listPosts()).toThrow(/does not match filename/);
  });

  it('refuses a file name that is not a safe slug (it would reach a URL)', () => {
    for (const name of ['Has Space.mdx', 'UPPER.mdx', '-lead.mdx', 'trail-.mdx', 'dots.in.name.mdx', 'quote"s.mdx']) {
      fs.rmSync(path.join(root, 'content'), { recursive: true, force: true });
      try {
        write(name, post({ ...base, date: '2026-02-01' }));
      } catch {
        continue; // the file system itself refused this name
      }
      expect(() => blog.listPosts(), name).toThrow(/Unsafe blog slug/);
    }
  });
});

describe('reading time', () => {
  it('is at least a minute and grows with length (220 words a minute)', () => {
    write('short.mdx', post({ ...base, date: '2026-02-01' }, 'Just a few words.'));
    write('long.mdx', post({ ...base, date: '2026-02-02' }, Array(1100).fill('word').join(' ')));
    expect(blog.getPostBySlug('short')?.reading_minutes).toBe(1);
    expect(blog.getPostBySlug('long')?.reading_minutes).toBe(5);
  });
});

describe('getPostBySlug', () => {
  it('finds .mdx and .md files, and returns null for one that is not there', () => {
    write('a.mdx', post({ ...base, date: '2026-02-01' }));
    write('b.md', post({ ...base, date: '2026-02-01' }));
    expect(blog.getPostBySlug('a')?.slug).toBe('a');
    expect(blog.getPostBySlug('b')?.slug).toBe('b');
    expect(blog.getPostBySlug('missing')).toBeNull();
  });

  it('never reads outside the blog folder: a slug that climbs out of it is "not found", not a crash and not the other file', () => {
    write('secret.mdx', post({ ...base, title: 'Not for the blog', date: '2026-02-01' }), path.join(root, 'content'));
    expect(blog.getPostBySlug('../secret')).toBeNull();
    expect(blog.getPostBySlug('..%2Fsecret')).toBeNull();
    expect(blog.getPostBySlug('../../content/secret')).toBeNull();
    expect(blog.getPostBySlug('')).toBeNull();
  });
});

describe('formatPostDate', () => {
  it('writes a date out in full, in UTC, so it never slips a day with the viewer\'s time zone', () => {
    expect(blog.formatPostDate('2026-05-13')).toBe('May 13, 2026');
    expect(blog.formatPostDate('2026-01-01')).toBe('January 1, 2026');
  });
  it('returns what it was given when it is not a date', () => {
    expect(blog.formatPostDate('soon')).toBe('soon');
  });
});
