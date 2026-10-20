'use client';

/**
 * The user guide as a page: a contents list that follows you down the page, a search box that narrows the sections, cards for each section, and a Print button. The text is
 * src/content/user-guide.ts, read by src/lib/guide-markdown.ts into plain elements (nothing is injected as HTML).
 */
import { useEffect, useMemo, useState } from 'react';
import { USER_GUIDE } from '@/content/user-guide';
import { parseGuide, parseInline, searchSections, type Block, type GuideSection } from '@/lib/guide-markdown';

function Inline({ text }: { text: string }) {
  return (
    <>
      {parseInline(text).map((p, i) => {
        switch (p.kind) {
          case 'b':
            return (
              <strong key={i} className="font-semibold text-fg-primary">
                {p.text}
              </strong>
            );
          case 'i':
            return (
              <em key={i} className="italic">
                {p.text}
              </em>
            );
          case 'code':
            return (
              <code key={i} className="rounded bg-surface-hover px-1.5 py-0.5 font-mono text-[0.85em] text-fg-primary">
                {p.text}
              </code>
            );
          case 'new':
            return (
              <span key={i} className="mx-0.5 inline-block rounded-full border border-emerald-500/40 bg-emerald-500/10 px-1.5 text-[0.7em] font-semibold uppercase tracking-wide text-emerald-400 align-middle">
                {p.text}
              </span>
            );
          default:
            return <span key={i}>{p.text}</span>;
        }
      })}
    </>
  );
}

function BlockView({ b }: { b: Block }) {
  switch (b.type) {
    case 'h3':
      return <h3 className="mt-5 text-sm font-semibold uppercase tracking-wide text-fg-secondary">{b.text}</h3>;
    case 'p':
      return (
        <p className="leading-relaxed text-fg-secondary">
          <Inline text={b.text} />
        </p>
      );
    case 'ul':
      return (
        <ul className="space-y-1.5 pl-1">
          {b.items.map((t, i) => (
            <li key={i} className="flex gap-2 leading-relaxed text-fg-secondary">
              <span aria-hidden className="mt-2 h-1.5 w-1.5 shrink-0 rounded-full bg-brand-500/70" />
              <span>
                <Inline text={t} />
              </span>
            </li>
          ))}
        </ul>
      );
    case 'ol':
      return (
        <ol className="space-y-2">
          {b.items.map((t, i) => (
            <li key={i} className="flex gap-3 leading-relaxed text-fg-secondary">
              <span aria-hidden className="mt-0.5 flex h-5 w-5 shrink-0 items-center justify-center rounded-full bg-brand-500/15 text-xs font-semibold text-brand-400">
                {i + 1}
              </span>
              <span>
                <Inline text={t} />
              </span>
            </li>
          ))}
        </ol>
      );
    case 'table':
      return (
        <div className="overflow-x-auto rounded-lg border border-surface-border">
          <table className="w-full text-left text-sm">
            <thead className="bg-surface-hover/60 text-xs uppercase tracking-wide text-fg-subtle">
              <tr>
                {b.head.map((h, i) => (
                  <th key={i} className="px-3 py-2 font-medium">
                    <Inline text={h} />
                  </th>
                ))}
              </tr>
            </thead>
            <tbody>
              {b.rows.map((r, ri) => (
                <tr key={ri} className="border-t border-surface-border align-top">
                  {r.map((c, ci) => (
                    <td key={ci} className="px-3 py-2 text-fg-secondary">
                      <Inline text={c} />
                    </td>
                  ))}
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      );
    default:
      return <hr className="border-surface-border" />;
  }
}

function SectionCard({ s }: { s: GuideSection }) {
  const number = /^(\d+)\./.exec(s.title)?.[1];
  const title = s.title.replace(/^\d+\.\s*/, '');
  return (
    <section id={s.id} aria-labelledby={`${s.id}-title`} className="scroll-mt-24 rounded-xl border border-surface-border bg-surface-card/60 p-5 print:break-inside-avoid print:border-0">
      <h2 id={`${s.id}-title`} className="mb-3 flex items-center gap-3 text-lg font-semibold text-fg-primary">
        {number && (
          <span aria-hidden className="flex h-7 w-7 shrink-0 items-center justify-center rounded-lg bg-brand-500/15 text-sm text-brand-400">
            {number}
          </span>
        )}
        {title}
      </h2>
      <div className="space-y-3 text-sm">
        {s.blocks.map((b, i) => (
          <BlockView key={i} b={b} />
        ))}
      </div>
    </section>
  );
}

export function GuideView() {
  const guide = useMemo(() => parseGuide(USER_GUIDE), []);
  const [query, setQuery] = useState('');
  const [active, setActive] = useState<string | null>(null);
  const shown = useMemo(() => searchSections(guide.sections, query), [guide, query]);

  // Highlight the contents entry for the section being read. Skipped where the browser has no IntersectionObserver.
  useEffect(() => {
    if (typeof IntersectionObserver === 'undefined') return;
    const observer = new IntersectionObserver(
      (entries) => {
        const visible = entries.filter((e) => e.isIntersecting).sort((a, b) => a.boundingClientRect.top - b.boundingClientRect.top)[0];
        if (visible) setActive(visible.target.id);
      },
      { rootMargin: '-80px 0px -65% 0px' },
    );
    for (const s of shown) {
      const el = document.getElementById(s.id);
      if (el) observer.observe(el);
    }
    return () => observer.disconnect();
  }, [shown]);

  const [lead, ...notes] = guide.intro;

  return (
    <div className="mx-auto max-w-6xl p-6">
      <header className="mb-6 rounded-2xl border border-surface-border bg-gradient-to-br from-brand-500/10 via-surface-card/60 to-surface-card/60 p-6">
        <div className="flex flex-wrap items-start justify-between gap-4">
          <div>
            <p className="text-xs font-semibold uppercase tracking-widest text-brand-400">User guide</p>
            <h1 className="mt-1 text-2xl font-bold text-fg-primary">{guide.title}</h1>
            {lead && lead.type === 'p' && (
              <p className="mt-2 max-w-2xl text-sm leading-relaxed text-fg-secondary">
                <Inline text={lead.text} />
              </p>
            )}
          </div>
          <button type="button" onClick={() => window.print()} className="rounded-lg border border-surface-border px-3 py-1.5 text-sm text-fg-secondary hover:bg-surface-hover print:hidden">
            Print
          </button>
        </div>
        {notes.map((n, i) =>
          n.type === 'p' ? (
            <p key={i} className="mt-4 rounded-lg border border-emerald-500/30 bg-emerald-500/5 p-3 text-sm leading-relaxed text-fg-secondary" data-testid="guide-note">
              <Inline text={n.text} />
            </p>
          ) : null,
        )}
        <label className="mt-4 block print:hidden">
          <span className="sr-only">Search the guide</span>
          <input
            type="search"
            value={query}
            onChange={(e) => setQuery(e.target.value)}
            placeholder="Search the guide, for example “hide”, “MFA” or “ticket”"
            className="w-full rounded-lg border border-surface-border bg-surface-card px-3 py-2 text-sm text-fg-primary placeholder:text-fg-subtle focus:border-brand-500/60 focus:outline-none focus:ring-2 focus:ring-brand-500/30"
          />
        </label>
      </header>

      <div className="grid gap-6 lg:grid-cols-[15rem_1fr]">
        <nav aria-label="Guide contents" className="hidden lg:block print:hidden">
          <ul className="sticky top-24 space-y-0.5 text-sm">
            {shown.map((s) => {
              const on = active === s.id;
              return (
                <li key={s.id}>
                  <a
                    href={`#${s.id}`}
                    aria-current={on ? 'true' : undefined}
                    className={`block rounded-md px-3 py-1.5 transition-colors ${on ? 'bg-brand-500/15 text-brand-400' : 'text-fg-muted hover:bg-surface-hover hover:text-fg-primary'}`}
                  >
                    {s.title}
                  </a>
                </li>
              );
            })}
          </ul>
        </nav>

        <div className="space-y-4">
          {shown.length === 0 ? (
            <p data-testid="guide-none" className="rounded-xl border border-surface-border p-6 text-sm text-fg-muted">
              Nothing in the guide mentions &ldquo;{query}&rdquo;. Try fewer or different words, or ask Cipher.
            </p>
          ) : (
            shown.map((s) => <SectionCard key={s.id} s={s} />)
          )}
        </div>
      </div>
    </div>
  );
}
