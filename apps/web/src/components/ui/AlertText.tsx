'use client';

import { Fragment } from 'react';
import { parseAlertText, type TextBlock } from '@/lib/alert-text';
import type { Inline } from '@/lib/guide-markdown';

function Inlines({ parts }: { parts: Inline[] }) {
  return (
    <>
      {parts.map((p, i) =>
        p.kind === 'b' ? (
          <strong key={i} className="font-semibold text-slate-200">
            {p.text}
          </strong>
        ) : p.kind === 'i' ? (
          <em key={i}>{p.text}</em>
        ) : p.kind === 'code' ? (
          <code key={i} className="rounded bg-slate-800/70 px-1 font-mono text-[0.92em] text-slate-200">
            {p.text}
          </code>
        ) : (
          <Fragment key={i}>{p.text}</Fragment>
        ),
      )}
    </>
  );
}

function Block({ block }: { block: TextBlock }) {
  switch (block.type) {
    case 'heading':
      return <h3 className="pt-1 text-[11px] font-semibold uppercase tracking-wide text-slate-500">{block.text}</h3>;
    case 'rule':
      return <hr className="border-slate-800" />;
    case 'list':
      return (
        <ul className="list-disc space-y-1 pl-5">
          {block.items.map((it, i) => (
            <li key={i}>
              <Inlines parts={it} />
            </li>
          ))}
        </ul>
      );
    case 'facts':
      return (
        <dl className="grid grid-cols-[minmax(7rem,max-content)_1fr] gap-x-4 gap-y-1 rounded-md border border-slate-800/80 bg-slate-900/40 px-3 py-2">
          {block.rows.map(([k, v], i) => (
            <Fragment key={i}>
              <dt className="text-slate-500">{k}</dt>
              <dd className="break-words text-slate-200">
                <Inlines parts={v} />
              </dd>
            </Fragment>
          ))}
        </dl>
      );
    default:
      return (
        <p className="leading-relaxed">
          <Inlines parts={block.text} />
        </p>
      );
  }
}

/** A vendor's alert or case text laid out as headings, paragraphs, lists and label/value tables instead of one run-on paragraph. */
export function AlertText({ text, className = '' }: { text: string; className?: string }) {
  const blocks = parseAlertText(text);
  return (
    <div className={`space-y-3 text-sm text-slate-400 ${className}`} data-testid="alert-text">
      {blocks.map((b, i) => (
        <Block key={i} block={b} />
      ))}
    </div>
  );
}
