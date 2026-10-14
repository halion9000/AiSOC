'use client';

/**
 * What the source said about the alert, in the investigation rail.
 *
 * For a Huntress incident this is the SOC's own write-up; for Petra, who and what was hit. It was only on the full detail page, so the rail showed a title and nothing to
 * read. Long write-ups start collapsed (the rail is narrow) with a Show more control. Renders nothing for an alert with no description.
 */

import { useState } from 'react';

/** Characters shown before the rest is folded away. */
export const DESCRIPTION_PREVIEW_CHARS = 600;

export function AlertDescriptionSection({ description }: { description: string | null | undefined }) {
  const [open, setOpen] = useState(false);
  const text = (description ?? '').trim();
  if (!text) return null;
  const long = text.length > DESCRIPTION_PREVIEW_CHARS;
  const shown = long && !open ? `${text.slice(0, DESCRIPTION_PREVIEW_CHARS).trimEnd()}…` : text;
  return (
    <section className="px-4 py-4 border-b border-gray-800/40" aria-label="Details from the source">
      <h3 className="text-[11px] uppercase tracking-wider text-gray-500 font-semibold mb-2">Details</h3>
      <p className="text-xs text-gray-300 leading-relaxed whitespace-pre-wrap break-words">{shown}</p>
      {long && (
        <button type="button" onClick={() => setOpen((v) => !v)} className="mt-2 text-xs text-blue-300 hover:text-blue-200">
          {open ? 'Show less' : 'Show more'}
        </button>
      )}
    </section>
  );
}
