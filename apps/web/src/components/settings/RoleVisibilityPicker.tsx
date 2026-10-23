'use client';

/**
 * The "what people in this role see" part of the role form: a tick per section and per page of the console. Ticked means shown. The role stores what is NOT ticked.
 * Hiding is about what the person sees; the permissions above are what the server enforces.
 */

import { ALWAYS_VISIBLE, sectionKey, type CatalogSection } from '@/lib/nav-visibility';

interface Props {
  catalog: CatalogSection[];
  hidden: ReadonlySet<string>;
  onChange: (next: Set<string>) => void;
}

export function RoleVisibilityPicker({ catalog, hidden, onChange }: Props) {
  const flip = (key: string, show: boolean) => {
    const next = new Set(hidden);
    if (show) next.delete(key);
    else next.add(key);
    onChange(next);
  };

  return (
    <div className="max-h-64 space-y-3 overflow-y-auto rounded-lg border border-gray-300 p-3">
      {catalog.map((section, si) => {
        const title = section.title;
        const sectionHidden = !!title && hidden.has(sectionKey(title));
        return (
          <div key={title ?? `main-${si}`}>
            {title ? (
              <label className="mb-1 flex cursor-pointer items-center gap-1.5">
                <input
                  type="checkbox"
                  aria-label={`Show the ${title} section`}
                  checked={!sectionHidden}
                  onChange={(e) => flip(sectionKey(title), e.target.checked)}
                  className="rounded border-gray-400 text-indigo-600"
                />
                <span className="text-xs font-semibold uppercase tracking-wide text-gray-600">{title}</span>
              </label>
            ) : (
              <p className="mb-1 text-xs font-semibold uppercase tracking-wide text-gray-600">Main</p>
            )}
            <div className="flex flex-wrap gap-x-4 gap-y-1 pl-6">
              {section.items.map((item) => {
                const locked = ALWAYS_VISIBLE.includes(item.href);
                const shown = locked || (!sectionHidden && !hidden.has(item.href));
                return (
                  <label key={item.href} className={`flex items-center gap-1.5 ${sectionHidden || locked ? 'opacity-60' : 'cursor-pointer'}`}>
                    <input
                      type="checkbox"
                      aria-label={`Show ${item.label}`}
                      checked={shown}
                      disabled={sectionHidden || locked}
                      onChange={(e) => flip(item.href, e.target.checked)}
                      className="rounded border-gray-400 text-indigo-600"
                    />
                    <span className="text-xs text-gray-800">{item.label}</span>
                  </label>
                );
              })}
            </div>
          </div>
        );
      })}
    </div>
  );
}
