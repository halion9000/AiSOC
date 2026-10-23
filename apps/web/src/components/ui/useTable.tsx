'use client';

/**
 * Sorting and per-column filtering for plain tables. A column says how to read its value from a row and what kind of filter suits it:
 * ``text`` (contains), ``choice`` (one of the values present), ``min`` (at least this number). Clicking a header sorts by it, and clicking again reverses
 * (a third click clears). Empty values sort last whichever way the column runs.
 */

import { useCallback, useMemo, useState, type ReactNode } from 'react';

export type FilterKind = 'text' | 'choice' | 'min' | 'none';

export interface Column<T> {
  key: string;
  label: string;
  /** The value shown and compared. ``null`` means "nothing here". */
  value: (row: T) => string | number | null;
  /** What to sort by when it differs from what is shown (a severity ranks by how serious it is, a time by when it was). */
  sortValue?: (row: T) => string | number | null;
  filter?: FilterKind;
  /** Sort numbers and dates by their number; text compares by its letters, with digits in order. */
  align?: 'left' | 'right';
}

export interface SortState {
  key: string;
  dir: 'asc' | 'desc';
}

export function compareValues(a: string | number | null, b: string | number | null): number {
  if (a === null && b === null) return 0;
  if (a === null) return 1;
  if (b === null) return -1;
  if (typeof a === 'number' && typeof b === 'number') return a - b;
  return String(a).localeCompare(String(b), undefined, { numeric: true, sensitivity: 'base' });
}

/** Rows kept by the filters, in the order the sort asks for. Pure so it can be tested without a table. */
export function applyTable<T>(rows: T[], columns: Column<T>[], filters: Record<string, string>, sort: SortState | null): T[] {
  const byKey = new Map(columns.map((c) => [c.key, c]));
  let out = rows;
  for (const [key, wanted] of Object.entries(filters)) {
    const col = byKey.get(key);
    const text = wanted.trim();
    if (!col || text === '') continue;
    if (col.filter === 'min') {
      const min = Number(text);
      if (Number.isFinite(min)) out = out.filter((r) => {
        const v = col.value(r);
        return typeof v === 'number' && v >= min;
      });
    } else if (col.filter === 'choice') {
      out = out.filter((r) => String(col.value(r) ?? '') === text);
    } else {
      const needle = text.toLowerCase();
      out = out.filter((r) => String(col.value(r) ?? '').toLowerCase().includes(needle));
    }
  }
  const col = sort ? byKey.get(sort.key) : undefined;
  if (!sort || !col) return out;
  const sign = sort.dir === 'asc' ? 1 : -1;
  return [...out].sort((x, y) => {
    const read = col.sortValue ?? col.value;
    const a = read(x);
    const b = read(y);
    if (a === null || b === null) return compareValues(a, b);
    return sign * compareValues(a, b);
  });
}

export function useTable<T>(rows: T[], columns: Column<T>[], initialSort: SortState | null = null) {
  const [sort, setSort] = useState<SortState | null>(initialSort);
  const [filters, setFilters] = useState<Record<string, string>>({});

  const toggleSort = useCallback((key: string) => {
    setSort((s) => (s?.key !== key ? { key, dir: 'asc' } : s.dir === 'asc' ? { key, dir: 'desc' } : null));
  }, []);
  const setFilter = useCallback((key: string, value: string) => setFilters((f) => ({ ...f, [key]: value })), []);
  const clear = useCallback(() => setFilters({}), []);

  const shown = useMemo(() => applyTable(rows, columns, filters, sort), [rows, columns, filters, sort]);
  const choices = useMemo(() => {
    const out: Record<string, string[]> = {};
    for (const c of columns) {
      if (c.filter !== 'choice') continue;
      out[c.key] = [...new Set(rows.map((r) => c.value(r)).filter((v): v is string | number => v !== null).map(String))].sort(compareValues);
    }
    return out;
  }, [rows, columns]);
  const active = Object.values(filters).some((v) => v.trim() !== '');

  return { shown, sort, toggleSort, filters, setFilter, clear, choices, active };
}

/** A column header that sorts when clicked and says which way it runs. */
export function SortableTh<T>({ col, sort, onSort, className = '' }: { col: Column<T>; sort: SortState | null; onSort: (key: string) => void; className?: string }): ReactNode {
  const mine = sort?.key === col.key ? sort.dir : null;
  return (
    <th scope="col" aria-sort={mine === 'asc' ? 'ascending' : mine === 'desc' ? 'descending' : 'none'} className={`px-3 py-2 ${col.align === 'right' ? 'text-right' : ''} ${className}`}>
      <button type="button" onClick={() => onSort(col.key)} className="inline-flex items-center gap-1 uppercase hover:text-gray-300">
        {col.label}
        <span aria-hidden="true" className={mine ? 'text-blue-300' : 'text-gray-700'}>
          {mine === 'asc' ? '▲' : mine === 'desc' ? '▼' : '↕'}
        </span>
      </button>
    </th>
  );
}

/** The row of filters under the headers: a box, a menu or a minimum, whichever suits each column. */
export function FilterRow<T>({
  columns,
  filters,
  setFilter,
  choices,
}: {
  columns: Column<T>[];
  filters: Record<string, string>;
  setFilter: (key: string, value: string) => void;
  choices: Record<string, string[]>;
}): ReactNode {
  const box = 'w-full min-w-[4rem] rounded border border-gray-700 bg-gray-950 px-2 py-1 text-xs normal-case text-gray-200 placeholder:text-gray-600';
  return (
    <tr className="bg-gray-900/30">
      {columns.map((c) => (
        <th key={c.key} scope="col" className="px-3 pb-2 font-normal">
          {c.filter === 'choice' ? (
            <select aria-label={`Filter ${c.label}`} value={filters[c.key] ?? ''} onChange={(e) => setFilter(c.key, e.target.value)} className={box}>
              <option value="">All</option>
              {(choices[c.key] ?? []).map((v) => (
                <option key={v} value={v}>
                  {v}
                </option>
              ))}
            </select>
          ) : c.filter === 'min' ? (
            <input aria-label={`Minimum ${c.label}`} type="number" inputMode="decimal" placeholder="min" value={filters[c.key] ?? ''} onChange={(e) => setFilter(c.key, e.target.value)} className={box} />
          ) : c.filter === 'none' ? null : (
            <input aria-label={`Filter ${c.label}`} type="search" placeholder="contains" value={filters[c.key] ?? ''} onChange={(e) => setFilter(c.key, e.target.value)} className={box} />
          )}
        </th>
      ))}
    </tr>
  );
}
