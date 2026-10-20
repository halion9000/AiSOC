/**
 * Filters a person picked on a list page, remembered in this browser so the page opens the way they left it. A per-viewer convenience only: storage can be empty, blocked or full (private
 * windows, cleared site data), so every read and write is guarded and the page works the same without it.
 */
const PREFIX = 'aisoc.filters.';

/** The saved filters for ``page``, or null when none were saved, they cannot be read, or they are not a plain object. */
export function loadFilters<T extends object>(page: string): Partial<T> | null {
  try {
    const raw = window.localStorage.getItem(PREFIX + page);
    if (!raw) return null;
    const parsed: unknown = JSON.parse(raw);
    return parsed && typeof parsed === 'object' && !Array.isArray(parsed) ? (parsed as Partial<T>) : null;
  } catch {
    return null;
  }
}

/** Remember ``filters`` for ``page``. A failed write is ignored. */
export function saveFilters(page: string, filters: Record<string, unknown>): void {
  try {
    window.localStorage.setItem(PREFIX + page, JSON.stringify(filters));
  } catch {
    // nothing to do: the filters simply are not remembered
  }
}

/** Forget what was saved for ``page``. */
export function clearFilters(page: string): void {
  try {
    window.localStorage.removeItem(PREFIX + page);
  } catch {
    // ignore
  }
}

/** A saved string, only when it is one of the allowed values (a vendor or client that no longer exists must not leave the page filtered by nothing). */
export function pickString(value: unknown, allowed?: readonly string[]): string {
  if (typeof value !== 'string') return '';
  return !allowed || allowed.includes(value) ? value : '';
}
