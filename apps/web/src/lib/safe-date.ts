import { format, formatDistanceToNow, type FormatDistanceToNowOptions } from 'date-fns';

type DateInput = string | number | Date | null | undefined;

/** A real Date for the input, or null. A string that does not parse (including '...+00:00Z') is null, never an Invalid Date. */
function toDate(value: DateInput): Date | null {
  if (value === null || value === undefined || value === '') return null;
  const date = value instanceof Date ? value : new Date(value);
  return Number.isNaN(date.getTime()) ? null : date;
}

/**
 * date-fns `format`, minus the crash: it throws RangeError on an Invalid Date, and an exception thrown while rendering blanks
 * the whole page. A value that is missing or unparseable renders as `fallback` instead.
 */
export function safeFormat(value: DateInput, pattern: string, fallback = '—'): string {
  const date = toDate(value);
  if (!date) return fallback;
  try {
    return format(date, pattern);
  } catch {
    return fallback;
  }
}

/** date-fns `formatDistanceToNow` with the same guarantee as {@link safeFormat}. */
export function safeDistance(value: DateInput, options: FormatDistanceToNowOptions = {}, fallback = '—'): string {
  const date = toDate(value);
  if (!date) return fallback;
  try {
    return formatDistanceToNow(date, options);
  } catch {
    return fallback;
  }
}
