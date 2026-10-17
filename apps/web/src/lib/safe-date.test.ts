import { describe, expect, it } from 'vitest';
import { safeDistance, safeFormat } from './safe-date';

describe('safe-date', () => {
  it('formats a valid ISO date', () => {
    expect(safeFormat('2026-08-08T00:41:29Z', 'yyyy-MM-dd', 'UTC-less')).toMatch(/^2026-08-0[78]$/);
  });

  // date-fns throws RangeError("Invalid time value") on these. Rendered in a component, that blanks the whole page
  // ("This page couldn't load"): fusion once sent '2026-08-08T00:41:29+00:00Z'.
  it.each([
    ['a stacked offset', '2026-08-08T00:41:29+00:00Z'],
    ['garbage', 'not a date'],
    ['an empty string', ''],
    ['null', null],
    ['undefined', undefined],
    ['NaN', Number.NaN],
  ])('never throws for %s', (_label, value) => {
    expect(() => safeFormat(value as never, 'PPpp')).not.toThrow();
    expect(safeFormat(value as never, 'PPpp')).toBe('—');
    expect(() => safeDistance(value as never, { addSuffix: true })).not.toThrow();
    expect(safeDistance(value as never, { addSuffix: true })).toBe('—');
  });

  it('uses the caller fallback', () => {
    expect(safeFormat('nope', 'PPpp', 'unknown')).toBe('unknown');
    expect(safeDistance('nope', {}, 'unknown')).toBe('unknown');
  });

  it('describes a recent time relative to now', () => {
    const fiveMinAgo = new Date(Date.now() - 5 * 60_000).toISOString();
    expect(safeDistance(fiveMinAgo, { addSuffix: true })).toBe('5 minutes ago');
  });

  it('accepts a Date and epoch millis', () => {
    expect(safeFormat(new Date(0), 'yyyy')).toMatch(/^19(69|70)$/);
    expect(safeFormat(0, 'yyyy')).toMatch(/^19(69|70)$/);
  });
});
