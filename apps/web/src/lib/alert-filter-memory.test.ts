import { describe, expect, it } from 'vitest';
import { rememberable, restoreFilters } from './alert-filter-memory';

const base = { page: 3, pageSize: 25, status: 'open' };

describe('rememberable', () => {
  it('keeps severity, status, source, client and ticket, and never search, device or page', () => {
    expect(rememberable({ ...base, severity: 'high', source: 'huntress', clientId: 'c1', ticket: 'none', search: 'x', device: 'PC-1' })).toEqual({
      severity: 'high',
      status: 'open',
      source: 'huntress',
      clientId: 'c1',
      ticket: 'none',
    });
  });

  it('writes "all" for no status, so All survives being saved', () => {
    expect(rememberable({ page: 1, pageSize: 25 }).status).toBe('all');
  });
});

describe('restoreFilters', () => {
  it('puts the saved filters back and goes to page 1', () => {
    const out = restoreFilters(base, { severity: 'critical', status: 'resolved', source: 'ninjaone', clientId: 'c9', ticket: 'linked' });
    expect(out).toEqual({ page: 1, pageSize: 25, status: 'resolved', severity: 'critical', source: 'ninjaone', clientId: 'c9', ticket: 'linked' });
  });

  it('remembers the repeat grouping, only when it is on', () => {
    const on = { page: 1, pageSize: 25, status: 'open', collapse: true };
    expect(restoreFilters({ page: 1, pageSize: 25, status: 'open' }, rememberable(on)).collapse).toBe(true);
    expect(restoreFilters({ page: 1, pageSize: 25, status: 'open' }, rememberable({ page: 1, pageSize: 25, status: 'open' })).collapse).toBeUndefined();
    expect(restoreFilters({ page: 1, pageSize: 25 }, { collapse: 'yes' }).collapse).toBeUndefined();
  });

  it('restores All as no status filter', () => {
    expect(restoreFilters(base, { status: 'all' }).status).toBeUndefined();
  });

  it('ignores anything invalid and keeps the starting filters', () => {
    expect(restoreFilters(base, { severity: 'catastrophic', status: 'weird', ticket: 'maybe', source: 5, clientId: '' })).toEqual({ page: 1, pageSize: 25, status: 'open' });
    expect(restoreFilters(base, null)).toBe(base);
    expect(restoreFilters(base, [1])).toBe(base);
    expect(restoreFilters(base, 'text')).toBe(base);
  });

  it('round-trips what rememberable produced', () => {
    const f = { page: 1, pageSize: 25, status: 'investigating', severity: 'low', ticket: 'none' as const };
    expect(restoreFilters({ page: 1, pageSize: 25, status: 'open' }, rememberable(f))).toEqual(f);
  });
});
