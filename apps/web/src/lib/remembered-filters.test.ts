import { afterEach, describe, expect, it, vi } from 'vitest';
import { clearFilters, loadFilters, pickString, saveFilters } from './remembered-filters';

afterEach(() => {
  vi.restoreAllMocks();
  window.localStorage.clear();
});

describe('remembered filters', () => {
  it('round-trips what was saved, per page', () => {
    saveFilters('devices', { vendor: 'huntress', offlineOnly: true });
    saveFilters('alerts', { status: 'open' });
    expect(loadFilters('devices')).toEqual({ vendor: 'huntress', offlineOnly: true });
    expect(loadFilters('alerts')).toEqual({ status: 'open' });
    expect(loadFilters('cases')).toBeNull();
  });

  it('forgets on request', () => {
    saveFilters('devices', { vendor: 'huntress' });
    clearFilters('devices');
    expect(loadFilters('devices')).toBeNull();
  });

  it('ignores anything that is not a plain object', () => {
    window.localStorage.setItem('aisoc.filters.devices', '[1,2]');
    expect(loadFilters('devices')).toBeNull();
    window.localStorage.setItem('aisoc.filters.devices', 'not json');
    expect(loadFilters('devices')).toBeNull();
  });

  it('never throws when storage is unavailable', () => {
    vi.spyOn(Storage.prototype, 'getItem').mockImplementation(() => {
      throw new Error('blocked');
    });
    vi.spyOn(Storage.prototype, 'setItem').mockImplementation(() => {
      throw new Error('full');
    });
    expect(loadFilters('devices')).toBeNull();
    expect(() => saveFilters('devices', { a: 1 })).not.toThrow();
  });

  it('keeps a saved string only when it is still an allowed value', () => {
    expect(pickString('huntress', ['huntress', 'addigy'])).toBe('huntress');
    expect(pickString('gone', ['huntress'])).toBe('');
    expect(pickString(5)).toBe('');
    expect(pickString('anything')).toBe('anything');
  });
});
