import { describe, expect, it } from 'vitest';
import { devicesApi } from './api';

describe('devicesApi.exportQuery', () => {
  it('carries every filter but not the paging', () => {
    const qs = new URLSearchParams(devicesApi.exportQuery({ page: 3, pageSize: 50, clientId: 'c1', search: ' 10.0.0.5 ', vendor: 'huntress', attention: true, stale: true, offline: true, hasAlerts: true, notInMaster: true, missing: 'huntress' }));
    expect(Object.fromEntries(qs)).toEqual({ client_id: 'c1', search: '10.0.0.5', vendor: 'huntress', attention: 'true', stale: 'true', offline: 'true', has_alerts: 'true', not_in_master: 'true', missing: 'huntress' });
  });

  it('is empty when nothing is filtered', () => {
    expect(devicesApi.exportQuery({ page: 1, pageSize: 50 })).toBe('');
  });
});
