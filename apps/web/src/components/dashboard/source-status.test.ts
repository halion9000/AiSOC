import { describe, expect, it } from 'vitest';
import { connectedCount, isConnected, sourceTone } from './source-status';

describe('source status', () => {
  it('reads the connector health the API sends: healthy and degraded are connected, unhealthy and unknown are not', () => {
    expect(['healthy', 'active', 'degraded'].map(isConnected)).toEqual([true, true, true]);
    expect(['unhealthy', 'unknown', '', 'disabled'].map(isConnected)).toEqual([false, false, false, false]);
    expect(isConnected(null)).toBe(false);
    expect(isConnected(undefined)).toBe(false);
  });
  it('colours a degraded source amber and a failing one red', () => {
    expect([sourceTone('healthy'), sourceTone('degraded'), sourceTone('unhealthy'), sourceTone('unknown')]).toEqual(['ok', 'warning', 'down', 'idle']);
  });
  it('counts the connected sources the dashboard tile shows (this read 0 whenever no source said "active")', () => {
    const rows = [{ status: 'healthy' }, { status: 'healthy' }, { status: 'degraded' }, { status: 'unhealthy' }, { status: 'unknown' }];
    expect(connectedCount(rows)).toBe(3);
    expect(connectedCount([])).toBe(0);
  });
});
