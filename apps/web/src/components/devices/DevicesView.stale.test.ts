import { describe, expect, it, vi } from 'vitest';
import type { DeviceRow } from '@/lib/api';

vi.mock('@/lib/api', () => ({ devicesApi: {} }));

const NOW = Date.parse('2026-10-21T12:00:00Z');
const src = (vendor: string, stale: boolean, last_checkin: string | null) => ({ vendor, name: 'PC', last_seen: last_checkin ?? '', details: {}, last_checkin, stale });
const device = (sources: ReturnType<typeof src>[]) => ({ sources }) as unknown as DeviceRow;

describe('staleNote', () => {
  it('says how long a tool has not seen the device when its only record is stale', async () => {
    const { staleNote } = await import('./DevicesView');
    expect(staleNote(device([src('dnsfilter', true, '2026-10-01T12:00:00Z')]), 'dnsfilter', NOW)).toMatch(/has not seen this device for 20 days/);
  });
  it('says nothing when the tool has a fresh record, even if it also holds an old one from a reinstall', async () => {
    const { staleNote } = await import('./DevicesView');
    const both = device([src('dnsfilter', true, '2024-08-23T12:00:00Z'), src('dnsfilter', false, '2026-10-21T10:00:00Z')]);
    expect(staleNote(both, 'dnsfilter', NOW)).toBeUndefined();
  });
  it('names the newest of several stale records, and says nothing for a tool the device does not have', async () => {
    const { staleNote } = await import('./DevicesView');
    const two = device([src('dnsfilter', true, '2024-08-23T12:00:00Z'), src('dnsfilter', true, '2026-10-01T12:00:00Z')]);
    expect(staleNote(two, 'dnsfilter', NOW)).toMatch(/for 20 days/);
    expect(staleNote(two, 'huntress', NOW)).toBeUndefined();
  });
});
