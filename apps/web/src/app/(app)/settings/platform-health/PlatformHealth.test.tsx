import { cleanup, render, screen, waitFor } from '@testing-library/react';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

import { PlatformHealth, agoLabel } from './PlatformHealth';

const authFetch = vi.fn();
vi.mock('@/lib/auth-session', () => ({ authFetch: (...a: unknown[]) => authFetch(...a) }));

const snapshot = (database?: unknown) => ({
  ok: true,
  status: 200,
  json: () =>
    Promise.resolve({
      overall: 'ok',
      down: [],
      services: [{ service: 'fusion', status: 'up', latency_ms: 20, detail: '' }],
      generated_at: '2026-10-18T00:00:00Z',
      ...(database ? { database } : {}),
    }),
});

beforeEach(() => {
  authFetch.mockReset();
});
afterEach(() => cleanup());

describe('PlatformHealth', () => {
  it('warns plainly when the database is not enforcing tenant isolation, and says how to fix it', async () => {
    authFetch.mockResolvedValue(snapshot({ enforced: false, reason: 'the API connects as a database superuser', fix: 'connect the API as an ordinary role' }));
    render(<PlatformHealth />);
    await waitFor(() => expect(screen.getByTestId('row-security').textContent).toContain('not being enforced'));
    expect(screen.getByTestId('row-security').textContent).toContain('superuser');
    expect(screen.getByTestId('row-security').textContent).toContain('To fix');
  });

  it('says nothing about it when isolation is enforced', async () => {
    authFetch.mockResolvedValue(snapshot({ enforced: true, reason: 'ok' }));
    render(<PlatformHealth />);
    await waitFor(() => expect(screen.getByTestId('overall').textContent).toContain('Every service is answering'));
    expect(screen.queryByTestId('row-security')).toBeNull();
  });

  it('says it could not check, rather than staying silent, when the role is unreadable', async () => {
    authFetch.mockResolvedValue(snapshot({ enforced: null, reason: 'the database role could not be read' }));
    render(<PlatformHealth />);
    await waitFor(() => expect(screen.getByTestId('row-security').textContent).toContain('Could not check'));
  });

  it('warns when the connection pool is nearly full, and stays quiet when it is not', async () => {
    authFetch.mockResolvedValue(snapshot({ enforced: true, reason: 'ok', pool: { known: true, in_use: 27, limit: 30, percent: 90, near_limit: true } }));
    render(<PlatformHealth />);
    await waitFor(() => expect(screen.getByTestId('pool-warning').textContent).toContain('90% full (27 of 30 in use)'));
    cleanup();
    authFetch.mockResolvedValue(snapshot({ enforced: true, reason: 'ok', pool: { known: true, in_use: 2, limit: 30, percent: 7, near_limit: false } }));
    render(<PlatformHealth />);
    await waitFor(() => expect(screen.getByTestId('overall')).toBeInTheDocument());
    expect(screen.queryByTestId('pool-warning')).not.toBeInTheDocument();
  });
});

describe('device feeds', () => {
  it('says in plain words how long ago each tool synced', () => {
    expect(agoLabel(null)).toBe('never');
    expect(agoLabel(1)).toBe('just now');
    expect(agoLabel(45)).toBe('45 minutes ago');
    expect(agoLabel(300)).toBe('5 hours ago');
    expect(agoLabel(60 * 24 * 5)).toBe('5 days ago');
  });

  it('lists each tool with its device count, and flags one that has gone quiet', async () => {
    authFetch.mockResolvedValue({
      ok: true,
      status: 200,
      json: () =>
        Promise.resolve({
          overall: 'ok',
          down: [],
          services: [{ service: 'fusion', status: 'up', latency_ms: 20, detail: '' }],
          device_feeds: [
            { vendor: 'huntress', devices: 5343, last_synced: '2026-10-19T01:49:54Z', minutes_ago: 12, stalled: false },
            { vendor: 'addigy', devices: 1799, last_synced: '2026-10-18T10:00:00Z', minutes_ago: 900, stalled: true },
          ],
          generated_at: '2026-10-19T02:00:00Z',
        }),
    });
    render(<PlatformHealth />);
    const feeds = await screen.findByTestId('device-feeds');
    expect(feeds).toHaveTextContent('huntress: 5,343 devices, last synced 12 minutes ago');
    expect(feeds).toHaveTextContent('addigy: 1,799 devices, last synced 15 hours ago (nothing for hours');
  });
});

describe('pool history', () => {
  const withPeak = (peak: unknown) => ({
    ok: true,
    status: 200,
    json: () =>
      Promise.resolve({
        overall: 'ok',
        down: [],
        services: [{ service: 'fusion', status: 'up', latency_ms: 20, detail: '' }],
        database: { enforced: true, reason: 'ok', pool: { known: true, in_use: 2, limit: 30, percent: 7, near_limit: false, peak_last_hour: peak } },
        generated_at: '2026-10-19T02:00:00Z',
      }),
  });

  it('says how full the connection pool got in the last hour, and when', async () => {
    authFetch.mockResolvedValue(withPeak({ samples: 40, peak_in_use: 26, peak_limit: 30, peak_percent: 87, peak_minutes_ago: 12 }));
    render(<PlatformHealth />);
    expect(await screen.findByTestId('pool-peak')).toHaveTextContent('busiest in the last hour was 87% (26 of 30), 12 minutes ago');
  });

  it('says nothing when there are no readings yet', async () => {
    authFetch.mockResolvedValue(withPeak({ samples: 0 }));
    render(<PlatformHealth />);
    await waitFor(() => expect(screen.getByTestId('overall')).toBeInTheDocument());
    expect(screen.queryByTestId('pool-peak')).not.toBeInTheDocument();
  });
});
