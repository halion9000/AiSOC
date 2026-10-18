import { cleanup, render, screen, waitFor } from '@testing-library/react';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

import { PlatformHealth } from './PlatformHealth';

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
