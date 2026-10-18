import { cleanup, render, screen, waitFor } from '@testing-library/react';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

import { EASMView } from './EASMView';

const authFetch = vi.fn();
vi.mock('@/lib/auth-session', () => ({ authFetch: (...a: unknown[]) => authFetch(...a) }));

const ok = (body: unknown) => Promise.resolve({ ok: true, status: 200, json: () => Promise.resolve(body) });

beforeEach(() => {
  authFetch.mockReset();
});
afterEach(() => cleanup());

describe('EASMView', () => {
  it('lists the discovered assets by type and the drift against the asset it happened on', async () => {
    authFetch.mockImplementation((url: string) =>
      url.includes('/assets')
        ? ok([
            { id: 'a1', asset_type: 'domain', value: 'example.com', first_seen: '2026-10-01T00:00:00Z', last_seen: '2026-10-17T00:00:00Z', metadata: {} },
            { id: 'a2', asset_type: 'ip', value: '8.8.8.8', first_seen: '2026-10-01T00:00:00Z', last_seen: '2026-10-17T00:00:00Z', metadata: {} },
          ])
        : ok([{ id: 'd1', external_asset_id: 'a2', drift_type: 'new_open_port', details: {}, detected_at: '2026-10-17T05:00:00Z' }]),
    );
    render(<EASMView />);
    await waitFor(() => expect(screen.getByTestId('asset-summary').textContent).toBe('2 external asset(s): 1 domain, 1 ip'));
    expect(screen.getByText('new_open_port')).toBeTruthy();
    expect(screen.getAllByText('8.8.8.8').length).toBe(2); // the asset row and the drift line
  });

  it('says there is nothing yet, rather than pretending, when no asset was discovered', async () => {
    authFetch.mockImplementation(() => ok([]));
    render(<EASMView />);
    await waitFor(() => expect(screen.getByTestId('asset-summary').textContent).toContain('No external assets discovered yet'));
  });

  it('shows the error when the API refuses', async () => {
    authFetch.mockImplementation(() => Promise.resolve({ ok: false, status: 500, json: () => Promise.resolve({}) }));
    render(<EASMView />);
    await waitFor(() => expect(screen.getByRole('alert').textContent).toContain('500'));
  });
});
