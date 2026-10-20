import { beforeEach, describe, expect, it, vi } from 'vitest';
import { render, screen } from '@testing-library/react';
import userEvent from '@testing-library/user-event';

const authFetch = vi.hoisted(() => vi.fn());
vi.mock('@/lib/auth-session', () => ({ authFetch }));

import { ClientPosture, coverage } from './ClientPosture';

const reply = (body: unknown, ok = true) => ({ ok, status: ok ? 200 : 500, json: () => Promise.resolve(body) });
const posture = (over: Record<string, unknown> = {}) => ({
  client_id: 'c1',
  client_name: 'Acme Dental',
  generated_at: '2026-10-19T10:00:00Z',
  devices: { devices: 40, needs_attention: 3, stale_agents: 1, not_in_huntress: 2, offline: 4 },
  identity: { people: 20, with_mfa: 15, not_required: 2, without_mfa: 3, admins_without_mfa: 1, refreshed_at: null },
  alerts: { open: 7, critical: 1, high: 2, without_ticket: 4 },
  open_cases: 2,
  ...over,
});

function serve(p: unknown) {
  authFetch.mockImplementation((url?: string) =>
    Promise.resolve((url ?? '').includes('/mssp/children') ? reply([{ id: 'c1', name: 'Acme Dental' }, { id: 'c0', name: 'Aardvark Vet' }]) : reply(p)),
  );
}

beforeEach(() => authFetch.mockReset());

describe('coverage', () => {
  it('is the share of people covered, or a dash when there are none', () => {
    expect(coverage({ people: 20, with_mfa: 15 })).toBe('75%');
    expect(coverage({ people: 0, with_mfa: 0 })).toBe('—');
  });
});

describe('ClientPosture', () => {
  it('lists the clients alphabetically and shows the posture of the one picked', async () => {
    serve(posture());
    render(<ClientPosture />);
    const select = await screen.findByLabelText('Client');
    await screen.findByRole('option', { name: 'Aardvark Vet' });
    const options = screen.getAllByRole('option').map((o) => o.textContent);
    expect(options).toEqual(['Pick a client', 'Aardvark Vet', 'Acme Dental']);
    await userEvent.selectOptions(select, 'c1');
    const page = await screen.findByTestId('posture');
    expect(page).toHaveTextContent('Acme Dental');
    expect(page).toHaveTextContent('40');
    expect(page).toHaveTextContent('75%');
    expect(page).toHaveTextContent('Open, no ticket');
    expect(authFetch).toHaveBeenCalledWith('/api/v1/client-posture/c1');
  });

  it('says so when a client has no second-factor data', async () => {
    serve(posture({ identity: null }));
    render(<ClientPosture />);
    await userEvent.selectOptions(await screen.findByLabelText('Client'), 'c1');
    expect(await screen.findByTestId('no-identity')).toHaveTextContent('No second-factor data yet');
  });

  it('shows an error plainly', async () => {
    authFetch.mockResolvedValue(reply({}, false));
    render(<ClientPosture />);
    expect(await screen.findByRole('alert')).toHaveTextContent('The API answered 500');
  });
});
