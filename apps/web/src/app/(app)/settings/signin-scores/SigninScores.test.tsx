import { beforeEach, describe, expect, it, vi } from 'vitest';
import { render, screen, waitFor } from '@testing-library/react';
import userEvent from '@testing-library/user-event';

const authFetch = vi.hoisted(() => vi.fn());
vi.mock('@/lib/auth-session', () => ({ authFetch }));

import { SigninScores, placeLabel } from './SigninScores';

const reply = (body: unknown, ok = true) => ({ ok, status: ok ? 200 : 500, json: () => Promise.resolve(body) });
const row = (over: Record<string, unknown> = {}) => ({
  client_id: 'c1',
  client_name: 'Acme Dental',
  user: 'bob@acme.com',
  display_name: null,
  occurred_at: '2026-10-19T10:00:00Z',
  score: 0.93,
  success: true,
  country: 'US',
  city: 'Dallas',
  ip_address: '203.0.113.9',
  app: 'Office 365',
  mfa: false,
  risk: 'high',
  ...over,
});

beforeEach(() => authFetch.mockReset());

describe('placeLabel', () => {
  it('joins city and country and falls back when neither is known', () => {
    expect(placeLabel({ city: 'Dallas', country: 'US' })).toBe('Dallas, US');
    expect(placeLabel({ city: null, country: 'US' })).toBe('US');
    expect(placeLabel({ city: null, country: null })).toBe('unknown place');
  });
});

describe('SigninScores', () => {
  it('also lists the most unusual identity changes', async () => {
    const change = { client_id: 'c1', client_name: 'Acme Dental', actor: 'eve@acme.com', actor_is_app: false, activity: 'Add member to role', category: 'RoleManagement', target: 'bob@acme.com', success: true, sensitivity: 3, occurred_at: '2026-10-19T10:00:00Z', score: 0.88 };
    authFetch.mockImplementation((url?: string) => Promise.resolve((url ?? '').includes('/identity/top') ? reply([change]) : reply([])));
    render(<SigninScores />);
    const rows = await screen.findAllByTestId('change-row');
    expect(rows[0]).toHaveTextContent('Add member to role');
    expect(rows[0]).toHaveTextContent('eve@acme.com');
    expect(authFetch).toHaveBeenCalledWith('/api/v1/identity/top?days=7&limit=50');
  });

  it('lists the scored sign-ins with who, where and what looked wrong', async () => {
    authFetch.mockImplementation((url?: string) => Promise.resolve((url ?? '').includes('/identity/top') ? reply([]) : reply([row(), row({ user: 'amy@acme.com', score: 0.5, success: false, mfa: true, risk: 'none' })])));
    render(<SigninScores />);
    const rows = await screen.findAllByTestId('signin-row');
    expect(rows).toHaveLength(2);
    expect(rows[0]).toHaveTextContent('0.93');
    expect(rows[0]).toHaveTextContent('Dallas, US');
    expect(rows[0]).toHaveTextContent('no MFA');
    expect(rows[0]).toHaveTextContent('risk: high');
    expect(rows[1]).toHaveTextContent('Failed');
    expect(authFetch).toHaveBeenCalledWith('/api/v1/signins/top?days=7&limit=100');
  });

  it('asks again for the period that is picked', async () => {
    authFetch.mockResolvedValue(reply([]));
    render(<SigninScores />);
    expect(await screen.findByTestId('none')).toBeInTheDocument();
    await userEvent.click(screen.getByRole('button', { name: 'Last 30 days' }));
    await waitFor(() => expect(authFetch).toHaveBeenCalledWith('/api/v1/signins/top?days=30&limit=100'));
  });

  it('shows an error plainly', async () => {
    authFetch.mockResolvedValue(reply({}, false));
    render(<SigninScores />);
    expect(await screen.findByRole('alert')).toHaveTextContent('The API answered 500');
  });
});
