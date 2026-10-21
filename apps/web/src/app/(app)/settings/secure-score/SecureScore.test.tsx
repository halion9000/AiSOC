import { beforeEach, describe, expect, it, vi } from 'vitest';
import { render, screen } from '@testing-library/react';
import userEvent from '@testing-library/user-event';

const authFetch = vi.hoisted(() => vi.fn());
vi.mock('@/lib/auth-session', () => ({ authFetch }));

import { SecureScore, changeText, sparklinePath, visibleScores, type ScoreClient } from './SecureScore';

const reply = (body: unknown, ok = true) => ({ ok, status: ok ? 200 : 500, json: () => Promise.resolve(body) });
const client = (over: Partial<ScoreClient> = {}): ScoreClient => ({
  client_id: 'c1',
  client_name: 'Acme Dental',
  current: 115,
  max: 267,
  percent: 43.1,
  average: 54.02,
  change_30d: 15,
  active_users: 20,
  licensed_users: 25,
  taken_at: '2026-10-21T00:00:00Z',
  refreshed_at: '2026-10-21T08:00:00Z',
  history: [
    { d: '2026-09-20', c: 100, m: 267 },
    { d: '2026-10-21', c: 115, m: 267 },
  ],
  points_available: 16,
  ...over,
});

beforeEach(() => authFetch.mockReset());

describe('the small helpers', () => {
  it('draws the trend scaled into the box, lowest point at the bottom, and nothing for fewer than two points', () => {
    expect(sparklinePath([{ c: 1 }])).toBe('');
    const path = sparklinePath([{ c: 10 }, { c: 20 }, { c: 15 }], 100, 20);
    expect(path).toBe('M0.0,19.0 L50.0,1.0 L100.0,10.0');
    expect(sparklinePath([{ c: 5 }, { c: 5 }], 10, 10)).toBe('M0.0,9.0 L10.0,9.0'); // a flat line does not divide by zero
  });
  it('writes the 30-day change with a sign, or a dash when there is nothing to compare with', () => {
    expect(changeText(15)).toBe('+15');
    expect(changeText(-5.5)).toBe('−5.5');
    expect(changeText(0)).toBe('0');
    expect(changeText(null)).toBe('—');
  });
  it('orders by lowest score, biggest drop, or name, and filters by name', () => {
    const list = [client({ client_id: 'a', client_name: 'Birch', percent: 60, change_30d: -2 }), client({ client_id: 'b', client_name: 'Acme', percent: 30, change_30d: 5 }), client({ client_id: 'c', client_name: 'Cedar', percent: 45, change_30d: -9 })];
    expect(visibleScores([...list], { sort: 'lowest' }).map((c) => c.client_name)).toEqual(['Acme', 'Cedar', 'Birch']);
    expect(visibleScores([...list], { sort: 'biggest_drop' }).map((c) => c.client_name)).toEqual(['Cedar', 'Birch', 'Acme']);
    expect(visibleScores([...list], { sort: 'name' }).map((c) => c.client_name)).toEqual(['Acme', 'Birch', 'Cedar']);
    expect(visibleScores([...list], { sort: 'name', query: 'ce' }).map((c) => c.client_name)).toEqual(['Cedar']);
  });
});

describe('SecureScore', () => {
  it('lists each client with its score, change and the lowest first, with a total line', async () => {
    authFetch.mockResolvedValue(reply([client(), client({ client_id: 'c2', client_name: 'Birch Law', percent: 80, current: 214, change_30d: -3 })]));
    render(<SecureScore />);
    expect(await screen.findByTestId('totals')).toHaveTextContent('2 clients, 62% on average; 1 has fallen in the last 30 days.');
    const rows = screen.getAllByTestId('score-row');
    expect(rows[0]).toHaveTextContent('Acme Dental');
    expect(rows[0]).toHaveTextContent('43.1%');
    expect(rows[0]).toHaveTextContent('115 / 267');
    expect(screen.getAllByTestId('change')[0]).toHaveTextContent('+15');
    expect(rows[1]).toHaveTextContent('Birch Law');
  });

  it('opens a client to list the controls still missing points, biggest first as the API sent them', async () => {
    authFetch.mockImplementation((url?: string) =>
      Promise.resolve(
        String(url).includes('/secure-scores/c1')
          ? reply({ ...client(), improvements: [{ id: 'a', title: 'Require MFA for administrative roles', missing: 10, max: 10, status: 'current status: off', user_impact: 'Low', cost: 'Unknown' }, { id: 'b', title: 'Block legacy authentication', missing: 6, max: 6 }] })
          : reply([client()]),
      ),
    );
    const user = userEvent.setup();
    render(<SecureScore />);
    await user.click(await screen.findByRole('button', { name: 'Acme Dental' }));
    const list = await screen.findByTestId('improvements');
    expect(list).toHaveTextContent('+10 points');
    expect(list).toHaveTextContent('Require MFA for administrative roles');
    expect(list).toHaveTextContent('user impact: Low');
    expect(list).not.toHaveTextContent('cost: Unknown');
    expect(list).toHaveTextContent('Block legacy authentication');
    expect(authFetch).toHaveBeenCalledWith('/api/v1/identity/secure-scores/c1');
  });

  it('says what to do when nothing has been read yet, and shows the error when the list cannot be loaded', async () => {
    authFetch.mockResolvedValue(reply([]));
    const { unmount } = render(<SecureScore />);
    expect(await screen.findByTestId('none')).toHaveTextContent('Nothing yet');
    unmount();
    authFetch.mockResolvedValue(reply({}, false));
    render(<SecureScore />);
    expect(await screen.findByRole('alert')).toHaveTextContent('The API answered 500');
  });
});
