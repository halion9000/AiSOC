import { beforeEach, describe, expect, it, vi } from 'vitest';
import { render, screen, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import type { Case } from '@/lib/api';

const recentMock = vi.fn();
vi.mock('@/lib/api', () => ({ casesApi: { recent: (limit?: number) => recentMock(limit) } }));

import { CASE_LIMIT, TeamAnalyticsView, buildTeamStats, formatDuration, sortRows } from './TeamAnalyticsView';

// The page was a "gamification leaderboard" of invented people (Sarah Chen, Marcus Rivera, ...) with invented scores, accuracy, badges and a
// "Team Highlights" feed, shown to every workspace. Now it is computed from real cases, and only from what cases record.
const INVENTED = ['Sarah Chen', 'Marcus Rivera', 'Aisha Patel', 'James Wong', 'Elena Vasquez', 'David Kim', 'Speed Demon', 'Zero FP', 'MITRE Master', 'Team Highlights'];

const NOW = Date.parse('2026-10-08T12:00:00Z');
const day = 86400000;
const iso = (offsetMs: number) => new Date(NOW - offsetMs).toISOString();

function make(over: Partial<Case> & { id: string }): Case {
  return { title: `Case ${over.id}`, status: 'open', severity: 'medium', createdAt: iso(10 * day), updatedAt: iso(day), ...over };
}
const finished = (id: string, assignee: string | undefined, openedAgoMs: number, finishedAgoMs: number, status: Case['status'] = 'closed', field: 'closedAt' | 'resolvedAt' = 'closedAt') =>
  make({ id, assignee, status, createdAt: iso(openedAgoMs), [field]: iso(finishedAgoMs) });

describe('buildTeamStats', () => {
  it('counts only cases finished inside the window, whichever of closed or resolved they are', () => {
    const cases = [
      finished('a', 'ana', 3 * day, 1 * day), // 2 days
      finished('b', 'ana', 40 * day, 35 * day), // outside 30
      finished('c', 'ana', 5 * day, 4 * day, 'resolved', 'resolvedAt'), // a resolved case has resolvedAt, not closedAt
      make({ id: 'd', assignee: 'ana', status: 'closed' }), // finished but no timestamp at all
    ];
    const stats = buildTeamStats(cases, NOW, 30);
    expect(stats.totalClosed).toBe(2);
    expect(stats.rows).toEqual([{ analyst: 'ana', closed: 2, avgMinutes: (2 * day + 1 * day) / 2 / 60000, open: 0 }]);
  });

  it('never counts a finish time in the future, or a negative duration in the average', () => {
    const cases = [finished('a', 'ana', day, -day), finished('b', 'ana', day, 2 * day), finished('c', 'ana', 4 * day, 2 * day)];
    const stats = buildTeamStats(cases, NOW, 30);
    expect(stats.totalClosed).toBe(2); // 'a' finishes tomorrow
    // 'b' finished BEFORE it was opened: counted as closed, but its duration is not trusted
    expect(stats.rows[0].closed).toBe(2);
    expect(stats.rows[0].avgMinutes).toBe((2 * day) / 60000);
  });

  it('an analyst whose closed cases have no valid duration has no average, not a zero', () => {
    const stats = buildTeamStats([finished('a', 'ana', day, 2 * day)], NOW, 30);
    expect(stats.rows[0].closed).toBe(1);
    expect(stats.rows[0].avgMinutes).toBeNull();
    expect(stats.avgMinutes).toBeNull();
  });

  it('counts open cases per assignee and keeps unassigned ones apart', () => {
    const stats = buildTeamStats(
      [make({ id: '1', assignee: 'ana' }), make({ id: '2', assignee: 'ana', status: 'in_progress' }), make({ id: '3', assignee: 'bo', status: 'pending' }), make({ id: '4' }), make({ id: '5', assignee: '   ' })],
      NOW,
      30,
    );
    expect(stats.totalOpen).toBe(5);
    expect(stats.unassignedOpen).toBe(2);
    expect(Object.fromEntries(stats.rows.map((r) => [r.analyst, r.open]))).toEqual({ ana: 2, bo: 1 });
  });

  it('counts a closed case with no assignee in the team total but gives nobody credit', () => {
    const stats = buildTeamStats([finished('a', undefined, 2 * day, day)], NOW, 30);
    expect(stats.totalClosed).toBe(1);
    expect(stats.rows).toEqual([]);
    expect(stats.activeAnalysts).toBe(0);
  });

  it('active analysts are those who closed something, not those who merely have open cases', () => {
    const stats = buildTeamStats([finished('a', 'ana', 2 * day, day), make({ id: 'b', assignee: 'bo' })], NOW, 30);
    expect(stats.rows.length).toBe(2);
    expect(stats.activeAnalysts).toBe(1);
  });

  it('uses the assignee exactly as recorded (it is free text, not a user id)', () => {
    const stats = buildTeamStats([finished('a', 'hal@example.com', 2 * day, day)], NOW, 30);
    expect(stats.rows[0].analyst).toBe('hal@example.com');
  });

  it('a workspace with no cases has nothing, and nothing invented', () => {
    expect(buildTeamStats([], NOW, 30)).toEqual({ rows: [], totalClosed: 0, avgMinutes: null, totalOpen: 0, activeAnalysts: 0, unassignedOpen: 0 });
  });
});

describe('sortRows', () => {
  const rows = [
    { analyst: 'bo', closed: 3, avgMinutes: 60, open: 1 },
    { analyst: 'ana', closed: 3, avgMinutes: null, open: 4 },
    { analyst: 'cy', closed: 5, avgMinutes: 30, open: 0 },
  ];
  it('orders by cases closed, breaking ties by name', () => expect(sortRows(rows, 'closed').map((r) => r.analyst)).toEqual(['cy', 'ana', 'bo']));
  it('orders by open cases', () => expect(sortRows(rows, 'open').map((r) => r.analyst)).toEqual(['ana', 'bo', 'cy']));
  it('puts the fastest first and people with no timed cases last', () => expect(sortRows(rows, 'speed').map((r) => r.analyst)).toEqual(['cy', 'bo', 'ana']));
  it('does not mutate its input', () => {
    const copy = JSON.stringify(rows);
    sortRows(rows, 'speed');
    expect(JSON.stringify(rows)).toBe(copy);
  });
});

describe('formatDuration', () => {
  it('is a dash when unknown, then minutes, hours, days', () => {
    expect(formatDuration(null)).toBe('—');
    expect(formatDuration(45)).toBe('45 min');
    expect(formatDuration(119.6)).toBe('120 min');
    expect(formatDuration(150)).toBe('2.5 h');
    expect(formatDuration(60 * 48)).toBe('2.0 days');
  });
});

describe('the page', () => {
  beforeEach(() => recentMock.mockReset());

  it('shows an honest empty state, none of the invented people, and no gamification', async () => {
    recentMock.mockResolvedValue({ cases: [], total: 0, page: 1, pageSize: 0 });
    const { container } = render(<TeamAnalyticsView />);
    expect(await screen.findByText('No assigned cases yet')).toBeInTheDocument();
    for (const invented of INVENTED) expect(container.textContent).not.toContain(invented);
    expect(container.textContent).not.toMatch(/Accuracy|Score|Badge/i);
    expect(screen.getByText('Cases Closed (30 days)').nextElementSibling).toHaveTextContent('0');
    expect(screen.getByText('Avg Resolution Time').nextElementSibling).toHaveTextContent('—');
  });

  it('asks for the maximum number of cases and shows real analysts with their real numbers', async () => {
    recentMock.mockResolvedValue({ cases: [finished('a', 'ana', 3 * day, day), finished('b', 'ana', 2 * day, day), make({ id: 'c', assignee: 'ana' }), finished('d', 'bo', 5 * day, day)], total: 4, page: 1, pageSize: 4 });
    render(<TeamAnalyticsView />);
    const table = await screen.findByRole('table');
    expect(recentMock).toHaveBeenCalledWith(CASE_LIMIT);
    const cells = (name: string) => within(within(table).getByText(name).closest('tr') as HTMLElement).getAllByRole('cell').map((c) => c.textContent);
    expect(cells('ana')).toEqual(['1', 'ana', '2', '36.0 h', '1']); // (2 days + 1 day) / 2 = 36 hours; days are used from 48 hours
    expect(cells('bo')).toEqual(['2', 'bo', '1', '4.0 days', '0']);
    const headers = within(table).getAllByRole('columnheader').map((h) => h.textContent);
    expect(headers).toEqual(['#', 'Analyst', 'Closed (30d)', 'Avg Time', 'Open Now']);
  });

  it('changes the counts when the period changes', async () => {
    recentMock.mockResolvedValue({ cases: [finished('a', 'ana', 22 * day, 20 * day), finished('b', 'ana', 3 * day, 2 * day)], total: 2, page: 1, pageSize: 2 });
    render(<TeamAnalyticsView />);
    const user = userEvent.setup();
    await screen.findByRole('table');
    expect(screen.getByText('Cases Closed (30 days)').nextElementSibling).toHaveTextContent('2');
    await user.click(screen.getByRole('button', { name: 'Last 7 days' }));
    expect(screen.getByText('Cases Closed (7 days)').nextElementSibling).toHaveTextContent('1');
  });

  it('searches by analyst and offers a way back', async () => {
    recentMock.mockResolvedValue({ cases: [finished('a', 'ana', 3 * day, day), finished('b', 'bo', 3 * day, day)], total: 2, page: 1, pageSize: 2 });
    render(<TeamAnalyticsView />);
    const user = userEvent.setup();
    await screen.findByRole('table');
    await user.type(screen.getByLabelText('Search analyst'), 'zzz');
    expect(screen.getByText('No analysts match your search')).toBeInTheDocument();
    await user.click(screen.getByRole('button', { name: 'Clear search' }));
    expect(screen.getByText('ana')).toBeInTheDocument();
    expect(screen.getByText('bo')).toBeInTheDocument();
  });

  it('says so when there may be older cases it has not counted', async () => {
    const many = Array.from({ length: CASE_LIMIT }, (_, i) => make({ id: String(i), assignee: 'ana' }));
    recentMock.mockResolvedValue({ cases: many, total: many.length, page: 1, pageSize: many.length });
    render(<TeamAnalyticsView />);
    expect(await screen.findByText(/older cases are not counted/)).toBeInTheDocument();
  });

  it('does not make that claim for a smaller set', async () => {
    recentMock.mockResolvedValue({ cases: [make({ id: '1', assignee: 'ana' })], total: 1, page: 1, pageSize: 1 });
    render(<TeamAnalyticsView />);
    await screen.findByRole('table');
    expect(screen.queryByText(/older cases are not counted/)).not.toBeInTheDocument();
  });

  it('shows the failure rather than any sample data, and retries', async () => {
    recentMock.mockRejectedValueOnce(new Error('503 service unavailable')).mockResolvedValue({ cases: [finished('a', 'ana', 2 * day, day)], total: 1, page: 1, pageSize: 1 });
    const { container } = render(<TeamAnalyticsView />);
    expect(await screen.findByText('Could not load team analytics')).toBeInTheDocument();
    expect(screen.getByText('503 service unavailable')).toBeInTheDocument();
    for (const invented of INVENTED) expect(container.textContent).not.toContain(invented);
    await userEvent.setup().click(screen.getByRole('button', { name: 'Try again' }));
    expect(await screen.findByText('ana')).toBeInTheDocument();
  });
});
