'use client';

import { useCallback, useEffect, useMemo, useState } from 'react';
import { clsx } from 'clsx';
import { EmptyState, EmptyStateIcons } from '@/components/ui/EmptyState';
import { casesApi, type Case } from '@/lib/api';

/**
 * Analyst activity, computed from this workspace's real cases.
 *
 * This page used to be a "gamification leaderboard" built on hard-coded people ("Sarah Chen", "Marcus Rivera", ...) with invented scores,
 * accuracy percentages, badges ("Speed Demon", "Zero FP") and a "Team Highlights" feed. None of that had a data source. What cases DO record is
 * who a case is assigned to, its status and when it was opened and finished, so that is all this shows: cases closed, how long they took, and
 * what each person has open. The assignee is the free-text value stored on the case, shown exactly as recorded.
 */

/** The API returns at most this many cases per request, newest first. */
export const CASE_LIMIT = 500;
export const PERIODS = [7, 30, 90] as const;
export type Period = (typeof PERIODS)[number];
export type SortKey = 'closed' | 'speed' | 'open';

export interface AnalystRow {
  analyst: string;
  closed: number;
  /** Mean minutes from opened to finished over the closed cases that have a valid duration; null if none. */
  avgMinutes: number | null;
  open: number;
}

export interface TeamStats {
  rows: AnalystRow[];
  totalClosed: number;
  avgMinutes: number | null;
  totalOpen: number;
  activeAnalysts: number;
  unassignedOpen: number;
}

const FINISHED = new Set(['resolved', 'closed']);

function finishedAt(c: Case): number | null {
  const stamp = c.closedAt ?? c.resolvedAt;
  if (!stamp) return null;
  const time = new Date(stamp).getTime();
  return Number.isNaN(time) ? null : time;
}

function minutesBetween(c: Case, end: number): number | null {
  const start = new Date(c.createdAt).getTime();
  if (Number.isNaN(start) || end < start) return null;
  return (end - start) / 60000;
}

function mean(values: number[]): number | null {
  return values.length ? values.reduce((a, b) => a + b, 0) / values.length : null;
}

/** Per-analyst totals for cases finished in the last `days` days, plus what each assignee has open right now. */
export function buildTeamStats(cases: Case[], now: number, days: number): TeamStats {
  const since = now - days * 86400000;
  const byAnalyst = new Map<string, { closed: number; minutes: number[]; open: number }>();
  const slot = (name: string) => {
    let entry = byAnalyst.get(name);
    if (!entry) byAnalyst.set(name, (entry = { closed: 0, minutes: [], open: 0 }));
    return entry;
  };
  const allMinutes: number[] = [];
  let totalClosed = 0;
  let totalOpen = 0;
  let unassignedOpen = 0;

  for (const c of cases) {
    const who = c.assignee?.trim() || null;
    if (FINISHED.has(c.status)) {
      const end = finishedAt(c);
      if (end === null || end < since || end > now) continue;
      totalClosed += 1;
      const minutes = minutesBetween(c, end);
      if (minutes !== null) allMinutes.push(minutes);
      if (who) {
        const entry = slot(who);
        entry.closed += 1;
        if (minutes !== null) entry.minutes.push(minutes);
      }
    } else {
      totalOpen += 1;
      if (who) slot(who).open += 1;
      else unassignedOpen += 1;
    }
  }

  const rows = [...byAnalyst.entries()].map(([analyst, e]) => ({ analyst, closed: e.closed, avgMinutes: mean(e.minutes), open: e.open }));
  return { rows, totalClosed, avgMinutes: mean(allMinutes), totalOpen, activeAnalysts: rows.filter((r) => r.closed > 0).length, unassignedOpen };
}

export function sortRows(rows: AnalystRow[], key: SortKey): AnalystRow[] {
  const byName = (a: AnalystRow, b: AnalystRow) => a.analyst.localeCompare(b.analyst);
  return [...rows].sort((a, b) => {
    if (key === 'closed') return b.closed - a.closed || byName(a, b);
    if (key === 'open') return b.open - a.open || byName(a, b);
    // fastest first; someone with no timed cases goes last
    if (a.avgMinutes === null && b.avgMinutes === null) return byName(a, b);
    if (a.avgMinutes === null) return 1;
    if (b.avgMinutes === null) return -1;
    return a.avgMinutes - b.avgMinutes || byName(a, b);
  });
}

export function formatDuration(minutes: number | null): string {
  if (minutes === null) return '—';
  if (minutes < 120) return `${Math.round(minutes)} min`;
  const hours = minutes / 60;
  if (hours < 48) return `${hours.toFixed(1)} h`;
  return `${(hours / 24).toFixed(1)} days`;
}

const SORT_OPTIONS: { key: SortKey; label: string }[] = [
  { key: 'closed', label: 'Cases closed' },
  { key: 'speed', label: 'Fastest' },
  { key: 'open', label: 'Open now' },
];

export function TeamAnalyticsView() {
  const [cases, setCases] = useState<Case[] | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [days, setDays] = useState<Period>(30);
  const [sortBy, setSortBy] = useState<SortKey>('closed');
  const [search, setSearch] = useState('');

  const load = useCallback(async () => {
    setError(null);
    setCases(null);
    try {
      const result = await casesApi.recent(CASE_LIMIT);
      setCases(result.cases);
    } catch (err) {
      setError(err instanceof Error && err.message ? err.message : 'Could not load cases.');
    }
  }, []);

  useEffect(() => {
    void load();
  }, [load]);

  const stats = useMemo(() => (cases ? buildTeamStats(cases, Date.now(), days) : null), [cases, days]);
  const rows = useMemo(() => {
    if (!stats) return [];
    const needle = search.trim().toLowerCase();
    return sortRows(stats.rows, sortBy).filter((r) => !needle || r.analyst.toLowerCase().includes(needle));
  }, [stats, sortBy, search]);

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-2xl font-bold tracking-tight text-white">Team Analytics</h1>
        <p className="mt-1 text-sm text-gray-400">Analyst activity from this workspace&rsquo;s cases</p>
      </div>

      {error ? (
        <EmptyState
          icon={EmptyStateIcons.search}
          title="Could not load team analytics"
          description={error}
          action={
            <button type="button" onClick={() => void load()} className="rounded-lg bg-gray-800 px-4 py-2 text-sm text-gray-200 hover:bg-gray-700 transition-colors">
              Try again
            </button>
          }
        />
      ) : cases === null || stats === null ? (
        <p role="status" className="text-sm text-gray-400">Loading cases…</p>
      ) : (
        <>
          <div className="flex flex-wrap items-center gap-3">
            <span className="text-xs font-medium uppercase tracking-wider text-gray-500">Period</span>
            {PERIODS.map((p) => (
              <button
                key={p}
                type="button"
                onClick={() => setDays(p)}
                aria-pressed={days === p}
                className={clsx('rounded-md px-2.5 py-1 text-xs font-medium transition', days === p ? 'bg-white/10 text-white' : 'text-gray-500 hover:text-gray-300')}
              >
                Last {p} days
              </button>
            ))}
            {cases.length >= CASE_LIMIT ? (
              <span className="text-xs text-amber-400">Based on the most recent {CASE_LIMIT} cases; older cases are not counted.</span>
            ) : null}
          </div>

          <div className="grid gap-4 sm:grid-cols-2 lg:grid-cols-4">
            {[
              { label: `Cases Closed (${days} days)`, value: String(stats.totalClosed), accent: 'text-emerald-400' },
              { label: 'Avg Resolution Time', value: formatDuration(stats.avgMinutes), accent: 'text-sky-400' },
              { label: 'Open Cases', value: String(stats.totalOpen), accent: 'text-violet-400', hint: stats.unassignedOpen ? `${stats.unassignedOpen} unassigned` : undefined },
              { label: 'Analysts Closing Cases', value: String(stats.activeAnalysts), accent: 'text-amber-400' },
            ].map((stat) => (
              <div key={stat.label} className="rounded-xl border border-gray-800/60 bg-gray-900/40 p-5 space-y-4">
                <p className="text-xs font-medium uppercase tracking-wider text-gray-400">{stat.label}</p>
                <p className={clsx('text-3xl font-bold', stat.accent)}>{stat.value}</p>
                {stat.hint ? <p className="text-xs text-gray-500">{stat.hint}</p> : null}
              </div>
            ))}
          </div>

          <div className="rounded-xl border border-gray-800/60 bg-gray-900/40 p-5 space-y-4">
            <div className="flex flex-wrap items-center justify-between gap-3">
              <h2 className="text-lg font-semibold text-white">Analyst Activity</h2>
              <div className="flex items-center gap-3">
                <input
                  type="search"
                  placeholder="Search analyst…"
                  aria-label="Search analyst"
                  value={search}
                  onChange={(e) => setSearch(e.target.value)}
                  className="rounded-lg border border-gray-700/60 bg-gray-900 px-3 py-1.5 text-xs text-gray-200 placeholder-gray-600 focus:outline-none focus:ring-1 focus:ring-blue-500"
                />
                <span className="text-xs font-medium uppercase tracking-wider text-gray-500">Sort</span>
                {SORT_OPTIONS.map((opt) => (
                  <button
                    key={opt.key}
                    type="button"
                    onClick={() => setSortBy(opt.key)}
                    aria-pressed={sortBy === opt.key}
                    className={clsx('rounded-md px-2.5 py-1 text-xs font-medium transition', sortBy === opt.key ? 'bg-white/10 text-white' : 'text-gray-500 hover:text-gray-300')}
                  >
                    {opt.label}
                  </button>
                ))}
              </div>
            </div>

            {stats.rows.length === 0 ? (
              <EmptyState
                icon={EmptyStateIcons.search}
                title="No assigned cases yet"
                description="Once cases are assigned to analysts, and some are resolved or closed, each analyst's activity appears here."
              />
            ) : rows.length === 0 ? (
              <EmptyState
                icon={EmptyStateIcons.search}
                title="No analysts match your search"
                description="Try a different name or clear the search to see all analysts."
                action={
                  <button type="button" onClick={() => setSearch('')} className="rounded-lg bg-gray-800 px-4 py-2 text-sm text-gray-200 hover:bg-gray-700 transition-colors">
                    Clear search
                  </button>
                }
              />
            ) : (
              <div className="overflow-x-auto">
                <table className="w-full text-left text-sm">
                  <thead>
                    <tr className="border-b border-gray-800/60 text-xs uppercase tracking-wider text-gray-500">
                      <th className="pb-3 pr-3 font-medium w-12">#</th>
                      <th className="pb-3 pr-3 font-medium">Analyst</th>
                      <th className="pb-3 pr-3 font-medium text-right">Closed ({days}d)</th>
                      <th className="pb-3 pr-3 font-medium text-right">Avg Time</th>
                      <th className="pb-3 font-medium text-right">Open Now</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-gray-800/40">
                    {rows.map((r, i) => (
                      <tr key={r.analyst} className="transition hover:bg-white/[0.02]">
                        <td className="py-3 pr-3 text-gray-500">{i + 1}</td>
                        <td className="py-3 pr-3 font-medium text-white">{r.analyst}</td>
                        <td className="py-3 pr-3 text-right tabular-nums text-gray-300">{r.closed}</td>
                        <td className="py-3 pr-3 text-right tabular-nums text-gray-300">{formatDuration(r.avgMinutes)}</td>
                        <td className="py-3 text-right tabular-nums text-gray-300">{r.open}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            )}
          </div>
        </>
      )}
    </div>
  );
}
