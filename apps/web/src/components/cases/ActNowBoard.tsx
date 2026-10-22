'use client';

import Link from 'next/link';
import { clsx } from 'clsx';
import type { Case } from '@/lib/api';
import { actNow } from './act-now';

const SEVERITY_TONE: Record<string, string> = {
  critical: 'border-red-500/40 bg-red-500/5 text-red-300',
  high: 'border-orange-500/40 bg-orange-500/5 text-orange-300',
  medium: 'border-yellow-500/30 bg-yellow-500/5 text-yellow-300',
  low: 'border-blue-500/30 bg-blue-500/5 text-blue-300',
};

/**
 * The top of the Cases page: one sentence on what is open and who has it, and the first few cases to work, most severe first, with the ones nobody owns ahead of the ones somebody does.
 * `cases` are the first few in work order, asked for from the API in that order (not picked from the page of cases below, which is only the newest); `totals` are the whole caseload's counts.
 */
export function ActNowBoard({ cases, totals }: { cases: readonly Case[]; totals?: { open: number; unassigned: number } }) {
  const board = actNow(cases, 3, totals);
  return (
    <section aria-label="Act now" data-testid="act-now" className="space-y-3">
      <h2 className="text-lg font-semibold text-gray-100" data-testid="act-now-headline">
        {board.headline}
      </h2>
      {board.top.length > 0 && (
        <div className="grid gap-3 md:grid-cols-3">
          {board.top.map((c, i) => {
            const tone = SEVERITY_TONE[c.severity] ?? SEVERITY_TONE.medium;
            return (
              <Link
                key={c.id}
                href={`/cases/${encodeURIComponent(c.caseNumber ?? c.id)}`}
                className={clsx('block rounded-xl border p-4 transition-colors hover:bg-gray-900/80', tone)}
                data-testid="act-now-card"
              >
                <p className="text-[11px] font-medium uppercase tracking-wide">
                  {i === 0 ? 'Act now · ' : 'Next · '}
                  {c.severity}
                  {c.clientName ? ` · ${c.clientName}` : ''}
                </p>
                <p className="mt-1 text-sm font-semibold text-gray-100">{c.title}</p>
                <p className="mt-1 text-xs text-gray-400">
                  {c.assignee ? `Owner: ${c.assignee.split('@')[0]}` : 'No owner'}
                  {typeof c.alertCount === 'number' && c.alertCount > 0 ? ` · ${c.alertCount} alert${c.alertCount === 1 ? '' : 's'}` : ''}
                </p>
              </Link>
            );
          })}
        </div>
      )}
    </section>
  );
}
