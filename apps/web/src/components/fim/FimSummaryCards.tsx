'use client';

import clsx from 'clsx';
import type { FimSummary } from '@/lib/osquery-api';

interface Props {
  summary: FimSummary;
}

const ACTION_STYLES: Record<string, string> = {
  CREATED: 'bg-emerald-50 text-emerald-700 border-emerald-200',
  DELETED: 'bg-red-500/10 text-red-300 border-red-500/30',
  UPDATED: 'bg-amber-500/10 text-amber-300 border-amber-500/30',
  ATTRIBUTES_MODIFIED: 'bg-sky-50 text-sky-700 border-sky-200',
};

export function FimSummaryCards({ summary }: Props) {
  return (
    <div className="space-y-4">
      {/* Top-level KPIs */}
      <div className="grid grid-cols-2 gap-3 sm:grid-cols-4">
        <KpiCard label="Total Events" value={summary.total_events.toLocaleString()} />
        <KpiCard label="Active Nodes" value={summary.active_nodes.toLocaleString()} />
        <KpiCard
          label="Unique Paths"
          value={summary.top_paths.length.toLocaleString()}
          note="(top 10 shown)"
        />
        <KpiCard
          label="Action Types"
          value={summary.by_action.length.toLocaleString()}
        />
      </div>

      {/* By-action breakdown */}
      {summary.by_action.length > 0 && (
        <div>
          <h3 className="mb-2 text-xs font-semibold uppercase tracking-wider text-gray-500">
            Events by Action
          </h3>
          <div className="flex flex-wrap gap-2">
            {summary.by_action.map((a) => (
              <span
                key={a.action}
                className={clsx(
                  'inline-flex items-center gap-1.5 rounded-full border px-3 py-1 text-sm font-medium',
                  ACTION_STYLES[a.action] ?? 'bg-gray-900/40 text-gray-300 border-gray-800',
                )}
              >
                {a.action}
                <span className="rounded-full bg-gray-900/60 px-1.5 py-0.5 text-xs font-bold">
                  {a.count.toLocaleString()}
                </span>
              </span>
            ))}
          </div>
        </div>
      )}

      {/* Top paths */}
      {summary.top_paths.length > 0 && (
        <div>
          <h3 className="mb-2 text-xs font-semibold uppercase tracking-wider text-gray-500">
            Top File Paths
          </h3>
          <div className="overflow-hidden rounded-lg border border-gray-800 bg-gray-900/60">
            {summary.top_paths.map((p, i) => (
              <div
                key={p.target_path}
                className={clsx(
                  'flex items-center justify-between px-3 py-2 text-sm',
                  i !== summary.top_paths.length - 1 && 'border-b border-gray-800/60',
                )}
              >
                <span className="truncate font-mono text-xs text-gray-300">{p.target_path}</span>
                <span className="ml-4 shrink-0 rounded bg-gray-800 px-2 py-0.5 text-xs font-semibold text-gray-400">
                  {p.count.toLocaleString()}
                </span>
              </div>
            ))}
          </div>
        </div>
      )}
    </div>
  );
}

function KpiCard({
  label,
  value,
  note,
}: {
  label: string;
  value: string;
  note?: string;
}) {
  return (
    <div className="rounded-xl border border-gray-800 bg-gray-900/60 px-4 py-3 shadow-sm">
      <p className="text-xs font-medium text-gray-500">{label}</p>
      <p className="mt-1 text-2xl font-bold text-white">{value}</p>
      {note && <p className="mt-0.5 text-xs text-gray-400">{note}</p>}
    </div>
  );
}
