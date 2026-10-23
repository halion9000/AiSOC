'use client';

/**
 * What the connected tools' own detections have raised. Built from the alerts A.C.O.R.N holds (last 30 days), grouped by tool and detection name — it
 * lists only detections that actually fired, not everything a tool could detect.
 */

import { useMemo, useState } from 'react';
import useSWR from 'swr';
import Link from 'next/link';
import { safeDistance } from '@/lib/safe-date';
import { detectionApi } from '@/lib/api';
import { EmptyState } from '@/components/ui/EmptyState';
import { ErrorState } from '@/components/ui/ErrorState';
import { Skeleton } from '@/components/ui/Skeleton';
import VendorBadge from '@/components/mssp/VendorBadge';
import { vendorLabel } from '@/components/mssp/ClientMapping';
import { FilterRow, SortableTh, useTable, type Column } from '@/components/ui/useTable';

type Detection = NonNullable<ReturnType<typeof detectionApi.vendorDetections> extends Promise<infer R> ? R : never>['detections'][number];

const SEVERITIES = ['critical', 'high', 'medium', 'low', 'info'] as const;
const RANK: Record<string, number> = { critical: 4, high: 3, medium: 2, low: 1, info: 0 };

const COLUMNS: Column<Detection>[] = [
  { key: 'tool', label: 'Tool', value: (r) => vendorLabel(r.source), filter: 'none' },
  { key: 'detection', label: 'Detection', value: (r) => r.name, filter: 'text' },
  { key: 'severity', label: 'Severity', value: (r) => r.severity, sortValue: (r) => RANK[r.severity] ?? -1, filter: 'none' },
  { key: 'alerts', label: 'Alerts', value: (r) => r.count, filter: 'min', align: 'right' },
  { key: 'open', label: 'Open', value: (r) => r.open, filter: 'min', align: 'right' },
  { key: 'clients', label: 'Clients', value: (r) => r.clients, filter: 'min', align: 'right' },
  { key: 'last_seen', label: 'Last seen', value: (r) => r.last_seen ?? null, sortValue: (r) => (r.last_seen ? Date.parse(r.last_seen) || null : null), filter: 'none' },
];

const SEVERITY_STYLE: Record<string, string> = {
  critical: 'bg-red-500/15 text-red-300 border-red-500/30',
  high: 'bg-orange-500/15 text-orange-300 border-orange-500/30',
  medium: 'bg-yellow-500/15 text-yellow-300 border-yellow-500/30',
  low: 'bg-blue-500/15 text-blue-300 border-blue-500/30',
  info: 'bg-gray-500/15 text-gray-300 border-gray-500/30',
};

export function VendorDetectionsView() {
  const { data, error, isLoading, mutate } = useSWR('detection:vendor', () => detectionApi.vendorDetections(), {
    revalidateOnFocus: false,
    shouldRetryOnError: false,
  });
  const [tool, setTool] = useState<string>('all');

  const rows = useMemo(() => data?.detections ?? [], [data]);
  const tools = useMemo(() => {
    const counts = new Map<string, number>();
    for (const r of rows) counts.set(r.source, (counts.get(r.source) ?? 0) + r.count);
    return [...counts.entries()].sort((a, b) => b[1] - a[1]);
  }, [rows]);
  const [severity, setSeverity] = useState<string>('all');
  const bySeverity = useMemo(() => {
    const counts = new Map<string, number>();
    for (const r of rows) if (tool === 'all' || r.source === tool) counts.set(r.severity, (counts.get(r.severity) ?? 0) + 1);
    return counts;
  }, [rows, tool]);
  const scoped = useMemo(() => rows.filter((r) => (tool === 'all' || r.source === tool) && (severity === 'all' || r.severity === severity)), [rows, tool, severity]);
  const table = useTable(scoped, COLUMNS, { key: 'severity', dir: 'desc' });
  const shown = table.shown;

  return (
    <div className="mx-auto flex max-w-6xl flex-col gap-5 p-6">
      <header className="flex flex-col gap-1">
        <h1 className="text-2xl font-semibold text-gray-100">Vendor detections</h1>
        <p className="text-sm text-gray-500">
          What the tools you have connected have detected in the last {data?.window_days ?? 30} days, across your clients. Built from real alerts, so a
          detection appears here only once it has fired.
        </p>
      </header>

      {isLoading ? (
        <Skeleton className="h-48 w-full rounded-lg" />
      ) : error ? (
        <ErrorState
          title="Could not load vendor detections"
          description={error instanceof Error ? error.message : 'Request failed'}
          onRetry={() => void mutate()}
        />
      ) : rows.length === 0 ? (
        <EmptyState
          title="No vendor detections yet"
          description="Nothing from your connected tools has raised an alert in the last 30 days. Check that the CORE feed is running on the Connectors page."
          action={
            <Link href="/connectors" className="rounded-md bg-blue-500 px-4 py-2 text-sm font-medium text-white hover:bg-blue-600">
              Open Connectors
            </Link>
          }
        />
      ) : (
        <>
          <div className="flex flex-wrap gap-2" role="group" aria-label="Filter by tool">
            <button
              type="button"
              aria-pressed={tool === 'all'}
              onClick={() => setTool('all')}
              className={`rounded-full border px-3 py-1 text-xs ${tool === 'all' ? 'border-blue-500 bg-blue-500/10 text-blue-300' : 'border-gray-700 text-gray-300 hover:border-gray-500'}`}
            >
              All tools ({rows.reduce((n, r) => n + r.count, 0)})
            </button>
            {tools.map(([source, n]) => (
              <button
                key={source}
                type="button"
                aria-pressed={tool === source}
                onClick={() => setTool(source)}
                className={`flex items-center gap-1.5 rounded-full border px-3 py-1 text-xs ${tool === source ? 'border-blue-500 bg-blue-500/10 text-blue-300' : 'border-gray-700 text-gray-300 hover:border-gray-500'}`}
              >
                <VendorBadge vendor={source} />
                {vendorLabel(source)} ({n})
              </button>
            ))}
          </div>

          <div className="flex flex-wrap items-center gap-2" role="group" aria-label="Filter by severity">
            <span className="text-xs uppercase text-gray-500">Severity</span>
            <button
              type="button"
              aria-pressed={severity === 'all'}
              onClick={() => setSeverity('all')}
              className={`rounded-full border px-3 py-1 text-xs ${severity === 'all' ? 'border-blue-500 bg-blue-500/10 text-blue-300' : 'border-gray-700 text-gray-300 hover:border-gray-500'}`}
            >
              All
            </button>
            {SEVERITIES.map((sev) => (
              <button
                key={sev}
                type="button"
                aria-pressed={severity === sev}
                onClick={() => setSeverity(sev)}
                className={`rounded-full border px-3 py-1 text-xs ${severity === sev ? SEVERITY_STYLE[sev] : 'border-gray-700 text-gray-300 hover:border-gray-500'}`}
              >
                {sev} ({bySeverity.get(sev) ?? 0})
              </button>
            ))}
          </div>

          <div className="overflow-x-auto rounded-lg border border-gray-800">
            <table className="min-w-full divide-y divide-gray-800 text-left text-sm">
              <thead className="bg-gray-900/60 text-xs uppercase text-gray-500">
                <tr>
                  {COLUMNS.map((c) => (
                    <SortableTh key={c.key} col={c} sort={table.sort} onSort={table.toggleSort} />
                  ))}
                </tr>
                <FilterRow columns={COLUMNS} filters={table.filters} setFilter={table.setFilter} choices={table.choices} />
              </thead>
              <tbody className="divide-y divide-gray-800">
                {shown.length === 0 ? (
                  <tr>
                    <td colSpan={COLUMNS.length} className="px-3 py-6 text-center text-gray-500">
                      Nothing matches these filters.
                    </td>
                  </tr>
                ) : null}
                {shown.map((r) => (
                  <tr key={`${r.source}:${r.name}`} className="hover:bg-gray-900/40">
                    <td className="px-3 py-2">
                      <span className="flex items-center gap-2">
                        <VendorBadge vendor={r.source} />
                        <span className="text-gray-300">{vendorLabel(r.source)}</span>
                      </span>
                    </td>
                    <td className="px-3 py-2 text-gray-100">{r.name}</td>
                    <td className="px-3 py-2">
                      <span className={`rounded-full border px-2 py-0.5 text-xs ${SEVERITY_STYLE[r.severity] ?? SEVERITY_STYLE.info}`}>{r.severity}</span>
                    </td>
                    <td className="px-3 py-2 text-right tabular-nums text-gray-200">{r.count}</td>
                    <td className="px-3 py-2 text-right tabular-nums text-gray-200">{r.open}</td>
                    <td className="px-3 py-2 text-right tabular-nums text-gray-200">{r.clients}</td>
                    <td className="px-3 py-2 text-gray-400">
                      {r.last_seen ? safeDistance(r.last_seen, { addSuffix: true }) : '—'}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </>
      )}
    </div>
  );
}
