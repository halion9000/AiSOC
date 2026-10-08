'use client';

import { useCallback, useEffect, useState } from 'react';
import { clsx } from 'clsx';
import toast from 'react-hot-toast';
import { EmptyState, EmptyStateIcons } from '@/components/ui/EmptyState';
import { msspApi, type ManagedTenantRow, type MsspOverview } from '@/lib/api';

/**
 * Cross-tenant overview for an MSSP parent workspace.
 *
 * Everything on this page is real. It used to render a hard-coded list of six invented tenants ("Acme Financial", "GlobalRetail Corp", ...) with
 * invented alert counts, ARR and analyst allocation, and an "Export Report" button that only showed a toast. Now the rows are this workspace's
 * actual child tenants; a figure nobody has reported is shown as "—" (never zero, never a guess), and Export downloads what is on screen.
 */

type Filter = 'all' | 'breaching' | 'no-data';

const FILTERS: { id: Filter; label: string }[] = [
  { id: 'all', label: 'All' },
  { id: 'breaching', label: 'Breaching SLA' },
  { id: 'no-data', label: 'No data yet' },
];

/** A figure that may not have been reported: "—" when it is null, never a made-up zero. */
export function figure(value: number | null | undefined, options: { decimals?: number; suffix?: string } = {}): string {
  if (value === null || value === undefined || Number.isNaN(value)) return '—';
  const text = options.decimals !== undefined ? value.toFixed(options.decimals) : String(value);
  return options.suffix ? `${text}${options.suffix}` : text;
}

export function matchesFilter(row: ManagedTenantRow, filter: Filter): boolean {
  if (filter === 'all') return true;
  if (filter === 'no-data') return !row.has_metrics;
  return row.has_metrics && (row.sla_breaches ?? 0) > 0;
}

function csvCell(value: string | number | null): string {
  const text = value === null ? '' : String(value);
  return /[",\n\r]/.test(text) ? `"${text.replace(/"/g, '""')}"` : text;
}

/** The managed-tenants table as CSV. Unreported figures are blank cells, not zeros. */
export function tenantsToCsv(rows: ManagedTenantRow[]): string {
  const header = ['tenant', 'tenant_id', 'has_metrics', 'snapshot_at', 'open_alerts', 'critical_alerts', 'open_cases', 'mttr_minutes', 'sla_breaches', 'connector_count', 'health_score'];
  const lines = rows.map((r) =>
    [r.name, r.tenant_id, r.has_metrics ? 'yes' : 'no', r.snapshot_at, r.open_alerts, r.critical_alerts, r.open_cases, r.mttr_minutes, r.sla_breaches, r.connector_count, r.health_score]
      .map(csvCell)
      .join(','),
  );
  return [header.join(','), ...lines].join('\n') + '\n';
}

function kpiCards(overview: MsspOverview) {
  return [
    { label: 'Managed tenants', value: String(overview.total_tenants), hint: `${overview.tenants_reporting} reporting metrics` },
    { label: 'Open alerts', value: figure(overview.total_open_alerts) },
    { label: 'Critical alerts', value: figure(overview.total_critical_alerts) },
    { label: 'Open cases', value: figure(overview.total_open_cases) },
    { label: 'SLA breaches', value: figure(overview.sla_breach_count) },
    { label: 'Avg MTTR', value: figure(overview.avg_mttr_minutes, { decimals: 0, suffix: ' min' }) },
  ];
}

function snapshotLabel(iso: string | null): string {
  if (!iso) return 'No data yet';
  const when = new Date(iso);
  return Number.isNaN(when.getTime()) ? 'No data yet' : when.toLocaleString();
}

export default function MSSPDashboardView() {
  const [overview, setOverview] = useState<MsspOverview | null>(null);
  const [tenants, setTenants] = useState<ManagedTenantRow[] | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [filter, setFilter] = useState<Filter>('all');

  const load = useCallback(async () => {
    setError(null);
    setTenants(null);
    try {
      const [nextOverview, nextTenants] = await Promise.all([msspApi.overview(), msspApi.tenants()]);
      setOverview(nextOverview);
      setTenants(nextTenants);
    } catch (err) {
      setError(err instanceof Error && err.message ? err.message : 'Could not load managed tenants.');
    }
  }, []);

  useEffect(() => {
    void load();
  }, [load]);

  const visible = (tenants ?? []).filter((row) => matchesFilter(row, filter));

  const exportCsv = () => {
    const blob = new Blob([tenantsToCsv(visible)], { type: 'text/csv;charset=utf-8' });
    const url = URL.createObjectURL(blob);
    const link = document.createElement('a');
    link.href = url;
    link.download = 'managed-tenants.csv';
    document.body.appendChild(link);
    link.click();
    link.remove();
    URL.revokeObjectURL(url);
    toast.success(`Exported ${visible.length} tenant${visible.length === 1 ? '' : 's'}`);
  };

  return (
    <div className="space-y-8 p-6 max-w-7xl mx-auto">
      <div>
        <h1 className="text-2xl font-bold text-white">MSSP Executive Dashboard</h1>
        <p className="text-gray-400 mt-1">Cross-tenant security operations overview</p>
      </div>

      {error ? (
        <EmptyState
          icon={EmptyStateIcons.shield}
          title="Could not load managed tenants"
          description={error}
          action={
            <button type="button" onClick={() => void load()} className="rounded-lg bg-gray-800 px-4 py-2 text-sm text-gray-200 hover:bg-gray-700 transition-colors">
              Try again
            </button>
          }
        />
      ) : tenants === null || overview === null ? (
        <p role="status" className="text-sm text-gray-400">Loading managed tenants…</p>
      ) : (
        <>
          <div className="grid grid-cols-2 md:grid-cols-3 lg:grid-cols-6 gap-4">
            {kpiCards(overview).map((c) => (
              <div key={c.label} className="rounded-xl border border-gray-800/60 bg-gray-900/40 p-4">
                <p className="text-xs text-gray-400 uppercase tracking-wider">{c.label}</p>
                <p className="mt-1 text-2xl font-semibold text-white">{c.value}</p>
                {c.hint ? <p className="mt-1 text-xs text-gray-500">{c.hint}</p> : null}
              </div>
            ))}
          </div>

          <div className="rounded-xl border border-gray-800/60 bg-gray-900/40 overflow-hidden">
            <div className="px-5 py-4 border-b border-gray-800/60 flex flex-wrap items-center justify-between gap-3">
              <h2 className="text-lg font-semibold text-white">Tenant Overview</h2>
              <div className="flex items-center gap-3">
                <span className="text-xs font-medium uppercase tracking-wider text-gray-500">Show</span>
                {FILTERS.map((f) => (
                  <button
                    key={f.id}
                    type="button"
                    onClick={() => setFilter(f.id)}
                    className={clsx('rounded-md px-2.5 py-1 text-xs font-medium transition', filter === f.id ? 'bg-white/10 text-white' : 'text-gray-500 hover:text-gray-300')}
                  >
                    {f.label}
                  </button>
                ))}
                <button
                  type="button"
                  onClick={exportCsv}
                  disabled={visible.length === 0}
                  className="text-sm px-3 py-1.5 rounded-lg bg-blue-600 hover:bg-blue-500 disabled:opacity-40 disabled:hover:bg-blue-600 text-white transition-colors"
                >
                  Export CSV
                </button>
              </div>
            </div>

            {tenants.length === 0 ? (
              <EmptyState
                icon={EmptyStateIcons.shield}
                title="No managed tenants yet"
                description="This workspace has no child tenants. Customer tenants you onboard as an MSSP parent will be listed here."
              />
            ) : visible.length === 0 ? (
              <EmptyState
                icon={EmptyStateIcons.shield}
                title="No tenants match this filter"
                description="Try a different filter to view tenants."
                action={
                  <button type="button" onClick={() => setFilter('all')} className="rounded-lg bg-gray-800 px-4 py-2 text-sm text-gray-200 hover:bg-gray-700 transition-colors">
                    Show all tenants
                  </button>
                }
              />
            ) : (
              <div className="overflow-x-auto">
                <table className="w-full text-sm">
                  <thead>
                    <tr className="border-b border-gray-800/60 text-left text-gray-400">
                      <th className="px-5 py-3 font-medium">Tenant</th>
                      <th className="px-5 py-3 font-medium text-right">Open Alerts</th>
                      <th className="px-5 py-3 font-medium text-right">Critical</th>
                      <th className="px-5 py-3 font-medium text-right">Open Cases</th>
                      <th className="px-5 py-3 font-medium text-right">MTTR (min)</th>
                      <th className="px-5 py-3 font-medium text-right">SLA Breaches</th>
                      <th className="px-5 py-3 font-medium text-right">Connectors</th>
                      <th className="px-5 py-3 font-medium text-right">Health</th>
                      <th className="px-5 py-3 font-medium">Last Snapshot</th>
                    </tr>
                  </thead>
                  <tbody>
                    {visible.map((t) => (
                      <tr key={t.tenant_id} className="border-b border-gray-800/40 hover:bg-gray-800/30 transition-colors">
                        <td className="px-5 py-3 font-medium text-white">{t.name}</td>
                        <td className="px-5 py-3 text-right text-gray-300">{figure(t.open_alerts)}</td>
                        <td className="px-5 py-3 text-right text-gray-300">{figure(t.critical_alerts)}</td>
                        <td className="px-5 py-3 text-right text-gray-300">{figure(t.open_cases)}</td>
                        <td className="px-5 py-3 text-right text-gray-300">{figure(t.mttr_minutes, { decimals: 0 })}</td>
                        <td className={clsx('px-5 py-3 text-right', (t.sla_breaches ?? 0) > 0 ? 'font-medium text-red-400' : 'text-gray-300')}>{figure(t.sla_breaches)}</td>
                        <td className="px-5 py-3 text-right text-gray-300">{figure(t.connector_count)}</td>
                        <td className="px-5 py-3 text-right text-gray-300">{figure(t.health_score, { decimals: 0 })}</td>
                        <td className="px-5 py-3 text-gray-400">{snapshotLabel(t.snapshot_at)}</td>
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
