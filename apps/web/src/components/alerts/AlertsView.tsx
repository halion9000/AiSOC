'use client';

import { useState, useCallback, useEffect } from 'react';
import useSWR from 'swr';
import Link from 'next/link';
import { useSearchParams } from 'next/navigation';
import { alertsApi, connectorsApi, msspApi, type Alert, type AlertFilters, type ConfidenceLabel } from '@/lib/api';
import { clsx } from 'clsx';
import { safeDistance } from '@/lib/safe-date';
import { EntityRiskQueue } from './EntityRiskQueue';
import { InvestigationRail } from './InvestigationRail';
import { EmptyState, EmptyStateIcons } from '@/components/ui/EmptyState';
import { ErrorState } from '@/components/ui/ErrorState';
import { CreateAlertModal } from './CreateAlertModal';
import { SavedViewsBar } from '@/components/saved-views/SavedViewsBar';
import BulkTicketBar from './BulkTicketBar';
import { loadFilters, saveFilters } from '@/lib/remembered-filters';
import { rememberable, restoreFilters } from '@/lib/alert-filter-memory';

// Wave 1 of the AiSOC v6 capability roadmap. The "entities" tab renders the
// rolled-up Risk-Based Alerting queue — alerts contribute time-decayed risk
// points to the entities they touch, and the queue surfaces those entities
// (not the raw alerts) to the analyst. The "alerts" tab keeps the legacy
// alert-centric grid for tenants that prefer it or have RBA disabled.
//
// v1.5 W6 — The alerts tab is now a two-pane layout: the dense grid on the
// left, an Investigation Rail on the right. Selecting a row populates the
// rail with the deterministic narrative + related entities + recent events +
// recommended actions envelope from `GET /alerts/{id}`. The legacy
// `ExplainDrawer` is no longer mounted from this view directly; it has been
// demoted to a "Deep Explain" button inside the rail itself, so analysts
// only burn an LLM call when they explicitly ask for it.
type ViewMode = 'entities' | 'alerts';

// ─── Config ───────────────────────────────────────────────────────────────────

const SEVERITY_CONFIG = {
  critical: { label: 'Critical', dot: 'bg-red-500', text: 'text-red-400', bg: 'bg-red-500/10 border-red-500/20' },
  high: { label: 'High', dot: 'bg-orange-500', text: 'text-orange-400', bg: 'bg-orange-500/10 border-orange-500/20' },
  medium: { label: 'Medium', dot: 'bg-yellow-500', text: 'text-yellow-400', bg: 'bg-yellow-500/10 border-yellow-500/20' },
  low: { label: 'Low', dot: 'bg-blue-500', text: 'text-blue-400', bg: 'bg-blue-500/10 border-blue-500/20' },
  info: { label: 'Info', dot: 'bg-gray-500', text: 'text-gray-400', bg: 'bg-gray-500/10 border-gray-500/20' },
};

const STATUS_CONFIG = {
  new: { label: 'New', color: 'text-purple-400 bg-purple-500/10 border-purple-500/20' },
  triaged: { label: 'Triaged', color: 'text-cyan-400 bg-cyan-500/10 border-cyan-500/20' },
  investigating: { label: 'Investigating', color: 'text-blue-400 bg-blue-500/10 border-blue-500/20' },
  resolved: { label: 'Resolved', color: 'text-green-400 bg-green-500/10 border-green-500/20' },
  false_positive: { label: 'False Positive', color: 'text-gray-400 bg-gray-500/10 border-gray-500/20' },
};

// Wave 1 — Detection confidence chip rendered inline in the alert grid so an
// analyst can spot low-confidence alerts at a glance without clicking through.
// Click-through still goes to AlertDetailView for the full evidence chain.
const CONFIDENCE_ROW_CONFIG: Record<ConfidenceLabel, { label: string; cls: string }> = {
  high: { label: 'HIGH', cls: 'text-emerald-400 bg-emerald-500/10 border-emerald-500/20' },
  medium: { label: 'MED', cls: 'text-yellow-400 bg-yellow-500/10 border-yellow-500/20' },
  low: { label: 'LOW', cls: 'text-gray-400 bg-gray-500/10 border-gray-500/20' },
};

function ConfidencePill({ label }: { label: ConfidenceLabel }) {
  const cfg = CONFIDENCE_ROW_CONFIG[label];
  return (
    <span
      className={clsx('text-[10px] font-mono font-medium px-1.5 py-0.5 rounded border shrink-0', cfg.cls)}
      title={`Detection confidence: ${cfg.label}`}
    >
      Conf: {cfg.label}
    </span>
  );
}

// ─── Sub-components ───────────────────────────────────────────────────────────

function SeverityDot({ severity }: { severity: string }) {
  const cfg = SEVERITY_CONFIG[severity as keyof typeof SEVERITY_CONFIG] || SEVERITY_CONFIG.info;
  return <span className={clsx('w-2 h-2 rounded-full shrink-0', cfg.dot)} />;
}

function SeverityBadge({ severity }: { severity: string }) {
  const cfg = SEVERITY_CONFIG[severity as keyof typeof SEVERITY_CONFIG] || SEVERITY_CONFIG.info;
  return (
    <span className={clsx('text-xs px-2 py-0.5 rounded border', cfg.text, cfg.bg)}>
      {cfg.label}
    </span>
  );
}

function StatusBadge({ status }: { status: string }) {
  const cfg = STATUS_CONFIG[status as keyof typeof STATUS_CONFIG] || STATUS_CONFIG.new;
  return (
    <span className={clsx('text-xs px-2 py-0.5 rounded border', cfg.color)}>
      {cfg.label}
    </span>
  );
}

/** The CORE-fed tools to offer in the Source filter: one per `core_feed` connector, named without the " (via CORE)" suffix. */
export function sourceOptions(connectors: { type: string; name: string; connectorConfig?: Record<string, unknown>; config?: Record<string, unknown> }[]) {
  const seen = new Map<string, string>();
  for (const c of connectors) {
    if (c.type !== 'core_feed') continue;
    const vendor = (c.connectorConfig ?? c.config)?.vendor;
    if (typeof vendor === 'string' && vendor && !seen.has(vendor)) seen.set(vendor, c.name.replace(/\s*\(via CORE\)\s*$/, ''));
  }
  return [...seen.entries()].map(([vendor, label]) => ({ vendor, label })).sort((a, b) => a.label.localeCompare(b.label));
}

export function FiltersBar({
  filters,
  onChange,
  total,
}: {
  filters: AlertFilters;
  onChange: (f: AlertFilters) => void;
  total: number;
}) {
  // The tools CORE forwards from (Huntress, Petra, ...), so alerts can be narrowed to one of them. Hidden when there are none.
  const { data: connectorData } = useSWR('alert-source-options', () => connectorsApi.list(), { shouldRetryOnError: false });
  const sources = sourceOptions(connectorData?.connectors ?? []);
  // An MSSP parent's client tenants, so the list can be narrowed to one client. Hidden when there are none.
  const { data: clientData } = useSWR('alert-client-options', () => msspApi.listChildren(), { shouldRetryOnError: false });
  const clients = Array.isArray(clientData) ? [...clientData].sort((a, b) => a.name.localeCompare(b.name)) : [];
  const severities = ['all', 'critical', 'high', 'medium', 'low', 'info'] as const;
  // "open" is every alert that is not finished (resolved, closed or a false positive); "all" has no status filter at all.
  const statuses = ['open', 'new', 'investigating', 'resolved', 'false_positive', 'all'] as const;

  // The box is typed into freely; the list is only re-queried a moment after typing stops (and straight away on Enter or clear).
  const [text, setText] = useState(filters.search ?? '');
  const [seenSearch, setSeenSearch] = useState(filters.search);
  if (seenSearch !== filters.search) {
    // The filter was changed from outside (for example Clear filters): show it.
    setSeenSearch(filters.search);
    setText(filters.search ?? '');
  }
  useEffect(() => {
    const wanted = text.trim() || undefined;
    if (wanted === (filters.search || undefined)) return;
    const timer = setTimeout(() => onChange({ ...filters, search: wanted, page: 1 }), 350);
    return () => clearTimeout(timer);
  }, [text, filters, onChange]);

  return (
    <div className="flex items-center gap-3 flex-wrap py-3 px-4 bg-gray-900/40 border border-gray-800/60 rounded-xl">
      <input
        type="search"
        aria-label="Search alerts"
        placeholder="Search alerts, devices or clients"
        value={text}
        onChange={(e) => setText(e.target.value)}
        onKeyDown={(e) => {
          if (e.key === 'Enter') onChange({ ...filters, search: text.trim() || undefined, page: 1 });
        }}
        className="text-xs bg-gray-900 border border-gray-700 text-gray-200 placeholder-gray-500 rounded-lg px-3 py-1 w-64"
      />
      <div className="w-px h-4 bg-gray-700" />
      <div className="flex items-center gap-1">
        {severities.map((s) => (
          <button
            key={s}
            onClick={() => onChange({ ...filters, severity: s === 'all' ? undefined : s, page: 1 })}
            className={clsx(
              'text-xs px-2.5 py-1 rounded-lg transition-colors capitalize',
              (s === 'all' && !filters.severity) || filters.severity === s
                ? 'bg-blue-600 text-white'
                : 'text-gray-500 hover:text-gray-300 hover:bg-gray-800/60'
            )}
          >
            {s}
          </button>
        ))}
      </div>
      <div className="w-px h-4 bg-gray-700" />
      <div className="flex items-center gap-1">
        {statuses.map((s) => (
          <button
            key={s}
            onClick={() => onChange({ ...filters, status: s === 'all' ? undefined : s, page: 1 })}
            className={clsx(
              'text-xs px-2.5 py-1 rounded-lg transition-colors capitalize',
              (s === 'all' && !filters.status) || filters.status === s
                ? 'bg-gray-700 text-gray-200'
                : 'text-gray-500 hover:text-gray-300 hover:bg-gray-800/60'
            )}
          >
            {s === 'all' ? 'All status' : s === 'open' ? 'Open all' : s.replace('_', ' ')}
          </button>
        ))}
      </div>
      {sources.length > 0 && (
        <>
          <div className="w-px h-4 bg-gray-700" />
          <select
            aria-label="Source"
            value={filters.source ?? ''}
            onChange={(e) => onChange({ ...filters, source: e.target.value || undefined, page: 1 })}
            className="text-xs bg-gray-900 border border-gray-700 text-gray-300 rounded-lg px-2 py-1"
          >
            <option value="">All sources</option>
            {sources.map((o) => (
              <option key={o.vendor} value={o.vendor}>
                {o.label}
              </option>
            ))}
          </select>
        </>
      )}
      {clients.length > 0 && (
        <>
          <div className="w-px h-4 bg-gray-700" />
          <select
            aria-label="Client"
            value={filters.clientId ?? ''}
            onChange={(e) => onChange({ ...filters, clientId: e.target.value || undefined, page: 1 })}
            className="text-xs bg-gray-900 border border-gray-700 text-gray-300 rounded-lg px-2 py-1"
          >
            <option value="">All clients</option>
            {clients.map((c) => (
              <option key={c.id} value={c.id}>
                {c.name}
              </option>
            ))}
          </select>
        </>
      )}
      <div className="w-px h-4 bg-gray-700" />
      <select
        aria-label="Halo ticket"
        value={filters.ticket ?? ''}
        onChange={(e) => onChange({ ...filters, ticket: (e.target.value || undefined) as AlertFilters['ticket'], page: 1 })}
        className="text-xs bg-gray-900 border border-gray-700 text-gray-300 rounded-lg px-2 py-1"
      >
        <option value="">Any Halo ticket</option>
        <option value="linked">Has a Halo ticket</option>
        <option value="none">No Halo ticket</option>
      </select>
      {filters.device && (
        <button
          type="button"
          aria-label={`Remove device filter ${filters.device}`}
          onClick={() => onChange({ ...filters, device: undefined, page: 1 })}
          className="text-xs px-2 py-1 rounded-lg border border-blue-500/40 bg-blue-500/10 text-blue-300 hover:bg-blue-500/20"
        >
          Device: {filters.device} ×
        </button>
      )}
      <span className="ml-auto text-xs text-gray-600">{total} total</span>
    </div>
  );
}

// v1.5 W6 — AlertRow is now a *selection* affordance. Plain click selects the
// row (which populates the Investigation Rail to the right); modifier-clicks
// or middle-clicks still navigate to the full detail page so we don't break
// "open in new tab" muscle memory. The row gets a left-border highlight
// when selected so the analyst can see at a glance which alert the rail is
// describing.
export function AlertRow({
  alert,
  selected,
  onSelect,
}: {
  alert: Alert;
  selected: boolean;
  onSelect: (id: string) => void;
}) {
  return (
    <Link
      href={`/alerts/${alert.id}`}
      onClick={(e) => {
        // Modifier or middle-click → keep the native Link behaviour so
        // analysts can open the alert in a new tab/window. Only a plain
        // left-click is hijacked for in-pane selection.
        if (e.metaKey || e.ctrlKey || e.shiftKey || e.altKey || e.button === 1) return;
        e.preventDefault();
        onSelect(alert.id);
      }}
      aria-current={selected ? 'true' : undefined}
      className={clsx(
        'flex items-center gap-4 px-4 py-3 transition-colors border-b border-gray-800/40 last:border-0 border-l-2',
        selected
          ? 'border-l-blue-500 bg-blue-500/5 hover:bg-blue-500/10'
          : 'border-l-transparent hover:bg-gray-800/20',
      )}
    >
      <SeverityDot severity={alert.severity} />

      <div className="flex-1 min-w-0">
        <div className="flex items-center gap-2">
          <p className="text-sm text-gray-200 truncate hover:text-white">{alert.title}</p>
          {alert.mitreAttack && alert.mitreAttack.length > 0 && (
            <span className="text-xs bg-orange-500/10 text-orange-400 border border-orange-500/20 px-1.5 py-0.5 rounded shrink-0">
              {alert.mitreAttack[0].techniqueId}
            </span>
          )}
        </div>
        <div className="flex items-center gap-2 mt-0.5">
          {alert.clientName && (
            <>
              <span className="text-xs text-blue-400/80">{alert.clientName}</span>
              <span className="text-gray-700">·</span>
            </>
          )}
          <span className="text-xs text-gray-600">{alert.source}</span>
          {alert.device && (
            <>
              <span className="text-gray-700">·</span>
              <span className="text-xs text-gray-500 truncate" data-testid="alert-device">{alert.device}</span>
            </>
          )}
          {alert.assignee && (
            <>
              <span className="text-gray-700">·</span>
              <span className="text-xs text-gray-600">{alert.assignee}</span>
            </>
          )}
        </div>
      </div>

      <div className="flex items-center gap-2 shrink-0">
        {alert.confidenceLabel && <ConfidencePill label={alert.confidenceLabel} />}
        <SeverityBadge severity={alert.severity} />
        <StatusBadge status={alert.status} />
        <span className="text-xs text-gray-600 w-24 text-right" suppressHydrationWarning>
          {safeDistance(alert.createdAt, { addSuffix: true })}
        </span>
      </div>
    </Link>
  );
}

// ─── Main View ────────────────────────────────────────────────────────────────

/** The list's starting filters from the address: ?device=HOST narrows to a machine, ?status=all|open|new|... picks a status tab (the default is Open all). */
export function filtersFromUrl(params: URLSearchParams | null): AlertFilters {
  const read = (name: string): string => {
    const fromRouter = params?.get(name);
    if (fromRouter != null) return fromRouter;
    return typeof window === 'undefined' ? '' : (new URLSearchParams(window.location.search).get(name) ?? '');
  };
  const device = read('device').trim() || undefined;
  const client = read('client').trim().slice(0, 64) || undefined;
  const severityWanted = read('severity');
  const severity = ['critical', 'high', 'medium', 'low', 'info'].includes(severityWanted) ? severityWanted : undefined;
  const ticketWanted = read('ticket');
  const ticket = ticketWanted === 'none' || ticketWanted === 'linked' ? ticketWanted : undefined;
  const wanted = read('status');
  let status: string | undefined = 'open';
  if (wanted === 'all') status = undefined;
  else if (['open', 'new', 'investigating', 'resolved', 'false_positive'].includes(wanted)) status = wanted;
  return { page: 1, pageSize: 25, ...(status ? { status } : {}), ...(device ? { device } : {}), ...(client ? { clientId: client } : {}), ...(severity ? { severity } : {}), ...(ticket ? { ticket } : {}) };
}

export function AlertsView() {
  // Reading window.location during a client-side navigation gives the PREVIOUS page's address, so the router's parameters are used.
  const urlParams = useSearchParams();
  const urlKey = `${urlParams?.get('device') ?? ''}|${urlParams?.get('status') ?? ''}|${urlParams?.get('client') ?? ''}|${urlParams?.get('severity') ?? ''}|${urlParams?.get('ticket') ?? ''}`;
  const [filters, setFilters] = useState<AlertFilters>(() => filtersFromUrl(urlParams));
  const [seenUrlKey, setSeenUrlKey] = useState(urlKey);
  if (seenUrlKey !== urlKey) {
    // Another link to this page while it is already open (for example from a device row).
    setSeenUrlKey(urlKey);
    setFilters(filtersFromUrl(urlParams));
  }
  // The filters picked last time come back, unless this visit came from a link that names a device or a status (those links must open exactly what they say).
  const deepLinked = !!(urlParams?.get('device') || urlParams?.get('status') || urlParams?.get('client') || urlParams?.get('severity') || urlParams?.get('ticket'));
  const [filtersRestored, setFiltersRestored] = useState(false);
  useEffect(() => {
    if (!deepLinked) {
      const saved = loadFilters<Record<string, unknown>>('alerts');
      if (saved) setFilters((prev) => restoreFilters(prev, saved));
    }
    setFiltersRestored(true);
    // Only on first show: later changes of the address are handled above.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);
  useEffect(() => {
    if (filtersRestored && !deepLinked) saveFilters('alerts', rememberable(filters));
  }, [filtersRestored, deepLinked, filters]);
  // Default to the entity-centric queue — that's the whole point of Wave 1's
  // RBA work. Analysts can flip back to the raw alert grid for legacy
  // workflows or when triaging a specific alert ID.
  const [viewMode, setViewMode] = useState<ViewMode>('alerts');
  const [createOpen, setCreateOpen] = useState(false);

  const { data, error, isLoading, mutate } = useSWR(
    ['alerts', filters],
    () => alertsApi.list(filters),
    {
      refreshInterval: 30000,
    }
  );

  const handleFilterChange = useCallback((newFilters: AlertFilters) => {
    setFilters(newFilters);
  }, []);

  const alerts = data?.alerts || [];
  const total = data?.total || 0;
  const scopeTotal = data?.summary?.total ?? total;

  // The tally comes from the server and covers every alert in scope; counting the rows on this page would change with the filters and the page size.
  const critCount = data?.summary?.critical ?? alerts.filter((a) => a.severity === 'critical').length;
  const highCount = data?.summary?.high ?? alerts.filter((a) => a.severity === 'high').length;
  const newCount = data?.summary?.unresolved ?? alerts.filter((a) => a.status === 'new').length;
  const noTicketCount = data?.summary?.noTicket;

  return (
    <div className="space-y-4">
      <CreateAlertModal open={createOpen} onClose={() => setCreateOpen(false)} onCreated={() => void mutate()} />
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-xl font-semibold text-gray-100">Alerts</h1>
          <p className="text-sm text-gray-500 mt-0.5">
            {viewMode === 'entities'
              ? 'Risk-Based Alerting · entity-centric triage queue'
              : 'Real-time security event monitoring and triage'}
          </p>
        </div>
        <div className="flex items-center gap-2">
          <div
            role="tablist"
            aria-label="View mode"
            className="inline-flex items-center bg-gray-900/60 border border-gray-800/60 rounded-lg p-0.5"
          >
            <button
              type="button"
              role="tab"
              aria-selected={viewMode === 'alerts'}
              onClick={() => setViewMode('alerts')}
              className={clsx(
                'text-xs px-3 py-1.5 rounded-md transition-colors',
                viewMode === 'alerts'
                  ? 'bg-gray-700 text-gray-100'
                  : 'text-gray-400 hover:text-gray-200',
              )}
            >
              Alerts
            </button>
            <button
              type="button"
              role="tab"
              aria-selected={viewMode === 'entities'}
              onClick={() => setViewMode('entities')}
              className={clsx(
                'text-xs px-3 py-1.5 rounded-md transition-colors',
                viewMode === 'entities'
                  ? 'bg-gray-700 text-gray-100'
                  : 'text-gray-400 hover:text-gray-200',
              )}
            >
              Entities
            </button>
          </div>
          <div className="flex items-center gap-2">
            <button
              type="button"
              onClick={() => setCreateOpen(true)}
              className="bg-blue-600 hover:bg-blue-500 text-white text-sm px-4 py-2 rounded-lg transition-colors"
            >
              + Create Alert
            </button>
          </div>
        </div>
      </div>

      {viewMode === 'entities' ? (
        <EntityRiskQueue />
      ) : (
        <AlertsTable
          alerts={alerts}
          total={total}
          scopeTotal={scopeTotal}
          critCount={critCount}
          highCount={highCount}
          newCount={newCount}
          noTicketCount={noTicketCount}
          filters={filters}
          isLoading={isLoading}
          error={error}
          onFilterChange={handleFilterChange}
          onChanged={() => void mutate()}
        />
      )}
    </div>
  );
}

// ─── Legacy alert-centric grid (extracted for the view-mode toggle) ──────────

function AlertsTable({
  alerts,
  total,
  scopeTotal,
  critCount,
  highCount,
  newCount,
  noTicketCount,
  filters,
  isLoading,
  error,
  onFilterChange,
  onChanged,
}: {
  alerts: Alert[];
  total: number;
  scopeTotal: number;
  critCount: number;
  highCount: number;
  newCount: number;
  noTicketCount?: number;
  filters: AlertFilters;
  isLoading: boolean;
  error: unknown;
  onFilterChange: (f: AlertFilters) => void;
  onChanged: () => void;
}) {
  // v1.5 W6 — Selection lives at the AlertsTable level (not AlertsView)
  // because the rail is only rendered inside the "alerts" view mode.
  // Switching to the entities tab unmounts this state cleanly, which is
  // what we want — the rail is alert-scoped, not entity-scoped.
  const [selectedAlertId, setSelectedAlertId] = useState<string | null>(null);

  return (
    <div className="space-y-4">
      {/* Stats strip (full width) */}
      <div className="grid grid-cols-5 gap-3">
        {[
          { label: 'Total', value: scopeTotal, color: 'text-gray-200' },
          { label: 'Critical', value: critCount, color: 'text-red-400' },
          { label: 'High', value: highCount, color: 'text-orange-400' },
          { label: 'Unresolved', value: newCount, color: 'text-purple-400' },
        ].map((stat) => (
          <div key={stat.label} className="bg-gray-900/60 border border-gray-800/60 rounded-xl px-4 py-3">
            <p className="text-xs text-gray-500">{stat.label}</p>
            <p className={clsx('text-2xl font-bold mt-1', stat.color)}>{stat.value}</p>
          </div>
        ))}
        <button
          type="button"
          data-testid="no-ticket-tile"
          aria-pressed={filters.ticket === 'none'}
          title="Open alerts with no HaloPSA ticket linked. Click to list them."
          onClick={() => onFilterChange({ ...filters, ticket: filters.ticket === 'none' ? undefined : 'none', status: filters.ticket === 'none' ? filters.status : 'open', page: 1 })}
          className={clsx('text-left rounded-xl px-4 py-3 border', filters.ticket === 'none' ? 'border-amber-500 bg-amber-500/10' : 'bg-gray-900/60 border-gray-800/60')}
        >
          <p className="text-xs text-gray-500">No Halo ticket</p>
          <p className="text-2xl font-bold mt-1 text-amber-300">{noTicketCount ?? '—'}</p>
        </button>
      </div>

      {/*
        WS-F3 — saved views. The bar reads/writes filters straight through
        ``onFilterChange`` so we don't need a parallel state path. We reset
        ``page`` to 1 when applying a preset because saved pagination would
        be confusing — analysts expect to start from the top.
      */}
      <SavedViewsBar<AlertFilters>
        viewType="alerts"
        filters={filters}
        onApply={(applied) =>
          onFilterChange({
            ...applied,
            page: 1,
            pageSize: filters.pageSize ?? 25,
          })
        }
      />

      <FiltersBar filters={filters} onChange={onFilterChange} total={total} />

      {/*
        v1.5 W6 — two-pane layout. On wide screens the queue takes the left
        seven cols and the Investigation Rail takes the right five; on narrow
        screens they stack so the rail sits beneath the queue rather than
        squeezing the columns into illegibility. The rail is `sticky` so it
        stays in view while the analyst scrolls the queue.
      */}
      <div className="grid grid-cols-1 xl:grid-cols-12 gap-4">
        <div className="xl:col-span-7 space-y-4">
          <AlertsTableGrid
            alerts={alerts}
            isLoading={isLoading}
            error={error}
            filters={filters}
            selectedAlertId={selectedAlertId}
            onSelect={setSelectedAlertId}
            onFilterChange={onFilterChange}
            onChanged={onChanged}
          />
          <AlertsPagination
            alerts={alerts}
            total={total}
            filters={filters}
            onFilterChange={onFilterChange}
          />
        </div>
        <div className="xl:col-span-5">
          <div className="xl:sticky xl:top-4 xl:max-h-[calc(100vh-7rem)] xl:overflow-hidden xl:flex xl:flex-col">
            <InvestigationRail
              alertId={selectedAlertId}
              onClose={() => setSelectedAlertId(null)}
            />
          </div>
        </div>
      </div>
    </div>
  );
}

// ─── Queue grid (split out from AlertsTable so the two-pane shell stays lean) ─

export function AlertsTableGrid({
  alerts,
  isLoading,
  error,
  filters,
  selectedAlertId,
  onSelect,
  onFilterChange,
  onChanged,
}: {
  alerts: Alert[];
  isLoading: boolean;
  error: unknown;
  filters: AlertFilters;
  selectedAlertId: string | null;
  onSelect: (id: string) => void;
  onFilterChange: (f: AlertFilters) => void;
  onChanged: () => void;
}) {
  // Ticked rows (for linking one ticket to several alerts). Only ids still on this page count, so paging or filtering never leaves a hidden alert selected.
  const [ticked, setTicked] = useState<Set<string>>(new Set());
  const tickedIds = alerts.filter((a) => ticked.has(a.id)).map((a) => a.id);
  const toggle = (id: string) =>
    setTicked((prev) => {
      const next = new Set(prev);
      if (next.has(id)) next.delete(id);
      else next.add(id);
      return next;
    });
  return (
    <div className="bg-gray-900/60 border border-gray-800/60 rounded-xl overflow-hidden">
      <BulkTicketBar alertIds={tickedIds} onDone={onChanged} onClear={() => setTicked(new Set())} />
      <div className="flex items-center px-4 py-2 border-b border-gray-800/60 bg-gray-900/80">
        <span className="text-xs text-gray-500 flex-1 pl-2">ALERT</span>
        <span className="text-xs text-gray-500 w-20">CONFIDENCE</span>
        <span className="text-xs text-gray-500 w-20">SEVERITY</span>
        <span className="text-xs text-gray-500 w-24">STATUS</span>
        <span className="text-xs text-gray-500 w-24 text-right">TIME</span>
      </div>

      {isLoading ? (
        <div className="flex items-center justify-center h-32">
          <div className="w-6 h-6 border-2 border-blue-500 border-t-transparent rounded-full animate-spin" />
        </div>
      ) : error ? (
        <div className="p-4">
          <ErrorState
            title="Couldn't load alerts"
            description="The alerts feed didn't respond. Check the API service or try again."
            error={error}
          />
        </div>
      ) : alerts.length === 0 ? (
        <div className="p-4">
          {/*
            WS-F5 — distinguish "no data at all" from "filtered out". The
            filter-aware copy is the difference between an analyst thinking
            "the system is broken" and "I should clear my filters".
          */}
          {filters.severity || filters.status || filters.source || filters.clientId || filters.device || filters.search ? (
            <EmptyState
              icon={EmptyStateIcons.search}
              title="No alerts match these filters"
              description="Try clearing the search text or the severity, status or source filter to widen the search."
              action={
                <button
                  onClick={() => onFilterChange({ page: 1, pageSize: filters.pageSize ?? 25 })}
                  className="text-xs px-3 py-1.5 rounded-md border border-blue-500/40 bg-blue-500/10 text-blue-300 hover:bg-blue-500/20 transition-colors"
                >
                  Clear filters
                </button>
              }
            />
          ) : (
            <EmptyState
              icon={EmptyStateIcons.alert}
              title="No alerts yet"
              description="Once a connector ingests events that trip a detection, alerts will appear here. Connect a data source from Settings → Connectors to start streaming."
            />
          )}
        </div>
      ) : (
        <div>
          {alerts.map((alert) => (
            <div key={alert.id} className="flex items-center">
              <input
                type="checkbox"
                aria-label={`Select alert ${alert.title}`}
                checked={ticked.has(alert.id)}
                onChange={() => toggle(alert.id)}
                className="ml-3 shrink-0"
              />
              <div className="min-w-0 flex-1">
                <AlertRow alert={alert} selected={selectedAlertId === alert.id} onSelect={onSelect} />
              </div>
            </div>
          ))}
        </div>
      )}
    </div>
  );
}

function AlertsPagination({
  alerts,
  total,
  filters,
  onFilterChange,
}: {
  alerts: Alert[];
  total: number;
  filters: AlertFilters;
  onFilterChange: (f: AlertFilters) => void;
}) {
  return (
    <div className="flex items-center justify-between text-xs text-gray-500">
      <span>Showing {alerts.length} of {total} alerts</span>
      <div className="flex items-center gap-1">
        <button
          onClick={() => onFilterChange({ ...filters, page: Math.max(1, (filters.page || 1) - 1) })}
          disabled={(filters.page || 1) <= 1}
          className="px-2 py-1 rounded bg-gray-800 hover:bg-gray-700 disabled:opacity-40 disabled:cursor-not-allowed"
        >
          Prev
        </button>
        <span className="px-2">Page {filters.page || 1}</span>
        <button
          onClick={() => onFilterChange({ ...filters, page: (filters.page || 1) + 1 })}
          disabled={alerts.length < (filters.pageSize || 25)}
          className="px-2 py-1 rounded bg-gray-800 hover:bg-gray-700 disabled:opacity-40 disabled:cursor-not-allowed"
        >
          Next
        </button>
      </div>
    </div>
  );
}
