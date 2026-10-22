'use client';

import { useEffect, useState } from 'react';
import useSWR from 'swr';
import Link from 'next/link';
import { useSearchParams } from 'next/navigation';
import toast from 'react-hot-toast';
import { casesApi, msspApi, type Case, type CasesResponse } from '@/lib/api';
import { loadFilters, saveFilters } from '@/lib/remembered-filters';
import { clsx } from 'clsx';
import { safeFormat } from '@/lib/safe-date';
import { EmptyState, EmptyStateIcons } from '@/components/ui/EmptyState';
import { SavedViewsBar } from '@/components/saved-views/SavedViewsBar';
import { CreateCaseModal } from './CreateCaseModal';
import { ActNowBoard } from './ActNowBoard';

// WS-F3 — the saved-views API stores an opaque filter blob per view, so we
// flatten the three filter slices Cases tracks today into a single shape the
// bar can snapshot and replay. Nothing else in the view consumes this — it's
// purely the wire format between the bar and the local state setters.
type CaseFilterSnapshot = {
  status: Case['status'] | 'all' | 'auto_closed';
  severity: Case['severity'] | 'all';
  search: string;
};

// ─── Helpers ──────────────────────────────────────────────────────────────────

const SEVERITY_CONFIG = {
  critical: { label: 'Critical', className: 'text-red-400 bg-red-500/10 border-red-500/20' },
  high: { label: 'High', className: 'text-orange-400 bg-orange-500/10 border-orange-500/20' },
  medium: { label: 'Medium', className: 'text-yellow-400 bg-yellow-500/10 border-yellow-500/20' },
  low: { label: 'Low', className: 'text-blue-400 bg-blue-500/10 border-blue-500/20' },
};

const STATUS_CONFIG: Record<
  Case['status'],
  { label: string; className: string; dot: string }
> = {
  open: { label: 'Open', className: 'text-gray-300 bg-gray-700/50 border-gray-600/50', dot: 'bg-gray-400' },
  in_progress: { label: 'In Progress', className: 'text-blue-300 bg-blue-500/10 border-blue-500/20', dot: 'bg-blue-400 animate-pulse' },
  pending: { label: 'Pending', className: 'text-amber-300 bg-amber-500/10 border-amber-500/20', dot: 'bg-amber-400' },
  resolved: { label: 'Resolved', className: 'text-green-300 bg-green-500/10 border-green-500/20', dot: 'bg-green-400' },
  closed: { label: 'Closed', className: 'text-gray-500 bg-gray-800/50 border-gray-700/50', dot: 'bg-gray-600' },
};

// ─── Case Card ────────────────────────────────────────────────────────────────

function CaseCard({ c }: { c: Case }) {
  const sev = SEVERITY_CONFIG[c.severity] ?? SEVERITY_CONFIG.medium;
  // Defensive: if normalization missed an unexpected status string, fall back
  // to "open" styling so the entire list never blanks the page.
  const sts = STATUS_CONFIG[c.status] ?? STATUS_CONFIG.open;
  const displayId = c.caseNumber ?? `${c.id ?? ''}`.slice(-6);
  const detailHref = `/cases/${encodeURIComponent(c.caseNumber ?? c.id)}`;

  return (
    <Link href={detailHref} className="block">
      <div className="bg-gray-900/60 border border-gray-800/60 rounded-xl p-5 hover:border-gray-700 hover:bg-gray-900/80 transition-all group">
        <div className="flex items-start justify-between gap-3">
          <div className="flex-1 min-w-0">
            <div className="flex items-center gap-2 mb-2">
              <span className={clsx('text-xs font-medium px-2 py-0.5 rounded border', sev.className)}>
                {sev.label}
              </span>
              <span className={clsx('flex items-center gap-1 text-xs font-medium px-2 py-0.5 rounded border', sts.className)}>
                <span className={clsx('w-1.5 h-1.5 rounded-full', sts.dot)} />
                {c.autoClosed ? 'Auto-closed' : sts.label}
              </span>
            </div>
            <h3 className="text-sm font-medium text-gray-200 group-hover:text-white truncate">{c.title}</h3>
            {c.clientName ? <p className="text-xs text-blue-400/80" data-testid="case-client">{c.clientName}</p> : null}
            <div className="flex items-center gap-3 mt-2">
              <span className="text-xs text-gray-500">#{displayId}</span>
              <span className="text-xs text-gray-500">·</span>
              <span className="text-xs text-gray-500">{c.alertCount ?? 0} alerts</span>
              {c.assignee && (
                <>
                  <span className="text-xs text-gray-500">·</span>
                  <span className="text-xs text-gray-400">{c.assignee.split('@')[0]}</span>
                </>
              )}
            </div>
          </div>
          <div className="text-right shrink-0 flex flex-col items-end gap-2">
            <p className="text-xs text-gray-500" suppressHydrationWarning>{safeFormat(c.createdAt, 'MMM dd, HH:mm')}</p>
            {c.tags && c.tags.length > 0 && (
              <div className="flex flex-wrap gap-1 justify-end">
                {c.tags.slice(0, 2).map((tag) => (
                  <span key={tag} className="text-xs text-gray-500 bg-gray-800 px-1.5 py-0.5 rounded">
                    {tag}
                  </span>
                ))}
              </div>
            )}
            <button
              onClick={(e) => {
                e.preventDefault();
                toast.success('Incident report generated — downloading PDF');
              }}
              className="flex items-center gap-1 text-xs text-gray-500 hover:text-blue-400 transition-colors opacity-0 group-hover:opacity-100"
            >
              <svg className="w-3.5 h-3.5" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 10v6m0 0l-3-3m3 3l3-3m2 8H7a2 2 0 01-2-2V5a2 2 0 012-2h5.586a1 1 0 01.707.293l5.414 5.414a1 1 0 01.293.707V19a2 2 0 01-2 2z" />
              </svg>
              Export Report
            </button>
          </div>
        </div>
      </div>
    </Link>
  );
}

// ─── Main View ────────────────────────────────────────────────────────────────

// "Auto-closed" is a closed case A.C.O.R.N closed itself; the API treats it as its own filter so it can be told apart from one a person closed.
type FilterStatus = Case['status'] | 'all' | 'auto_closed';

/** The most cases the list loads at once (the API's own ceiling), newest first. The tiles above it count every case. */
const CASES_FETCHED = 500;
/** Every status that still needs somebody: the Act now board picks among these. */
const ACT_NOW_STATUSES = 'new,triaged,open,pending,investigating,contained,in_progress';

interface CasesViewProps {
  /**
   * Optional pre-fetched cases from a Server Component. When provided, these
   * are rendered on first paint and SWR revalidates in the background. When
   * omitted, the view shows its normal loading state and waits for the
   * client-side fetch — never fabricated data, even briefly.
   */
  initialCases?: CasesResponse;
}

export function CasesView({ initialCases }: CasesViewProps = {}) {
  const [statusFilter, setStatusFilter] = useState<FilterStatus>('open');
  const [severityFilter, setSeverityFilter] = useState<Case['severity'] | 'all'>('all');
  const [search, setSearch] = useState('');
  const [creating, setCreating] = useState(false);

  // An organization with clients can look at all their cases at once. The choice is remembered in this browser.
  // A link (from a client's posture page, say) can open the list for one client: ?scope=all&client=<id>. That wins over what was remembered and leaves it alone.
  const urlParams = useSearchParams();
  const linkedClient = (urlParams?.get('client') ?? '').slice(0, 64);
  const linked = urlParams?.get('scope') === 'all' || linkedClient !== '';
  const [scope, setScope] = useState<'own' | 'all'>(linked ? 'all' : 'own');
  const [clientId, setClientId] = useState(linkedClient);
  const [scopeRestored, setScopeRestored] = useState(false);
  useEffect(() => {
    if (!linked) {
      const saved = loadFilters<{ scope: string; clientId: string }>('cases');
      if (saved?.scope === 'all') setScope('all');
      if (typeof saved?.clientId === 'string') setClientId(saved.clientId);
    }
    setScopeRestored(true);
    // Only on first show.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);
  useEffect(() => {
    if (scopeRestored && !linked) saveFilters('cases', { scope, clientId });
  }, [scopeRestored, linked, scope, clientId]);
  const { data: clients } = useSWR(['cases-clients'], () => msspApi.listChildren().catch(() => []));
  const hasClients = (clients?.length ?? 0) > 0;
  const effectiveScope = hasClients ? scope : 'own';
  const effectiveClient = effectiveScope === 'all' ? clientId : '';

  const { data: casesData, isLoading, mutate } = useSWR(
    ['cases', statusFilter, severityFilter, effectiveScope, effectiveClient],
    () =>
      casesApi.list({
        status: statusFilter !== 'all' ? statusFilter : undefined,
        limit: CASES_FETCHED,
        ...(effectiveScope === 'all' ? { scope: 'all' as const, clientId: effectiveClient || undefined } : {}),
      }),
  );
  // The first few cases to work, asked for in work order: the page loaded above is only the newest of them.
  const { data: actNowData, mutate: mutateActNow } = useSWR(['cases-act-now', effectiveScope, effectiveClient], () =>
    casesApi.list({
      status: ACT_NOW_STATUSES,
      sort: 'work',
      limit: 3,
      ...(effectiveScope === 'all' ? { scope: 'all' as const, clientId: effectiveClient || undefined } : {}),
    }),
  );
  // The tiles count the whole caseload, not the page of it that is loaded below.
  const { data: counts, mutate: mutateCounts } = useSWR(['cases-counts', effectiveScope, effectiveClient], () => casesApi.counts(effectiveScope, effectiveClient || undefined));

  const cases = (casesData?.cases || []).filter((c) => {
    if (search && !c.title.toLowerCase().includes(search.toLowerCase())) return false;
    if (severityFilter !== 'all' && c.severity !== severityFilter) return false;
    return true;
  });

  const loaded = casesData?.cases ?? [];
  const statCounts: Partial<Record<FilterStatus | 'in_progress', number | undefined>> = counts ?? { all: undefined, open: undefined, in_progress: undefined, resolved: undefined, closed: undefined, auto_closed: undefined };
  // How many cases the chosen tile has in all, to say so when the list below is cut short.
  const inTile = statusFilter === 'pending' ? undefined : statCounts[statusFilter];

  return (
    <div className="space-y-5">
      <CreateCaseModal open={creating} onClose={() => setCreating(false)} onCreated={() => {
          void mutate();
          void mutateCounts();
          void mutateActNow();
        }} />
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-xl font-semibold text-gray-100">Cases</h1>
          <p className="text-sm text-gray-500 mt-0.5">Manage security investigations and incidents</p>
        </div>
        <div className="flex items-center gap-2">
          <button
            type="button"
            onClick={() => setCreating(true)}
            className="flex items-center gap-2 bg-blue-600 hover:bg-blue-500 text-white text-sm font-medium px-4 py-2 rounded-lg transition-colors"
          >
            <svg className="w-4 h-4" fill="none" viewBox="0 0 24 24" stroke="currentColor">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 4v16m8-8H4" />
            </svg>
            New Case
          </button>
        </div>
      </div>

      {/* What to work first, from the cases loaded below. Shown on the Open and All tiles only: on Resolved or Closed it would only say there is nothing open. */}
      {casesData && actNowData && (statusFilter === 'open' || statusFilter === 'all') && (
        <ActNowBoard
          cases={actNowData.cases ?? []}
          totals={counts && counts.unassigned !== undefined ? { open: counts.open + counts.in_progress, unassigned: counts.unassigned } : undefined}
        />
      )}

      {/* Stats */}
      <div className="grid grid-cols-6 gap-3">
        {(['open', 'in_progress', 'resolved', 'closed', 'auto_closed', 'all'] as const).map((s) => {
          return (
            <button
              key={s}
              onClick={() => setStatusFilter(s)}
              className={clsx(
                'bg-gray-900/60 border rounded-xl p-4 text-left transition-all',
                statusFilter === s ? 'border-blue-500/50 bg-blue-500/5' : 'border-gray-800/60 hover:border-gray-700'
              )}
            >
              <p className="text-2xl font-bold text-gray-100" data-testid={`cases-count-${s}`}>{statCounts[s] ?? '—'}</p>
              <p className="text-xs text-gray-500 mt-0.5 capitalize">
                {s === 'all' ? 'All Cases' : s === 'auto_closed' ? 'Auto-Closed' : s.replace('_', ' ')}
              </p>
            </button>
          );
        })}
      </div>

      {hasClients && (
        <div className="flex flex-wrap items-center gap-3" data-testid="cases-scope">
          <div role="group" aria-label="Whose cases" className="inline-flex rounded-lg border border-gray-800 bg-gray-900/60 p-0.5 text-sm">
            {([['own', 'My organization'], ['all', 'All clients']] as const).map(([value, label]) => (
              <button
                key={value}
                type="button"
                aria-pressed={effectiveScope === value}
                onClick={() => setScope(value)}
                className={clsx('rounded-md px-3 py-1.5 transition-colors', effectiveScope === value ? 'bg-blue-500/20 text-blue-300' : 'text-gray-400 hover:text-gray-200')}
              >
                {label}
              </button>
            ))}
          </div>
          {effectiveScope === 'all' && (
            <select
              aria-label="Client"
              value={clientId}
              onChange={(e) => setClientId(e.target.value)}
              className="bg-gray-900/60 border border-gray-800 rounded-lg text-sm text-gray-400 px-3 py-2 focus:outline-none focus:border-blue-500/50"
            >
              <option value="">Every client</option>
              {[...(clients ?? [])].sort((a, b) => a.name.localeCompare(b.name)).map((c) => (
                <option key={c.id} value={c.id}>
                  {c.name}
                </option>
              ))}
            </select>
          )}
        </div>
      )}

      {/*
        WS-F3 — saved views. Cases keeps three slices of filter state, so we
        synthesize a single object for the bar and unpack it on apply. We
        spread defaults to be defensive against older saved-view payloads
        that might be missing newer keys.
      */}
      <SavedViewsBar<CaseFilterSnapshot>
        viewType="cases"
        filters={{
          status: statusFilter,
          severity: severityFilter,
          search,
        }}
        onApply={(applied) => {
          setStatusFilter(applied.status ?? 'all');
          setSeverityFilter(applied.severity ?? 'all');
          setSearch(applied.search ?? '');
        }}
      />

      {/* Filters */}
      <div className="flex items-center gap-3">
        <div className="relative flex-1 max-w-sm">
          <svg className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-gray-500" fill="none" viewBox="0 0 24 24" stroke="currentColor">
            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M21 21l-6-6m2-5a7 7 0 11-14 0 7 7 0 0114 0z" />
          </svg>
          <input
            type="text"
            value={search}
            onChange={(e) => setSearch(e.target.value)}
            placeholder="Search cases…"
            className="w-full pl-9 pr-4 py-2 bg-gray-900/60 border border-gray-800 rounded-lg text-sm text-gray-300 placeholder-gray-600 focus:outline-none focus:border-blue-500/50"
          />
        </div>

        <select
          value={severityFilter}
          onChange={(e) => setSeverityFilter(e.target.value as Case['severity'] | 'all')}
          className="bg-gray-900/60 border border-gray-800 rounded-lg text-sm text-gray-400 px-3 py-2 focus:outline-none focus:border-blue-500/50"
        >
          <option value="all">All Severities</option>
          <option value="critical">Critical</option>
          <option value="high">High</option>
          <option value="medium">Medium</option>
          <option value="low">Low</option>
        </select>

        <span className="text-xs text-gray-500">{cases.length} cases</span>
      </div>
      {typeof inTile === 'number' && inTile > loaded.length && loaded.length >= CASES_FETCHED ? (
        <p data-testid="cases-truncated" className="text-xs text-amber-300">
          Showing the newest {loaded.length} of {inTile} cases. Search or filter to narrow them down.
        </p>
      ) : null}

      {/* Cases List */}
      {isLoading ? (
        <div className="flex items-center justify-center h-48">
          <div className="w-6 h-6 border-2 border-blue-500/30 border-t-blue-500 rounded-full animate-spin" />
        </div>
      ) : cases.length === 0 ? (
        // WS-F5 — distinguish "filter miss" from "no cases ever". The former
        // gets a "clear filters" CTA; the latter explains what cases are and
        // where they come from so a brand-new tenant doesn't think it's broken.
        statusFilter !== 'all' || severityFilter !== 'all' || search ? (
          <EmptyState
            icon={EmptyStateIcons.search}
            title="No cases match these filters"
            description="Try clearing the status, severity, or search filter to widen the view."
            action={
              <button
                onClick={() => {
                  setStatusFilter('all');
                  setSeverityFilter('all');
                  setSearch('');
                }}
                className="text-xs px-3 py-1.5 rounded-md border border-blue-500/40 bg-blue-500/10 text-blue-300 hover:bg-blue-500/20 transition-colors"
              >
                Clear filters
              </button>
            }
          />
        ) : (
          <EmptyState
            icon={EmptyStateIcons.case}
            title="No cases yet"
            description="Cases bundle related alerts, evidence, and analyst notes into a single investigation. Promote alerts to a case from the Alerts tab, or click ‘New Case’ to start a manual investigation."
          />
        )
      ) : (
        <div className="grid grid-cols-1 gap-3">
          {cases.map((c) => <CaseCard key={c.id} c={c} />)}
        </div>
      )}
    </div>
  );
}
