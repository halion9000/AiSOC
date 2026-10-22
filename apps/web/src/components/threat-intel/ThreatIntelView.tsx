'use client';

import { useState } from 'react';
import Link from 'next/link';
import useSWR from 'swr';
import {
  alertsApi,
  threatIntelApi,
  type AlertSeverity,
  type IndicatorType,
  type ThreatIndicator,
} from '@/lib/api';
import { clsx } from 'clsx';
import { safeFormat } from '@/lib/safe-date';
import { EmptyState, EmptyStateIcons } from '@/components/ui/EmptyState';

// ─── Type badges ──────────────────────────────────────────────────────────────

const TYPE_CONFIG: Record<IndicatorType, { label: string; color: string }> = {
  ip: { label: 'IP', color: 'text-purple-400 bg-purple-500/10 border-purple-500/20' },
  domain: { label: 'Domain', color: 'text-blue-400 bg-blue-500/10 border-blue-500/20' },
  hash: { label: 'Hash', color: 'text-yellow-400 bg-yellow-500/10 border-yellow-500/20' },
  url: { label: 'URL', color: 'text-orange-400 bg-orange-500/10 border-orange-500/20' },
  email: { label: 'Email', color: 'text-green-400 bg-green-500/10 border-green-500/20' },
};

const SEVERITY_CONFIG: Record<AlertSeverity, string> = {
  critical: 'text-red-400 bg-red-500/10 border-red-500/20',
  high: 'text-orange-400 bg-orange-500/10 border-orange-500/20',
  medium: 'text-yellow-400 bg-yellow-500/10 border-yellow-500/20',
  low: 'text-blue-400 bg-blue-500/10 border-blue-500/20',
  info: 'text-slate-400 bg-slate-500/10 border-slate-500/20',
};

// ─── Lookup Form ──────────────────────────────────────────────────────────────

function LookupForm() {
  const [query, setQuery] = useState('');
  const [result, setResult] = useState<ThreatIndicator | null>(null);
  const [isLooking, setIsLooking] = useState(false);
  const [notFound, setNotFound] = useState(false);

  const handleLookup = async () => {
    if (!query.trim()) return;
    setIsLooking(true);
    setNotFound(false);
    setResult(null);
    try {
      const r = await threatIntelApi.lookup(query.trim());
      setResult(r);
    } catch {
      setNotFound(true);
    } finally {
      setIsLooking(false);
    }
  };

  return (
    <div className="bg-gray-900/60 border border-gray-800/60 rounded-xl p-5">
      <h3 className="text-sm font-medium text-gray-300 mb-3">IOC Lookup</h3>
      <div className="flex gap-2">
        <input
          type="text"
          value={query}
          onChange={(e) => setQuery(e.target.value)}
          onKeyDown={(e) => e.key === 'Enter' && handleLookup()}
          placeholder="Enter IP, domain, hash, or URL…"
          className="flex-1 bg-gray-800 border border-gray-700 rounded-lg text-sm text-gray-300 placeholder-gray-600 px-3 py-2 focus:outline-none focus:border-blue-500/50"
        />
        <button
          onClick={handleLookup}
          disabled={isLooking || !query.trim()}
          className="bg-blue-600 hover:bg-blue-500 disabled:opacity-50 text-white text-sm px-4 py-2 rounded-lg transition-colors"
        >
          {isLooking ? 'Looking up…' : 'Lookup'}
        </button>
      </div>

      {notFound && (
        <div className="mt-3 flex items-center gap-2 text-sm text-green-400 bg-green-500/10 border border-green-500/20 rounded-lg px-3 py-2">
          <span className="text-[10px] font-semibold uppercase tracking-wider">clean</span>
          <span>No threat indicators found for this IOC</span>
        </div>
      )}

      {result && (
        <div className="mt-3 bg-red-500/5 border border-red-500/20 rounded-lg p-3 space-y-2">
          <div className="flex items-center gap-2">
            <span className="text-red-400 font-medium text-sm">Malicious indicator</span>
            <span className="text-xs text-gray-500">Confidence: {result.confidence}%</span>
          </div>
          {result.description ? (
            <p className="text-xs text-gray-400">{result.description}</p>
          ) : null}
          <div className="flex flex-wrap gap-1">
            {(result.tags ?? []).map((t) => (
              <span key={t} className="text-xs bg-gray-800 text-gray-400 px-1.5 py-0.5 rounded">{t}</span>
            ))}
          </div>
          <div className="text-xs text-gray-500">
            Sources: {result.sources.join(', ')}
          </div>
        </div>
      )}
    </div>
  );
}

// ─── IOC Row ──────────────────────────────────────────────────────────────────

function IOCRow({ ioc }: { ioc: ThreatIndicator }) {
  const typeCfg = TYPE_CONFIG[ioc.type] || TYPE_CONFIG.ip;
  const [open, setOpen] = useState(false);

  return (
    <div className="border-b border-gray-800/60 last:border-0">
      <div
        role="button"
        tabIndex={0}
        aria-expanded={open}
        aria-label={`${open ? 'Hide' : 'Show'} details for ${ioc.value}`}
        onClick={() => setOpen((v) => !v)}
        onKeyDown={(e) => {
          if (e.key === 'Enter' || e.key === ' ') {
            e.preventDefault();
            setOpen((v) => !v);
          }
        }}
        className="flex items-center gap-4 py-3 cursor-pointer hover:bg-gray-800/20 px-4 -mx-4 transition-colors rounded-lg focus:outline-none focus-visible:ring-1 focus-visible:ring-blue-500/50"
      >
        <span className={clsx('text-xs font-medium px-2 py-0.5 rounded border shrink-0', typeCfg.color)}>
          {typeCfg.label}
        </span>

        <div className="flex-1 min-w-0">
          <p className="text-sm font-mono text-gray-300 truncate">{ioc.value}</p>
          <p className="text-xs text-gray-600 mt-0.5 truncate">{ioc.description ?? ''}</p>
        </div>

        <span className={clsx('text-xs font-medium px-2 py-0.5 rounded border shrink-0', SEVERITY_CONFIG[ioc.severity])}>
          {ioc.severity}
        </span>

        <div className="text-right shrink-0">
          <div className="flex items-center gap-1 justify-end">
            <span className="text-xs text-gray-500">Confidence:</span>
            <span className={clsx(
              'text-xs font-medium',
              ioc.confidence >= 80 ? 'text-red-400' : ioc.confidence >= 60 ? 'text-yellow-400' : 'text-gray-400'
            )}>
              {ioc.confidence}%
            </span>
          </div>
          <p className="text-xs text-gray-600 mt-0.5" suppressHydrationWarning>
            {ioc.lastSeen || ioc.firstSeen
              ? safeFormat(ioc.lastSeen ?? ioc.firstSeen ?? 0, 'MMM dd HH:mm')
              : '\u2014'}
          </p>
        </div>

        <div className="flex flex-wrap gap-1 max-w-32 shrink-0">
          {ioc.sources.slice(0, 2).map((src) => (
            <span key={src} className="text-xs bg-gray-800 text-gray-500 px-1.5 py-0.5 rounded">
              {src}
            </span>
          ))}
        </div>
      </div>
      {open && <IOCDetails ioc={ioc} />}
    </div>
  );
}

/** Where to look an indicator up by hand. Opening a link sends nothing from A.C.O.R.N; the lookup button below asks the configured providers and only when pressed. */
export function externalCheckUrl(ioc: Pick<ThreatIndicator, 'type' | 'value'>): { label: string; url: string } | null {
  const v = encodeURIComponent(ioc.value.trim());
  switch (ioc.type) {
    case 'hash':
      return { label: 'Check on VirusTotal', url: `https://www.virustotal.com/gui/file/${v}` };
    case 'ip':
      return { label: 'Check on VirusTotal', url: `https://www.virustotal.com/gui/ip-address/${v}` };
    case 'domain':
      return { label: 'Check on VirusTotal', url: `https://www.virustotal.com/gui/domain/${v}` };
    default:
      return null;
  }
}

function hashAlgorithm(storedType?: string): string | null {
  const m = /^file_hash_(md5|sha1|sha256|sha512)$/.exec(storedType ?? '');
  return m ? m[1].toUpperCase() : null;
}

function IOCDetails({ ioc }: { ioc: ThreatIndicator }) {
  const [copied, setCopied] = useState(false);
  const [lookup, setLookup] = useState<{ state: 'idle' | 'running' | 'found' | 'clean' | 'failed'; result?: ThreatIndicator }>({ state: 'idle' });
  const linked = ioc.linkedAlerts ?? [];
  const alertTitles = useSWR(linked.length > 0 ? ['ioc-alerts', ioc.id] : null, async () => {
    const shown = linked.slice(0, 5);
    const settled = await Promise.allSettled(shown.map((id) => alertsApi.get(id)));
    return shown.map((id, i) => {
      const r = settled[i];
      const alert = r.status === 'fulfilled' ? r.value : null;
      return { id, title: alert?.title ?? null, severity: alert?.severity ?? null };
    });
  });
  const external = externalCheckUrl(ioc);
  const algorithm = hashAlgorithm(ioc.storedType);

  const copy = async () => {
    try {
      await navigator.clipboard.writeText(ioc.value);
      setCopied(true);
      setTimeout(() => setCopied(false), 1500);
    } catch {
      /* clipboard not available: the value is selectable on screen */
    }
  };

  const runLookup = async () => {
    setLookup({ state: 'running' });
    try {
      setLookup({ state: 'found', result: await threatIntelApi.lookup(ioc.value) });
    } catch (err) {
      // A 404 is the provider's answer ("nothing known"); anything else is a failed lookup.
      const status = (err as { status?: number })?.status;
      setLookup({ state: status === 404 ? 'clean' : 'failed' });
    }
  };

  const facts: Array<[string, string | undefined]> = [
    ['Type', algorithm ? `Hash (${algorithm})` : TYPE_CONFIG[ioc.type]?.label],
    ['Severity', ioc.severity],
    ['Confidence', `${ioc.confidence}%`],
    ['First seen', ioc.firstSeen ? safeFormat(ioc.firstSeen, 'MMM dd yyyy HH:mm') : undefined],
    ['Last seen', ioc.lastSeen ? safeFormat(ioc.lastSeen, 'MMM dd yyyy HH:mm') : undefined],
    ['Expires', ioc.expiresAt ? safeFormat(ioc.expiresAt, 'MMM dd yyyy') : undefined],
    ['Sources', ioc.sources.join(', ') || undefined],
    ['Source reference', ioc.sourceRef],
    ['TLP', ioc.tlp],
    ['Threat actor', ioc.threatActor],
    ['Campaign', ioc.campaign],
    ['Malware family', ioc.malwareFamily],
  ];

  return (
    <div data-testid="ioc-details" className="mb-3 -mx-4 px-4 pb-4 pt-1 space-y-4 bg-gray-800/20 rounded-b-lg">
      <div className="flex items-start gap-2">
        <p className="flex-1 text-sm font-mono text-gray-200 break-all select-all">{ioc.value}</p>
        <button onClick={copy} className="text-xs px-2 py-1 rounded border border-gray-700 text-gray-300 hover:bg-gray-800 shrink-0">
          {copied ? 'Copied' : 'Copy'}
        </button>
      </div>

      {ioc.description && <p className="text-sm text-gray-400">{ioc.description}</p>}

      <dl className="grid grid-cols-2 md:grid-cols-4 gap-x-4 gap-y-2 text-xs">
        {facts
          .filter(([, v]) => v)
          .map(([k, v]) => (
            <div key={k}>
              <dt className="text-gray-600">{k}</dt>
              <dd className="text-gray-300">{v}</dd>
            </div>
          ))}
      </dl>

      {(ioc.tags ?? []).length > 0 && (
        <div className="flex flex-wrap gap-1">
          {(ioc.tags ?? []).map((t) => (
            <span key={t} className="text-xs bg-gray-800 text-gray-400 px-1.5 py-0.5 rounded">{t}</span>
          ))}
        </div>
      )}

      <div>
        <p className="text-xs font-medium text-gray-400 mb-1">Seen on {linked.length} alert{linked.length === 1 ? '' : 's'}</p>
        {linked.length === 0 && <p className="text-xs text-gray-600">No alert is linked to this indicator.</p>}
        <ul className="space-y-1">
          {(alertTitles.data ?? linked.slice(0, 5).map((id) => ({ id, title: null, severity: null }))).map((a) => (
            <li key={a.id} className="text-xs">
              <Link href={`/alerts/${a.id}`} className="text-blue-400 hover:text-blue-300">
                {a.title ?? `Alert ${a.id.slice(0, 8)}`}
              </Link>
              {a.severity && <span className="ml-2 text-gray-600">{a.severity}</span>}
            </li>
          ))}
        </ul>
        {linked.length > 5 && <p className="text-xs text-gray-600 mt-1">and {linked.length - 5} more</p>}
      </div>

      <div className="flex flex-wrap items-center gap-2">
        <button
          onClick={runLookup}
          disabled={lookup.state === 'running'}
          className="text-xs px-3 py-1.5 rounded border border-blue-500/40 bg-blue-500/10 text-blue-300 hover:bg-blue-500/20 disabled:opacity-50"
        >
          {lookup.state === 'running' ? 'Asking the providers\u2026' : 'Look up with threat intel providers'}
        </button>
        {external && (
          <a href={external.url} target="_blank" rel="noopener noreferrer" className="text-xs px-3 py-1.5 rounded border border-gray-700 text-gray-300 hover:bg-gray-800">
            {external.label}
          </a>
        )}
      </div>
      {lookup.state === 'clean' && <p className="text-xs text-green-400">The providers know nothing about this indicator.</p>}
      {lookup.state === 'failed' && <p className="text-xs text-red-400">The lookup failed (no provider answered). Try again, or check a provider by hand.</p>}
      {lookup.state === 'found' && lookup.result && (
        <p className="text-xs text-gray-300">
          Providers report {lookup.result.malicious ? 'a malicious indicator' : 'a known indicator'} at {lookup.result.confidence}% confidence
          {lookup.result.sources.length > 0 ? ` (${lookup.result.sources.join(', ')})` : ''}.
        </p>
      )}
    </div>
  );
}

// ─── Main View ────────────────────────────────────────────────────────────────

export function ThreatIntelView() {
  const [typeFilter, setTypeFilter] = useState<ThreatIndicator['type'] | 'all'>('all');
  const [search, setSearch] = useState('');

  const { data } = useSWR(
    'threat-intel-indicators',
    () => threatIntelApi.list(),
  );

  const allIndicators = data?.indicators ?? [];

  const indicators = allIndicators.filter((ioc) => {
    if (typeFilter !== 'all' && ioc.type !== typeFilter) return false;
    if (
      search &&
      !ioc.value.toLowerCase().includes(search.toLowerCase()) &&
      !(ioc.description ?? '').toLowerCase().includes(search.toLowerCase())
    ) {
      return false;
    }
    return true;
  });

  const typeCounts = {
    all: allIndicators.length,
    ip: allIndicators.filter(i => i.type === 'ip').length,
    domain: allIndicators.filter(i => i.type === 'domain').length,
    hash: allIndicators.filter(i => i.type === 'hash').length,
    url: allIndicators.filter(i => i.type === 'url').length,
  };

  return (
    <div className="space-y-5">
      {/* Header */}
      <div>
        <h1 className="text-xl font-semibold text-gray-100">Threat Intelligence</h1>
        <p className="text-sm text-gray-500 mt-0.5">
          Indicators of compromise aggregated from multiple intel feeds
        </p>
      </div>

      {/* Stats */}
      <div className="grid grid-cols-4 gap-3">
        {[
          { label: 'Total IOCs', value: allIndicators.length, color: 'text-blue-400' },
          { label: 'Malicious', value: allIndicators.filter(i => i.malicious).length, color: 'text-red-400' },
          { label: 'High Confidence', value: allIndicators.filter(i => i.confidence >= 80).length, color: 'text-orange-400' },
          { label: 'Added Today', value: allIndicators.filter((i) => i.firstSeen && new Date(i.firstSeen).toDateString() === new Date().toDateString()).length, color: 'text-green-400' },
        ].map((stat) => (
          <div key={stat.label} className="bg-gray-900/60 border border-gray-800/60 rounded-xl p-4">
            <p className={clsx('text-2xl font-bold mb-1', stat.color)}>{stat.value}</p>
            <p className="text-xs text-gray-500">{stat.label}</p>
          </div>
        ))}
      </div>

      {/* Lookup */}
      <LookupForm />

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
            placeholder="Search indicators…"
            className="w-full pl-9 pr-4 py-2 bg-gray-900/60 border border-gray-800 rounded-lg text-sm text-gray-300 placeholder-gray-600 focus:outline-none focus:border-blue-500/50"
          />
        </div>

        <div className="flex gap-1">
          {(['all', 'ip', 'domain', 'hash', 'url'] as const).map((t) => (
            <button
              key={t}
              onClick={() => setTypeFilter(t)}
              className={clsx(
                'text-xs px-3 py-1.5 rounded-lg transition-colors',
                typeFilter === t
                  ? 'bg-blue-600 text-white'
                  : 'text-gray-400 bg-gray-800/60 hover:bg-gray-800'
              )}
            >
              {t === 'all' ? 'All' : t.toUpperCase()} ({typeCounts[t] ?? 0})
            </button>
          ))}
        </div>
      </div>

      {/* IOC List */}
      <div className="bg-gray-900/60 border border-gray-800/60 rounded-xl p-4">
        <div className="flex items-center justify-between mb-3">
          <h3 className="text-sm font-medium text-gray-300">Indicators of Compromise</h3>
          <span className="text-xs text-gray-500">{indicators.length} indicators</span>
        </div>
        {indicators.length === 0 ? (
          // WS-F5 — TI feeds rarely have a true "no IOCs ever" state in
          // practice (the OT feed alone seeds dozens), so the most common
          // empty path here is a filter-miss. Both copies still steer the
          // analyst back to a useful action.
          typeFilter !== 'all' || search ? (
            <EmptyState
              icon={EmptyStateIcons.search}
              title="No indicators match these filters"
              description="Try a different IOC type or clear the search to see the full feed."
              action={
                <button
                  onClick={() => {
                    setTypeFilter('all');
                    setSearch('');
                  }}
                  className="text-xs px-3 py-1.5 rounded-md border border-blue-500/40 bg-blue-500/10 text-blue-300 hover:bg-blue-500/20 transition-colors"
                >
                  Clear filters
                </button>
              }
              className="bg-transparent py-8"
            />
          ) : (
            <EmptyState
              icon={EmptyStateIcons.shield}
              title="No threat intel ingested yet"
              description="Connect a TI feed (MISP, OTX, AbuseIPDB, GreyNoise, internal STIX/TAXII) from Settings → Connectors to start enriching alerts with reputation context."
              className="bg-transparent py-8"
            />
          )
        ) : (
          <div>
            {indicators.map((ioc) => <IOCRow key={ioc.id} ioc={ioc} />)}
          </div>
        )}
      </div>
    </div>
  );
}
