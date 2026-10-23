'use client';

/**
 * Identities: every person (e-mail identity) the connected tools know, one row each. Shows which tools know them (as logos), their multi-factor state, and the open alerts that name them; a row opens to
 * every tool's record of the person, the alerts, and a summary of their recent sign-ins. Read only. Backed by GET /api/v1/identities.
 */

import { useEffect, useMemo, useState } from 'react';
import Link from 'next/link';
import useSWR from 'swr';
import { identitiesApi, msspApi, type IdentityPerson, type IdentityQuery, type IdentitySort } from '@/lib/api';
import VendorBadge from '@/components/mssp/VendorBadge';
import { vendorLabel } from '@/components/mssp/ClientMapping';
import { safeDistance } from '@/lib/safe-date';

const SEVERITY_STYLE: Record<string, string> = {
  critical: 'bg-red-500/15 text-red-300 border-red-500/30',
  high: 'bg-orange-500/15 text-orange-300 border-orange-500/30',
  medium: 'bg-yellow-500/15 text-yellow-300 border-yellow-500/30',
  low: 'bg-blue-500/15 text-blue-300 border-blue-500/30',
  info: 'bg-gray-500/15 text-gray-300 border-gray-500/30',
};

export const MFA_LABEL: Record<string, { text: string; className: string }> = {
  covered: { text: 'Covered', className: 'text-emerald-300' },
  registered_not_required: { text: 'Signed up, not required', className: 'text-amber-300' },
  none: { text: 'None', className: 'text-red-300' },
  unknown: { text: 'Not known', className: 'text-gray-500' },
};

const SORT_FOR_COLUMN: Record<string, IdentitySort> = { person: 'email', client: 'client', tools: 'tools', alerts: 'alerts' };

function SortHeader({ col, label, sort, onSort }: { col: keyof typeof SORT_FOR_COLUMN; label: string; sort: IdentitySort; onSort: (s: IdentitySort) => void }) {
  const mine = SORT_FOR_COLUMN[col];
  return (
    <th scope="col" aria-sort={sort === mine ? 'ascending' : 'none'} className="px-3 py-2">
      <button type="button" onClick={() => onSort(mine)} className="inline-flex items-center gap-1 uppercase hover:text-gray-300">
        {label}
        <span aria-hidden="true" className={sort === mine ? 'text-blue-300' : 'text-gray-700'}>
          {sort === mine ? '▲' : '↕'}
        </span>
      </button>
    </th>
  );
}

function Detail({ person }: { person: IdentityPerson }) {
  const { data, error } = useSWR(['identity', person.client_id, person.email], () => identitiesApi.detail(person.client_id, person.email), { revalidateOnFocus: false });
  if (error) return <p className="text-sm text-red-300">Could not load this person.</p>;
  if (!data) return <p className="text-sm text-gray-500">Loading…</p>;
  const s = data.signins;
  return (
    <div className="grid gap-4 md:grid-cols-3" data-testid="identity-detail">
      <section>
        <h4 className="mb-1 text-xs font-semibold uppercase text-gray-500">Known to</h4>
        <ul className="space-y-1">
          {data.person.sources.map((src) => (
            <li key={`${src.vendor}:${src.external_id}`} className="flex items-center gap-2 text-sm text-gray-200">
              <VendorBadge vendor={src.vendor} />
              <span>{vendorLabel(src.vendor)}</span>
              {src.enabled === false && <span className="text-xs text-red-300">disabled</span>}
            </li>
          ))}
        </ul>
        {data.person.mfa_methods && <p className="mt-2 text-xs text-gray-400">Second factor methods: {data.person.mfa_methods}</p>}
      </section>
      <section>
        <h4 className="mb-1 text-xs font-semibold uppercase text-gray-500">Open alerts ({data.alerts.length})</h4>
        {data.alerts.length === 0 ? (
          <p className="text-sm text-gray-500">None name this person.</p>
        ) : (
          <ul className="space-y-1">
            {data.alerts.slice(0, 8).map((a) => (
              <li key={a.id} className="text-sm">
                <span className={`mr-2 rounded-full border px-1.5 py-0.5 text-[11px] ${SEVERITY_STYLE[a.severity] ?? SEVERITY_STYLE.info}`}>{a.severity}</span>
                <Link href={`/alerts/${a.id}`} className="text-blue-300 hover:underline">
                  {a.title}
                </Link>
              </li>
            ))}
          </ul>
        )}
      </section>
      <section>
        <h4 className="mb-1 text-xs font-semibold uppercase text-gray-500">Sign-ins, last 30 days</h4>
        {s.last_30_days === 0 ? (
          <p className="text-sm text-gray-500">None read for this person.</p>
        ) : (
          <ul className="space-y-0.5 text-sm text-gray-200">
            <li>{s.last_30_days} sign-ins, {s.failed} failed</li>
            <li>{s.unusual} flagged as unusual</li>
            {s.countries.length > 0 && <li>From: {s.countries.join(', ')}</li>}
            {s.last_at && <li className="text-gray-400">Last {safeDistance(s.last_at, { addSuffix: true })}</li>}
          </ul>
        )}
      </section>
    </div>
  );
}

export function IdentitiesView() {
  const [page, setPage] = useState(1);
  const [search, setSearch] = useState('');
  const [debounced, setDebounced] = useState('');
  const [clientId, setClientId] = useState('');
  const [tool, setTool] = useState('');
  const [mfa, setMfa] = useState('');
  const [kind, setKind] = useState('');
  const [hasAlerts, setHasAlerts] = useState(false);
  const [adminOnly, setAdminOnly] = useState(false);
  const [disabledOnly, setDisabledOnly] = useState(false);
  const [oneTool, setOneTool] = useState(false);
  const [sort, setSort] = useState<IdentitySort>('alerts');
  const [open, setOpen] = useState<string | null>(null);

  useEffect(() => {
    const t = setTimeout(() => setDebounced(search), 250);
    return () => clearTimeout(t);
  }, [search]);

  const query: IdentityQuery = useMemo(
    () => ({ page, pageSize: 50, clientId: clientId || undefined, search: debounced || undefined, source: tool || undefined, mfa: mfa || undefined, kind: kind || undefined, hasAlerts, admin: adminOnly, disabled: disabledOnly, onlyIn: oneTool && tool ? tool : undefined, sort }),
    [page, clientId, debounced, tool, mfa, kind, hasAlerts, adminOnly, disabledOnly, oneTool, sort],
  );
  const { data, error, isLoading, mutate } = useSWR(['identities', query], () => identitiesApi.list(query), { revalidateOnFocus: false, keepPreviousData: true });
  const { data: clients } = useSWR('mssp-children', () => msspApi.listChildren().catch(() => []), { revalidateOnFocus: false });

  const reset = (fn: () => void) => {
    fn();
    setPage(1);
  };
  const tile = (label: string, value: number | undefined, on: boolean, toggle: () => void, bad = false) => (
    <button
      type="button"
      aria-pressed={on}
      onClick={() => reset(toggle)}
      className={`rounded-lg border p-3 text-left ${on ? 'border-blue-500 bg-blue-500/10' : 'border-gray-800 bg-gray-900/60'}`}
    >
      <div className="text-xs text-gray-400">{label}</div>
      <div className={`text-2xl font-semibold ${bad ? 'text-amber-300' : 'text-gray-100'}`}>{value ?? '—'}</div>
    </button>
  );

  const summary = data?.summary;
  const tools = Object.keys(summary?.tools ?? {});

  return (
    <div className="space-y-5 p-6">
      <div>
        <h1 className="text-2xl font-semibold text-white">Identities</h1>
        <p className="mt-1 text-sm text-gray-400">Every person the connected tools know, one row each, with the tools that know them, their multi-factor state and the alerts that name them.</p>
      </div>

      <div className="flex flex-wrap gap-3">
        <div className="rounded-lg border border-gray-800 bg-gray-900/60 p-3">
          <div className="text-xs text-gray-400">People</div>
          <div className="text-2xl font-semibold text-white" data-testid="identities-total">
            {summary?.total ?? '—'}
          </div>
        </div>
        {tile('With open alerts', summary?.with_alerts, hasAlerts, () => setHasAlerts((v) => !v), true)}
        {tile('No Multi-Factor', summary?.without_mfa, mfa === 'none', () => setMfa(mfa === 'none' ? '' : 'none'), true)}
        {tile('Administrators', summary?.admins, adminOnly, () => setAdminOnly((v) => !v))}
        {tile('Disabled accounts', summary?.disabled, disabledOnly, () => setDisabledOnly((v) => !v))}
        {tile('In only one tool', summary?.in_one_tool, oneTool, () => setOneTool((v) => !v))}
      </div>
      {oneTool && !tool && <p className="text-xs text-amber-300">Pick a tool below to see the people only that tool knows.</p>}

      <div className="flex flex-wrap items-center gap-2">
        <input
          type="search"
          aria-label="Search people"
          placeholder="Search name, e-mail or client"
          value={search}
          onChange={(e) => reset(() => setSearch(e.target.value))}
          className="w-64 rounded-md border border-gray-700 bg-gray-900 px-3 py-1.5 text-sm text-white placeholder:text-gray-500"
        />
        <select aria-label="Client" value={clientId} onChange={(e) => reset(() => setClientId(e.target.value))} className="rounded-md border border-gray-700 bg-gray-900 px-2 py-1.5 text-sm text-white">
          <option value="">All clients</option>
          {(clients ?? []).map((c) => (
            <option key={c.id} value={c.id}>
              {c.name}
            </option>
          ))}
        </select>
        <select aria-label="Known to" value={tool} onChange={(e) => reset(() => setTool(e.target.value))} className="rounded-md border border-gray-700 bg-gray-900 px-2 py-1.5 text-sm text-white">
          <option value="">Any tool</option>
          {tools.map((t) => (
            <option key={t} value={t}>
              {vendorLabel(t)} ({summary?.tools[t]})
            </option>
          ))}
        </select>
        <select aria-label="Multi-Factor" value={mfa} onChange={(e) => reset(() => setMfa(e.target.value))} className="rounded-md border border-gray-700 bg-gray-900 px-2 py-1.5 text-sm text-white">
          <option value="">Any Multi-Factor</option>
          {Object.entries(MFA_LABEL).map(([k, v]) => (
            <option key={k} value={k}>
              {v.text}
            </option>
          ))}
        </select>
        <select aria-label="Kind" value={kind} onChange={(e) => reset(() => setKind(e.target.value))} className="rounded-md border border-gray-700 bg-gray-900 px-2 py-1.5 text-sm text-white">
          <option value="">Any kind</option>
          <option value="user">Members</option>
          <option value="guest">Guests</option>
          <option value="shared">Shared mailboxes</option>
        </select>
      </div>

      {error ? (
        <p role="alert" className="rounded border border-red-500/40 bg-red-500/10 p-3 text-sm text-red-300">
          Could not load the identities{error instanceof Error ? `: ${error.message}` : ''}.{' '}
          <button type="button" onClick={() => void mutate()} className="underline">
            Retry
          </button>
        </p>
      ) : (
        <div className="overflow-x-auto rounded-lg border border-gray-800">
          <table className="min-w-full divide-y divide-gray-800 text-left text-sm">
            <thead className="bg-gray-900/60 text-xs uppercase text-gray-500">
              <tr>
                <SortHeader col="person" label="Person" sort={sort} onSort={(s) => reset(() => setSort(s))} />
                <SortHeader col="client" label="Client" sort={sort} onSort={(s) => reset(() => setSort(s))} />
                <SortHeader col="tools" label="Known to" sort={sort} onSort={(s) => reset(() => setSort(s))} />
                <th scope="col" className="px-3 py-2">Multi-Factor</th>
                <SortHeader col="alerts" label="Alerts" sort={sort} onSort={(s) => reset(() => setSort(s))} />
              </tr>
            </thead>
            <tbody className="divide-y divide-gray-800">
              {isLoading && !data && (
                <tr>
                  <td colSpan={5} className="px-3 py-8 text-center text-gray-400">
                    Loading people…
                  </td>
                </tr>
              )}
              {data && data.items.length === 0 && (
                <tr>
                  <td colSpan={5} className="px-3 py-8 text-center text-gray-400">
                    No people match.
                  </td>
                </tr>
              )}
              {(data?.items ?? []).map((p) => {
                const isOpen = open === p.key;
                const mfaInfo = MFA_LABEL[p.mfa] ?? MFA_LABEL.unknown;
                return (
                  <FragmentRow key={p.key}>
                    <tr data-testid="identity-row" className="cursor-pointer hover:bg-gray-900/40" onClick={() => setOpen(isOpen ? null : p.key)}>
                      <td className="px-3 py-2">
                        <div className="text-gray-100">{p.display_name ?? p.email}</div>
                        <div className="text-xs text-gray-500">
                          {p.display_name ? `${p.email} · ` : ''}
                          {p.admin && <span className="mr-1 text-amber-300">admin</span>}
                          {p.enabled === false && <span className="mr-1 text-red-300">disabled</span>}
                          {p.kind !== 'user' && <span className="text-gray-400">{p.kind}</span>}
                        </div>
                      </td>
                      <td className="px-3 py-2 text-gray-300">{p.client_name ?? '—'}</td>
                      <td className="px-3 py-2">
                        <span className="flex flex-wrap gap-1">
                          {p.tools.map((t) => (
                            <VendorBadge key={t} vendor={t} />
                          ))}
                        </span>
                      </td>
                      <td className={`px-3 py-2 ${mfaInfo.className}`}>{mfaInfo.text}</td>
                      <td className="px-3 py-2">
                        {p.open_alerts > 0 ? (
                          <span className="flex items-center gap-2">
                            <span className="tabular-nums text-gray-100">{p.open_alerts}</span>
                            {p.top_severity && <span className={`rounded-full border px-1.5 py-0.5 text-[11px] ${SEVERITY_STYLE[p.top_severity] ?? SEVERITY_STYLE.info}`}>{p.top_severity}</span>}
                          </span>
                        ) : (
                          <span className="text-gray-600">0</span>
                        )}
                      </td>
                    </tr>
                    {isOpen && (
                      <tr className="bg-gray-900/30">
                        <td colSpan={5} className="px-4 py-3">
                          <Detail person={p} />
                        </td>
                      </tr>
                    )}
                  </FragmentRow>
                );
              })}
            </tbody>
          </table>
        </div>
      )}

      {data && data.pages > 1 && (
        <div className="flex items-center justify-between text-sm text-gray-300">
          <span>
            Page {data.page} of {data.pages} ({data.total} people)
          </span>
          <span className="flex gap-2">
            <button type="button" disabled={page <= 1} onClick={() => setPage(page - 1)} className="rounded border border-gray-700 px-3 py-1 disabled:opacity-40">
              Previous
            </button>
            <button type="button" disabled={page >= data.pages} onClick={() => setPage(page + 1)} className="rounded border border-gray-700 px-3 py-1 disabled:opacity-40">
              Next
            </button>
          </span>
        </div>
      )}
    </div>
  );
}

function FragmentRow({ children }: { children: React.ReactNode }) {
  return <>{children}</>;
}
