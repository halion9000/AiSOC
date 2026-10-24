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

/** The alerts grouped by the tool that raised them, the tool with the most first ("other" when an alert names none). */
export function groupBySource<T extends { source: string | null }>(alerts: T[]): Record<string, T[]> {
  const groups: Record<string, T[]> = {};
  for (const a of alerts) (groups[a.source || 'other'] ??= []).push(a);
  return Object.fromEntries(Object.entries(groups).sort((x, y) => y[1].length - x[1].length || x[0].localeCompare(y[0])));
}

export const BACKUP_STYLE: Record<string, { label: string; className: string }> = {
  ok: { label: 'Backed up', className: 'border-emerald-500/40 text-emerald-300' },
  stale: { label: 'No recent backup', className: 'border-amber-500/40 text-amber-300' },
  issue: { label: 'Backup error', className: 'border-red-500/40 text-red-300' },
  paused: { label: 'Paused', className: 'border-amber-500/40 text-amber-300' },
  unprotected: { label: 'Not protected', className: 'border-red-500/40 text-red-300' },
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
              {src.details?.via ? <span className="text-xs text-gray-500">({String(src.details.via)})</span> : null}
              {src.enabled === false && <span className="text-xs text-red-300">disabled</span>}
            </li>
          ))}
        </ul>
        {data.person.mfa_methods && <p className="mt-2 text-xs text-gray-400">Second factor methods: {data.person.mfa_methods}</p>}
        {(data.person.backups ?? []).length > 0 && (
          <div className="mt-3" data-testid="backup-detail">
            <h4 className="mb-1 text-xs font-semibold uppercase text-gray-500">Backups</h4>
            <ul className="space-y-1">
              {(data.person.backups ?? []).map((b) => (
                <li key={b.vendor} className="text-sm text-gray-200">
                  <span className={`mr-2 rounded border px-1 py-0.5 text-[11px] ${(BACKUP_STYLE[b.status] ?? BACKUP_STYLE.stale).className}`}>{(BACKUP_STYLE[b.status] ?? BACKUP_STYLE.stale).label}</span>
                  {b.detail}
                </li>
              ))}
            </ul>
          </div>
        )}
      </section>
      <section>
        <h4 className="mb-1 text-xs font-semibold uppercase text-gray-500">Open alerts ({data.alerts.length})</h4>
        {data.alerts.length === 0 ? (
          <p className="text-sm text-gray-500">None name this person.</p>
        ) : (
          <div className="space-y-2">
            {Object.entries(groupBySource(data.alerts)).map(([tool, rows]) => (
              <div key={tool} data-testid="alert-group">
                <div className="mb-1 flex items-center gap-1.5 text-xs text-gray-400">
                  {tool !== 'other' && <VendorBadge vendor={tool} />}
                  <span>{tool === 'other' ? 'Other' : vendorLabel(tool)}</span>
                  <span className="tabular-nums">({rows.length})</span>
                </div>
                <ul className="space-y-1">
                  {rows.slice(0, 6).map((a) => (
                    <li key={a.id} className="text-sm">
                      <span className={`mr-2 rounded-full border px-1.5 py-0.5 text-[11px] ${SEVERITY_STYLE[a.severity] ?? SEVERITY_STYLE.info}`}>{a.severity}</span>
                      <Link href={`/alerts/${a.id}`} className="text-blue-300 hover:underline">
                        {a.title}
                      </Link>
                    </li>
                  ))}
                </ul>
              </div>
            ))}
          </div>
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
  const [alertTool, setAlertTool] = useState('');
  const [mfa, setMfa] = useState('');
  const [backup, setBackup] = useState('');
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
    () => ({ page, pageSize: 50, clientId: clientId || undefined, search: debounced || undefined, source: tool || undefined, mfa: mfa || undefined, kind: kind || undefined, hasAlerts, alertSource: alertTool || undefined, backup: backup || undefined, admin: adminOnly, disabled: disabledOnly, onlyIn: oneTool && tool ? tool : undefined, sort }),
    [page, clientId, debounced, tool, alertTool, mfa, backup, kind, hasAlerts, adminOnly, disabledOnly, oneTool, sort],
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
        {tile('Backup problems', summary?.backup_problems, backup === 'problem', () => setBackup(backup === 'problem' ? '' : 'problem'), true)}
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
        <select aria-label="Alerts from" value={alertTool} onChange={(e) => reset(() => setAlertTool(e.target.value))} className="rounded-md border border-gray-700 bg-gray-900 px-2 py-1.5 text-sm text-white">
          <option value="">Alerts from any tool</option>
          {Object.entries(summary?.alert_sources ?? {}).map(([t, n]) => (
            <option key={t} value={t}>
              {vendorLabel(t)} ({n})
            </option>
          ))}
        </select>
        <select aria-label="Backup" value={backup} onChange={(e) => reset(() => setBackup(e.target.value))} className="rounded-md border border-gray-700 bg-gray-900 px-2 py-1.5 text-sm text-white">
          <option value="">Any backup state</option>
          <option value="ok">Backed up</option>
          <option value="problem">Backup problem</option>
          <option value="none">No backup tool knows them</option>
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
                <th scope="col" className="px-3 py-2">Backup</th>
                <SortHeader col="alerts" label="Alerts" sort={sort} onSort={(s) => reset(() => setSort(s))} />
              </tr>
            </thead>
            <tbody className="divide-y divide-gray-800">
              {isLoading && !data && (
                <tr>
                  <td colSpan={6} className="px-3 py-8 text-center text-gray-400">
                    Loading people…
                  </td>
                </tr>
              )}
              {data && data.items.length === 0 && (
                <tr>
                  <td colSpan={6} className="px-3 py-8 text-center text-gray-400">
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
                        <span className="flex flex-wrap gap-1" data-testid="backups">
                          {(p.backups ?? []).length === 0 ? (
                            <span className="text-gray-600">—</span>
                          ) : (
                            (p.backups ?? []).map((b) => {
                              const st = BACKUP_STYLE[b.status] ?? BACKUP_STYLE.stale;
                              return (
                                <span key={b.vendor} title={b.detail} className={`inline-flex items-center gap-1 rounded border px-1 py-0.5 text-[11px] ${st.className}`}>
                                  <VendorBadge vendor={b.vendor} />
                                  {st.label}
                                </span>
                              );
                            })
                          )}
                        </span>
                      </td>
                      <td className="px-3 py-2">
                        {p.open_alerts > 0 ? (
                          <span className="flex items-center gap-2">
                            <span className="tabular-nums text-gray-100">{p.open_alerts}</span>
                            {p.top_severity && <span className={`rounded-full border px-1.5 py-0.5 text-[11px] ${SEVERITY_STYLE[p.top_severity] ?? SEVERITY_STYLE.info}`}>{p.top_severity}</span>}
                            <span className="flex flex-wrap gap-1" data-testid="alerts-by-source">
                              {Object.entries(p.alerts_by_source ?? {}).map(([t, n]) => (
                                <span key={t} className="inline-flex items-center gap-1 rounded border border-gray-700 px-1 py-0.5 text-[11px] text-gray-300" title={`${n} open alert${n === 1 ? '' : 's'} from ${t === 'other' ? 'an unnamed tool' : vendorLabel(t)}`}>
                                  {t !== 'other' && <VendorBadge vendor={t} />}
                                  {t === 'other' && <span>other</span>}
                                  <span className="tabular-nums">{n}</span>
                                </span>
                              ))}
                            </span>
                          </span>
                        ) : (
                          <span className="text-gray-600">0</span>
                        )}
                      </td>
                    </tr>
                    {isOpen && (
                      <tr className="bg-gray-900/30">
                        <td colSpan={6} className="px-4 py-3">
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
