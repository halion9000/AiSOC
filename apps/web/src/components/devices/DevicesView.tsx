'use client';

import { useCallback, useEffect, useState } from 'react';
import Link from 'next/link';
import { useSearchParams } from 'next/navigation';
import toast from 'react-hot-toast';
import { apiErrorDetail, devicesApi, msspApi, type ChildTenant, type DeviceList, type DeviceQuery, type DeviceRow } from '@/lib/api';
import VendorBadge from '@/components/mssp/VendorBadge';
import DuplicateDevices from './DuplicateDevices';
import { ClientRollupTable } from './ClientRollupTable';
import { vendorLabel } from '@/components/mssp/ClientMapping';
import { loadFilters, pickString, saveFilters } from '@/lib/remembered-filters';

/**
 * Every machine across your clients, one row per device. The same laptop reported by NinjaOne, Addigy and Huntress is ONE row (matched on serial number) and shows
 * each tool that feeds it. Pick a master tool (usually the RMM) and devices it does not report are flagged: a machine another tool sees that your RMM does not.
 */

const MASTER_CHOICES = ['ninjaone', 'addigy', 'threatmate'];

type Missing = 'addigy' | 'threatmate' | 'huntress';

export function toolsOf(d: DeviceRow): string[] {
  return [...new Set(d.sources.map((s) => s.vendor))].sort();
}

function when(iso: string): string {
  const t = new Date(iso);
  return Number.isNaN(t.getTime()) ? '' : t.toLocaleString();
}

/** A URL parameter, from the router when there is one. Reading window.location during a client-side navigation gives the PREVIOUS page's address (the router changes it after the new page renders), so a link with ?search= opened an unfiltered list. */
function urlParam(params: URLSearchParams | null, name: string): string {
  const fromRouter = params?.get(name);
  if (fromRouter != null) return fromRouter;
  return typeof window === 'undefined' ? '' : (new URLSearchParams(window.location.search).get(name) ?? '');
}

/** The filters a link to this page names (``?client=<id>&attention=1&stale=1&offline=1&alerts=1&missing=huntress&os=mac&tool=huntress``), or null when it names none. */
export function filtersFromParams(params: URLSearchParams | null): Partial<SavedDeviceFilters> | null {
  if (!params) return null;
  const out: Partial<SavedDeviceFilters> = {};
  const client = params.get('client');
  if (client) out.clientId = client.slice(0, 64);
  const tool = params.get('tool');
  if (tool) out.vendor = tool.slice(0, 40);
  const osName = params.get('os');
  if (osName) out.os = osName;
  const missing = params.get('missing');
  if (missing === 'addigy' || missing === 'threatmate' || missing === 'huntress') out.missing = missing;
  if (params.get('attention') === '1') out.attentionOnly = true;
  if (params.get('stale') === '1') out.staleOnly = true;
  if (params.get('offline') === '1') out.offlineOnly = true;
  if (params.get('alerts') === '1') out.alertsOnly = true;
  return Object.keys(out).length > 0 ? out : null;
}

const OS_CHOICES: { value: string; label: string }[] = [
  { value: 'windows', label: 'Windows' },
  { value: 'mac', label: 'Mac' },
  { value: 'ios', label: 'iOS / iPadOS' },
  { value: 'linux', label: 'Linux' },
];

interface SavedDeviceFilters {
  clientId: string;
  vendor: string;
  os: string;
  missing: Missing | null;
  gapsOnly: boolean;
  attentionOnly: boolean;
  staleOnly: boolean;
  offlineOnly: boolean;
  alertsOnly: boolean;
}

export default function DevicesView() {
  const urlParams = useSearchParams();
  const [data, setData] = useState<DeviceList | null>(null);
  const [clients, setClients] = useState<ChildTenant[]>([]);
  const [error, setError] = useState('');
  const [loading, setLoading] = useState(true);
  const [page, setPage] = useState(1);
  // A link from an alert (/devices?search=PC-1) opens the page already searching for that device.
  const urlSearch = urlParam(urlParams, 'search').slice(0, 100);
  const [search, setSearch] = useState(urlSearch);
  // Following another device link while already on this page (the address changes, the page stays mounted).
  const [seenUrlSearch, setSeenUrlSearch] = useState(urlSearch);
  if (seenUrlSearch !== urlSearch) {
    setSeenUrlSearch(urlSearch);
    setSearch(urlSearch);
    setPage(1);
  }
  const [clientId, setClientId] = useState('');
  const [vendor, setVendor] = useState('');
  const [os, setOs] = useState('');
  const [gapsOnly, setGapsOnly] = useState(false);
  const [missing, setMissing] = useState<Missing | null>(null);
  const [attentionOnly, setAttentionOnly] = useState(false);
  const [staleOnly, setStaleOnly] = useState(false);
  const [offlineOnly, setOfflineOnly] = useState(false);
  const [alertsOnly, setAlertsOnly] = useState(false);
  const [hiddenOnly, setHiddenOnly] = useState(false);
  const [open, setOpen] = useState<string | null>(null);

  // The filters a person picked last time come back when they return (not the search or the hidden list, which are for the moment).
  const [filtersRestored, setFiltersRestored] = useState(false);
  useEffect(() => {
    // A link from another page (a posture tile, say) names the filters it wants, and those win over what was saved.
    const fromLink = filtersFromParams(urlParams);
    const saved = fromLink ?? loadFilters<SavedDeviceFilters>('devices');
    if (saved) {
      setClientId(pickString(saved.clientId));
      setVendor(pickString(saved.vendor));
      setOs(pickString(saved.os, OS_CHOICES.map((o) => o.value)));
      setMissing((pickString(saved.missing, ['addigy', 'threatmate', 'huntress']) || null) as Missing | null);
      setGapsOnly(saved.gapsOnly === true);
      setAttentionOnly(saved.attentionOnly === true);
      setStaleOnly(saved.staleOnly === true);
      setOfflineOnly(saved.offlineOnly === true);
      setAlertsOnly(saved.alertsOnly === true);
    }
    setFiltersRestored(true);
    // Only on first show.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);
  useEffect(() => {
    if (filtersRestored) saveFilters('devices', { clientId, vendor, os, missing, gapsOnly, attentionOnly, staleOnly, offlineOnly, alertsOnly } satisfies SavedDeviceFilters);
  }, [filtersRestored, clientId, vendor, os, missing, gapsOnly, attentionOnly, staleOnly, offlineOnly, alertsOnly]);

  const load = useCallback(async () => {
    setLoading(true);
    setError('');
    try {
      setData(await devicesApi.list({ page, pageSize: 50, clientId: clientId || undefined, search, vendor: vendor || undefined, os: (os || undefined) as DeviceQuery['os'], notInMaster: gapsOnly, missing: missing ?? undefined, offline: offlineOnly || undefined, hasAlerts: alertsOnly || undefined, attention: attentionOnly || undefined, stale: staleOnly || undefined, hidden: hiddenOnly || undefined }));
    } catch (err) {
      setError(devicesLoadError(err));
    } finally {
      setLoading(false);
    }
  }, [page, clientId, search, vendor, os, gapsOnly, missing, offlineOnly, alertsOnly, attentionOnly, staleOnly, hiddenOnly]);

  useEffect(() => {
    const t = setTimeout(() => void load(), search ? 250 : 0);
    return () => clearTimeout(t);
  }, [load, search]);

  useEffect(() => {
    msspApi
      .listChildren()
      .then(setClients)
      .catch(() => setClients([])); // an organisation with no clients has nothing to pick
  }, []);

  const exportCsv = async () => {
    try {
      const text = await devicesApi.exportCsv({ clientId: clientId || undefined, search, vendor: vendor || undefined, os: (os || undefined) as DeviceQuery['os'], notInMaster: gapsOnly, missing: missing ?? undefined, offline: offlineOnly || undefined, hasAlerts: alertsOnly || undefined, attention: attentionOnly || undefined, stale: staleOnly || undefined, hidden: hiddenOnly || undefined });
      const url = URL.createObjectURL(new Blob([text], { type: 'text/csv;charset=utf-8' }));
      const link = document.createElement('a');
      link.href = url;
      link.download = 'devices.csv';
      link.click();
      URL.revokeObjectURL(url);
    } catch (err) {
      toast.error(err instanceof Error ? err.message : 'Could not export the devices.');
    }
  };

  const setHidden = async (d: DeviceRow, hide: boolean) => {
    try {
      if (hide) await devicesApi.hide(d.id);
      else await devicesApi.unhide(d.id);
      toast.success(hide ? `${d.hostname} is hidden until a tool sees it online again.` : `${d.hostname} is shown again.`);
      await load();
    } catch (err) {
      toast.error(err instanceof Error ? err.message : 'Could not change that device.');
    }
  };

  const chooseMaster = async (value: string) => {
    try {
      await devicesApi.setMaster(value || null);
      toast.success(value ? `${vendorLabel(value)} is now the master device list.` : 'No master device list.');
      setGapsOnly(false);
      setPage(1);
      await load();
    } catch (err) {
      toast.error(err instanceof Error ? err.message : 'Could not save the master tool.');
    }
  };

  const master = data?.master_vendor ?? null;
  const toolChoices = [...new Set([...MASTER_CHOICES, ...(data?.items.flatMap(toolsOf) ?? []), ...(master ? [master] : [])])].sort();

  return (
    <div className="space-y-5 p-6">
      <div className="flex flex-wrap items-end justify-between gap-3">
        <div>
          <h1 className="text-2xl font-semibold text-white">Devices</h1>
          <p className="mt-1 text-sm text-gray-400">One row per machine, matched across tools on serial number.</p>
        </div>
        <label className="text-sm text-gray-300">
          Master device list
          <select
            aria-label="Master device list"
            value={master ?? ''}
            onChange={(e) => void chooseMaster(e.target.value)}
            className="ml-2 rounded-md border border-gray-700 bg-gray-900 px-2 py-1.5 text-sm text-white"
          >
            <option value="">None</option>
            {toolChoices.map((v) => (
              <option key={v} value={v}>
                {vendorLabel(v)}
              </option>
            ))}
          </select>
        </label>
      </div>

      <div className="grid grid-cols-2 gap-3 sm:max-w-5xl sm:grid-cols-6">
        <div className="rounded-lg border border-gray-800 bg-gray-900/60 p-3">
          <div className="text-xs text-gray-400">Devices</div>
          <div className="text-2xl font-semibold text-white" data-testid="devices-total">
            {data?.summary.total ?? '—'}
          </div>
        </div>
        <button
          type="button"
          disabled={!master}
          onClick={() => {
            setGapsOnly((v) => !v);
            setPage(1);
          }}
          aria-pressed={gapsOnly}
          className={`rounded-lg border p-3 text-left ${gapsOnly ? 'border-amber-500 bg-amber-500/10' : 'border-gray-800 bg-gray-900/60'} disabled:opacity-50`}
        >
          <div className="text-xs text-gray-400">{master ? `Not in ${vendorLabel(master)}` : 'Not in master (pick a master)'}</div>
          <div className="text-2xl font-semibold text-amber-300" data-testid="devices-gaps">
            {master ? (data?.summary.not_in_master ?? '—') : '—'}
          </div>
        </button>
        <button
          type="button"
          onClick={() => {
            setStaleOnly(!staleOnly);
            setPage(1);
          }}
          aria-pressed={staleOnly}
          title="Protection agents that have not checked in for two weeks: often a retired machine that still holds a licence"
          className={`rounded-lg border p-3 text-left ${staleOnly ? 'border-amber-500 bg-amber-500/10' : 'border-gray-800 bg-gray-900/60'}`}
        >
          <div className="text-xs text-gray-400">Stale agents</div>
          <div className="text-2xl font-semibold text-amber-300" data-testid="devices-stale">
            {data?.summary.stale_agents ?? '—'}
          </div>
        </button>
        <button
          type="button"
          onClick={() => {
            setAttentionOnly(!attentionOnly);
            setPage(1);
          }}
          aria-pressed={attentionOnly}
          className={`rounded-lg border p-3 text-left ${attentionOnly ? 'border-red-500 bg-red-500/10' : 'border-gray-800 bg-gray-900/60'}`}
        >
          <div className="text-xs text-gray-400">Needs attention</div>
          <div className="text-2xl font-semibold text-red-300" data-testid="devices-attention">
            {data?.summary.needs_attention ?? '—'}
          </div>
        </button>
        {(['addigy', 'threatmate', 'huntress'] as const).map((tool) => {
          const count = data?.summary[tool === 'addigy' ? 'not_in_addigy' : tool === 'threatmate' ? 'not_in_threatmate' : 'not_in_huntress'];
          const on = missing === tool;
          return (
            <button
              key={tool}
              type="button"
              onClick={() => {
                setMissing(on ? null : tool);
                setPage(1);
              }}
              aria-pressed={on}
              className={`rounded-lg border p-3 text-left ${on ? 'border-amber-500 bg-amber-500/10' : 'border-gray-800 bg-gray-900/60'}`}
            >
              <div className="text-xs text-gray-400">
                Not in {vendorLabel(tool)}
                {tool === 'addigy' && <span className="text-gray-500"> (Macs)</span>}
              </div>
              <div className="text-2xl font-semibold text-amber-300" data-testid={`devices-missing-${tool}`}>
                {count ?? '—'}
              </div>
            </button>
          );
        })}
        {([
          ['offline', 'Offline 7+ days', offlineOnly, () => setOfflineOnly((v) => !v), data?.summary.offline],
          ['alerts', 'With open alerts', alertsOnly, () => setAlertsOnly((v) => !v), data?.summary.with_alerts],
          ['hidden', 'Hidden until online', hiddenOnly, () => setHiddenOnly((v) => !v), data?.summary.hidden],
        ] as const).map(([key, label, on, toggle, count]) => (
          <button
            key={key}
            type="button"
            onClick={() => {
              toggle();
              setPage(1);
            }}
            aria-pressed={on}
            className={`rounded-lg border p-3 text-left ${on ? 'border-amber-500 bg-amber-500/10' : 'border-gray-800 bg-gray-900/60'}`}
          >
            <div className="text-xs text-gray-400">{label}</div>
            <div className="text-2xl font-semibold text-amber-300" data-testid={`devices-${key}`}>
              {count ?? '—'}
            </div>
          </button>
        ))}
      </div>

      <div className="flex flex-wrap gap-2">
        <input
          type="search"
          value={search}
          onChange={(e) => {
            setSearch(e.target.value);
            setPage(1);
          }}
          placeholder="Search name, serial or client"
          aria-label="Search devices"
          className="w-64 rounded-md border border-gray-700 bg-gray-900 px-3 py-1.5 text-sm text-white"
        />
        {clients.length > 0 && (
          <select
            aria-label="Client"
            value={clientId}
            onChange={(e) => {
              setClientId(e.target.value);
              setPage(1);
            }}
            className="rounded-md border border-gray-700 bg-gray-900 px-2 py-1.5 text-sm text-white"
          >
            <option value="">All clients</option>
            {clients.map((c) => (
              <option key={c.id} value={c.id}>
                {c.name}
              </option>
            ))}
          </select>
        )}
        <select
          aria-label="Reported by"
          value={vendor}
          onChange={(e) => {
            setVendor(e.target.value);
            setPage(1);
          }}
          className="rounded-md border border-gray-700 bg-gray-900 px-2 py-1.5 text-sm text-white"
        >
          <option value="">Any tool</option>
          {toolChoices.map((v) => (
            <option key={v} value={v}>
              {vendorLabel(v)}
            </option>
          ))}
        </select>
        <select
          aria-label="Operating system"
          value={os}
          onChange={(e) => {
            setOs(e.target.value);
            setPage(1);
          }}
          className="rounded-md border border-gray-700 bg-gray-900 px-2 py-1.5 text-sm text-white"
        >
          <option value="">Any OS</option>
          {OS_CHOICES.map((o) => (
            <option key={o.value} value={o.value}>
              {o.label}
            </option>
          ))}
        </select>
        <button type="button" onClick={() => void exportCsv()} className="rounded-md border border-gray-700 bg-gray-900 px-2 py-1.5 text-sm text-white hover:bg-gray-800">
          Export CSV
        </button>
      </div>
      {(data?.summary.long_offline ?? 0) > 0 && (
        <p data-testid="long-offline-note" className="text-xs text-gray-500">
          {data?.summary.long_offline} device{data?.summary.long_offline === 1 ? '' : 's'} offline for 10 days or more still show in the list and the offline count, but are left out of the other numbers.
        </p>
      )}

      <ClientRollupTable
        onPick={(id) => {
          setClientId(id);
          setPage(1);
        }}
      />

      <DuplicateDevices clientId={clientId || undefined} onChanged={() => void load()} />

      {error && (
        <div role="alert" className="flex flex-wrap items-center gap-3 rounded-md border border-red-500/40 bg-red-500/10 p-3 text-sm text-red-300">
          <span>{error}</span>
          <button type="button" onClick={() => void load()} className="rounded border border-red-400/40 px-2 py-0.5 text-xs hover:bg-red-500/20">
            Try again
          </button>
        </div>
      )}

      <div className="overflow-x-auto rounded-lg border border-gray-800">
        <table className="w-full text-left text-sm">
          <thead className="bg-gray-900 text-xs uppercase text-gray-400">
            <tr>
              <th className="px-3 py-2">Device</th>
              <th className="px-3 py-2">Client</th>
              <th className="px-3 py-2">Serial</th>
              <th className="px-3 py-2">OS</th>
              <th className="px-3 py-2">Fed by</th>
              <th className="px-3 py-2">Last online</th>
              <th className="px-3 py-2" title="When CORE last synced this device from its tools. Not when the device was online.">Last synced</th>
            </tr>
          </thead>
          <tbody>
            {data?.items.map((d) => (
              <DeviceRowView key={d.id} d={d} master={master} open={open === d.id} onToggle={() => setOpen(open === d.id ? null : d.id)} onHide={(hide) => void setHidden(d, hide)} />
            ))}
            {loading && !data && (
              <tr>
                <td colSpan={7} className="px-3 py-8 text-center text-gray-400" data-testid="devices-loading">
                  Loading devices... a large estate can take several seconds the first time.
                </td>
              </tr>
            )}
            {!loading && data?.items.length === 0 && (
              <tr>
                <td colSpan={7} className="px-3 py-8 text-center text-gray-400">
                  No devices match.
                </td>
              </tr>
            )}
          </tbody>
        </table>
      </div>

      {data && data.pages > 1 && (
        <div className="flex items-center gap-3 text-sm text-gray-300">
          <button type="button" disabled={page <= 1} onClick={() => setPage(page - 1)} className="rounded border border-gray-700 px-3 py-1 disabled:opacity-40">
            Previous
          </button>
          <span>
            Page {data.page} of {data.pages}
          </span>
          <button type="button" disabled={page >= data.pages} onClick={() => setPage(page + 1)} className="rounded border border-gray-700 px-3 py-1 disabled:opacity-40">
            Next
          </button>
        </div>
      )}
    </div>
  );
}

function DeviceRowView({ d, master, open, onToggle, onHide }: { d: DeviceRow; master: string | null; open: boolean; onToggle: () => void; onHide: (hide: boolean) => void }) {
  const tools = toolsOf(d);
  return (
    <>
      <tr onClick={onToggle} className="cursor-pointer border-t border-gray-800 hover:bg-gray-900/60">
        <td className="px-3 py-2 font-medium text-white">
          {d.online != null && (
            <span
              role="img"
              aria-label={d.online ? 'Online' : 'Offline'}
              title={d.online ? 'Online as of the last sync' : 'Offline as of the last sync'}
              className={`mr-2 inline-block h-2 w-2 rounded-full ${d.online ? 'bg-green-500' : 'bg-gray-500'}`}
            />
          )}
          {d.hostname}
          {(d.open_alerts ?? 0) > 0 && (
            <Link
              href={`/alerts?device=${encodeURIComponent(d.hostname)}`}
              onClick={(e) => e.stopPropagation()}
              title="Show this machine's alerts"
              className="ml-2 rounded bg-red-500/20 px-1.5 py-0.5 text-[11px] text-red-300 hover:bg-red-500/30"
            >
              {d.open_alerts} open alert{d.open_alerts === 1 ? '' : 's'}
            </Link>
          )}
          {discoveredOnNetwork(d) && (
            <span
              title="ThreatMate found this device by scanning the network. It has no management agent reporting in."
              className="ml-2 rounded bg-sky-500/20 px-1.5 py-0.5 text-[11px] text-sky-300"
            >
              Discovered on network
            </span>
          )}
          {!d.in_master && master && (
            <span className="ml-2 rounded bg-amber-500/20 px-1.5 py-0.5 text-[11px] text-amber-300">Not in {vendorLabel(master)}</span>
          )}
          {ransomwareLinked(d) && (
            <span title="ThreatMate says a known-exploited vulnerability on this device is used by ransomware." className="ml-2 rounded bg-red-500/20 px-1.5 py-0.5 text-[11px] text-red-300">
              Ransomware-linked CVE
            </span>
          )}
          {attentionOf(d).length > 0 && (
            <div className="mt-0.5 text-xs font-normal text-red-300" data-testid="attention-reason">
              {attentionOf(d)[0]}
              {attentionOf(d).length > 1 ? ` (+${attentionOf(d).length - 1} more)` : ''}
            </div>
          )}
        </td>
        <td className="px-3 py-2 text-gray-300">{d.client_name ?? '—'}</td>
        <td className="px-3 py-2 font-mono text-xs text-gray-300">{d.serial_number ?? '—'}</td>
        <td className="px-3 py-2 text-gray-300">{d.os ?? '—'}</td>
        <td className="px-3 py-2">
          <span className="flex gap-1">
            {tools.map((v) => (
              <VendorBadge key={v} vendor={v} />
            ))}
          </span>
        </td>
        <td className="px-3 py-2 text-gray-400">
          {d.last_online ? when(d.last_online) : '—'}
          {d.offline_days != null && <span className="ml-2 rounded bg-gray-700/60 px-1.5 py-0.5 text-[11px] text-gray-300">Offline {d.offline_days}d</span>}
          {d.hidden_since ? (
            <button
              type="button"
              title="Show this device in the list again"
              onClick={(e) => {
                e.stopPropagation();
                onHide(false);
              }}
              className="ml-2 rounded border border-gray-600 px-1.5 py-0.5 text-[11px] text-gray-200 hover:bg-gray-800"
            >
              Show again
            </button>
          ) : (
            d.offline_days != null && (
              <button
                type="button"
                title="Leave this device out of the list and the counts until a tool sees it online again"
                onClick={(e) => {
                  e.stopPropagation();
                  onHide(true);
                }}
                className="ml-2 rounded border border-gray-600 px-1.5 py-0.5 text-[11px] text-gray-200 hover:bg-gray-800"
              >
                Hide until online
              </button>
            )
          )}
        </td>
        <td className="px-3 py-2 text-gray-500">{when(d.last_seen)}</td>
      </tr>
      {open && (
        <tr className="border-t border-gray-800 bg-gray-900/40">
          <td colSpan={7} className="px-4 py-3 text-sm text-gray-300">
            <dl className="grid gap-x-6 gap-y-1 sm:grid-cols-2">
              <Field label="Manufacturer" value={d.manufacturer} />
              <Field label="Model" value={d.model} />
              <Field label="OS version" value={d.os_version} />
              <Field label="IP addresses" value={d.ip_addresses.join(', ')} />
              <Field label="First seen" value={when(d.first_seen)} />
              {specs(d).map(([label, value]) => (
                <Field key={label} label={label} value={value} />
              ))}
            </dl>
            <div className="mt-3">
              <Link
                href={`/alerts?device=${encodeURIComponent(d.hostname)}&status=all`}
                onClick={(e) => e.stopPropagation()}
                className="inline-block rounded border border-blue-500/40 bg-blue-500/10 px-3 py-1 text-xs text-blue-300 hover:bg-blue-500/20"
              >
                Show alerts{(d.open_alerts ?? 0) > 0 ? ` (${d.open_alerts} open)` : ''}
              </Link>
            </div>
            {(d.alerts ?? []).length > 0 && (
              <>
                <h3 className="mb-1 mt-3 text-xs font-semibold uppercase text-gray-400">Open alerts on this device</h3>
                <ul className="space-y-1">
                  {(d.alerts ?? []).map((a) => (
                    <li key={a.id} className="flex items-center gap-2">
                      <span className="rounded bg-gray-800 px-1.5 py-0.5 text-[11px] uppercase text-gray-300">{a.severity}</span>
                      <a href={`/alerts/${a.id}`} className="text-blue-300 hover:underline" onClick={(e) => e.stopPropagation()}>
                        {a.title}
                      </a>
                      <span className="ml-auto text-xs text-gray-500">{when(a.created_at)}</span>
                    </li>
                  ))}
                </ul>
              </>
            )}
            {attentionOf(d).length > 0 && (
              <div className="mt-3 rounded border border-red-500/30 bg-red-500/10 p-2 text-xs text-red-200" data-testid="device-attention">
                <div className="mb-1 font-semibold uppercase">Needs attention</div>
                <ul className="list-disc pl-4">
                  {attentionOf(d).map((a) => (
                    <li key={a}>{a}</li>
                  ))}
                </ul>
              </div>
            )}
            {protectionLines(d).length > 0 && (
              <div className="mt-3" data-testid="protection">
                <h3 className="mb-1 text-xs font-semibold uppercase text-gray-400">Protection (Huntress)</h3>
                <dl className="grid gap-x-6 gap-y-0.5 text-xs sm:grid-cols-2">
                  {protectionLines(d).map(([k, v]) => (
                    <div key={k} className="flex gap-2">
                      <dt className="w-40 shrink-0 text-gray-500">{k}</dt>
                      <dd className="text-gray-200">{v}</dd>
                    </div>
                  ))}
                </dl>
              </div>
            )}
            <h3 className="mb-1 mt-3 text-xs font-semibold uppercase text-gray-400">Feeding this device</h3>
            <ul className="space-y-1">
              {d.sources.map((s) => (
                <li key={`${s.vendor}-${s.name}`} className="flex items-center gap-2">
                  <VendorBadge vendor={s.vendor} />
                  <span>{vendorLabel(s.vendor)}</span>
                  {s.name && <span className="text-gray-400">as “{s.name}”</span>}
                  <span className="ml-auto text-xs text-gray-500">seen {when(s.last_seen)}</span>
                  {facts(s).length > 0 && (
                    <details className="basis-full pl-8 text-xs text-gray-400">
                      <summary className="cursor-pointer text-gray-300">All details from {vendorLabel(s.vendor)}</summary>
                      <dl className="mt-1 grid gap-x-6 gap-y-0.5 sm:grid-cols-2">
                        {facts(s).map(([k, v]) => (
                          <div key={k} className="flex gap-2">
                            <dt className="w-44 shrink-0 text-gray-500">{k}</dt>
                            <dd className="break-all">{v}</dd>
                          </div>
                        ))}
                      </dl>
                    </details>
                  )}
                </li>
              ))}
            </ul>
          </td>
        </tr>
      )}
    </>
  );
}

/** What Huntress reports about a machine's protection, in plain words, for the expanded row. Empty when Huntress does not report this device. */
export function protectionLines(d: DeviceRow): [string, string][] {
  const h = d.sources.find((s) => s.vendor === 'huntress')?.details as Record<string, unknown> | undefined;
  if (!h) return [];
  const text = (v: unknown): string | null => (typeof v === 'string' && v.trim() !== '' ? v.trim() : null);
  const out: [string, string][] = [];
  const defender = text(h.defender_status);
  const sub = text(h.defender_substatus);
  if (defender) out.push(['Microsoft Defender', sub ? `${defender} (${sub})` : defender]);
  const policy = text(h.defender_policy_status);
  if (policy) out.push(['Defender policy', policy]);
  const firewall = text(h.firewall_status);
  if (firewall) out.push(['Windows firewall', firewall]);
  if (h.tamper_protection_configured === true) out.push(['Tamper protection', h.tamper_protection_actual === true ? 'On, and in force' : 'Configured, but NOT in force']);
  else if (h.tamper_protection_configured === false) out.push(['Tamper protection', 'Not configured']);
  const days = typeof h.days_since_checkin === 'number' ? h.days_since_checkin : null;
  if (days !== null) out.push(['Huntress agent checked in', days === 0 ? 'today' : `${days} day${days === 1 ? '' : 's'} ago`]);
  const edr = text(h.edr_version);
  if (edr) out.push(['Huntress version', edr]);
  return out;
}

/** True when any tool says a known-exploited vulnerability on this device is one ransomware is known to use (ThreatMate's ``kev_ransomware``). */
export function ransomwareLinked(d: DeviceRow): boolean {
  return d.sources.some((s) => s.details?.kev_ransomware === true);
}

/** The message shown when the device list cannot load: the API's own reason when it gave one, and where to look next. */
export function devicesLoadError(err: unknown): string {
  const reason = apiErrorDetail(err) ?? (err instanceof Error ? err.message : '');
  const status = typeof (err as { status?: unknown })?.status === 'number' ? ` (error ${(err as { status: number }).status})` : '';
  return `Could not load devices${status}${reason ? `: ${reason}` : ''}. Try again in a moment; if it keeps happening, Settings, Platform health shows whether the database is under strain.`;
}

/** What the tools say needs a person's attention on this device (Huntress: not checking in, Defender or firewall unhealthy, tamper protection not in force). */
export function attentionOf(d: DeviceRow): string[] {
  return d.sources.flatMap((s) => (Array.isArray(s.details?.needs_attention) ? (s.details.needs_attention as unknown[]).filter((x): x is string => typeof x === 'string' && x !== '') : []));
}

/** True when a tool says it only found this device by scanning the network (ThreatMate's asset source), not through an agent. */
export function discoveredOnNetwork(d: DeviceRow): boolean {
  return d.sources.some((s) => s.details?.discovered_on_network === true);
}

/** Memory, processor and disks from whichever feed reports them (first one wins), as label/value pairs. */
export function specs(d: DeviceRow): [string, string][] {
  const out: [string, string][] = [];
  const pick = (key: string) => d.sources.map((s) => s.details?.[key]).find((v) => v !== undefined && v !== null);
  const mem = pick('memory_gb');
  if (typeof mem === 'number') out.push(['Memory', `${mem} GB`]);
  const cpu = pick('processor');
  const cores = pick('cpu_cores');
  if (typeof cpu === 'string') out.push(['Processor', typeof cores === 'number' ? `${cpu} (${cores} cores)` : cpu]);
  const disks = pick('disks');
  if (Array.isArray(disks) && disks.length > 0) {
    out.push([
      'Disks',
      disks
        .map((x: { name?: string; size_gb?: number; free_gb?: number }) => `${x.name ?? 'disk'} ${x.size_gb} GB${typeof x.free_gb === 'number' ? ` (${x.free_gb} free)` : ''}`)
        .join(', '),
    ]);
  }
  return out;
}

/** Every fact a feed reported, as label/value pairs: ``os.buildNumber`` becomes "Os build number". */
export function facts(s: DeviceRow['sources'][number]): [string, string][] {
  const raw = s.details?.facts;
  if (raw === null || typeof raw !== 'object') return [];
  return Object.entries(raw as Record<string, unknown>).map(([k, v]) => {
    const words = k
      .replace(/\./g, ' ')
      .replace(/([a-z0-9])([A-Z])/g, '$1 $2')
      .toLowerCase();
    return [words.charAt(0).toUpperCase() + words.slice(1), String(v)];
  });
}

function Field({ label, value }: { label: string; value: string | null }) {
  return (
    <div className="flex gap-2">
      <dt className="w-28 shrink-0 text-gray-500">{label}</dt>
      <dd>{value || '—'}</dd>
    </div>
  );
}
