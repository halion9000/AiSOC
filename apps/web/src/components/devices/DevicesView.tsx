'use client';

import { useCallback, useEffect, useState } from 'react';
import toast from 'react-hot-toast';
import { devicesApi, msspApi, type ChildTenant, type DeviceList, type DeviceRow } from '@/lib/api';
import VendorBadge from '@/components/mssp/VendorBadge';
import { vendorLabel } from '@/components/mssp/ClientMapping';

/**
 * Every machine across your clients, one row per device. The same laptop reported by NinjaOne, Addigy and Huntress is ONE row (matched on serial number) and shows
 * each tool that feeds it. Pick a master tool (usually the RMM) and devices it does not report are flagged: a machine another tool sees that your RMM does not.
 */

const MASTER_CHOICES = ['ninjaone', 'addigy', 'threatmate'];

type Missing = 'addigy' | 'threatmate';

export function toolsOf(d: DeviceRow): string[] {
  return [...new Set(d.sources.map((s) => s.vendor))].sort();
}

function when(iso: string): string {
  const t = new Date(iso);
  return Number.isNaN(t.getTime()) ? '' : t.toLocaleString();
}

export default function DevicesView() {
  const [data, setData] = useState<DeviceList | null>(null);
  const [clients, setClients] = useState<ChildTenant[]>([]);
  const [error, setError] = useState('');
  const [loading, setLoading] = useState(true);
  const [page, setPage] = useState(1);
  const [search, setSearch] = useState('');
  const [clientId, setClientId] = useState('');
  const [vendor, setVendor] = useState('');
  const [gapsOnly, setGapsOnly] = useState(false);
  const [missing, setMissing] = useState<Missing | null>(null);
  const [open, setOpen] = useState<string | null>(null);

  const load = useCallback(async () => {
    setLoading(true);
    setError('');
    try {
      setData(await devicesApi.list({ page, pageSize: 50, clientId: clientId || undefined, search, vendor: vendor || undefined, notInMaster: gapsOnly, missing: missing ?? undefined }));
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Could not load devices.');
    } finally {
      setLoading(false);
    }
  }, [page, clientId, search, vendor, gapsOnly, missing]);

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

      <div className="grid grid-cols-2 gap-3 sm:max-w-3xl sm:grid-cols-4">
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
        {(['addigy', 'threatmate'] as const).map((tool) => {
          const count = data?.summary[tool === 'addigy' ? 'not_in_addigy' : 'not_in_threatmate'];
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
      </div>

      {error && (
        <p role="alert" className="rounded-md border border-red-500/40 bg-red-500/10 p-3 text-sm text-red-300">
          {error}
        </p>
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
              <th className="px-3 py-2">Last seen</th>
            </tr>
          </thead>
          <tbody>
            {data?.items.map((d) => (
              <DeviceRowView key={d.id} d={d} master={master} open={open === d.id} onToggle={() => setOpen(open === d.id ? null : d.id)} />
            ))}
            {!loading && data?.items.length === 0 && (
              <tr>
                <td colSpan={6} className="px-3 py-8 text-center text-gray-400">
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

function DeviceRowView({ d, master, open, onToggle }: { d: DeviceRow; master: string | null; open: boolean; onToggle: () => void }) {
  const tools = toolsOf(d);
  return (
    <>
      <tr onClick={onToggle} className="cursor-pointer border-t border-gray-800 hover:bg-gray-900/60">
        <td className="px-3 py-2 font-medium text-white">
          {d.hostname}
          {(d.open_alerts ?? 0) > 0 && (
            <span className="ml-2 rounded bg-red-500/20 px-1.5 py-0.5 text-[11px] text-red-300">
              {d.open_alerts} open alert{d.open_alerts === 1 ? '' : 's'}
            </span>
          )}
          {!d.in_master && master && (
            <span className="ml-2 rounded bg-amber-500/20 px-1.5 py-0.5 text-[11px] text-amber-300">Not in {vendorLabel(master)}</span>
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
        <td className="px-3 py-2 text-gray-400">{when(d.last_seen)}</td>
      </tr>
      {open && (
        <tr className="border-t border-gray-800 bg-gray-900/40">
          <td colSpan={6} className="px-4 py-3 text-sm text-gray-300">
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
