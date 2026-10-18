'use client';

import { useEffect, useState } from 'react';
import toast from 'react-hot-toast';
import { devicesApi, type DeviceRow, type DuplicatePair } from '@/lib/api';
import VendorBadge from '@/components/mssp/VendorBadge';
import { vendorLabel } from '@/components/mssp/ClientMapping';

/**
 * Devices that share a name but have no serial number to prove they are the same machine are never merged automatically. They are listed here for a person to decide:
 * merge them into one, or say they are different machines. The decision is remembered for the whole organization.
 */

function tools(d: DeviceRow): string[] {
  return [...new Set(d.sources.map((s) => s.vendor))].sort();
}

const VENDOR_FACTS: [string, string][] = [
  ['agent_version', 'Agent version'],
  ['edr_version', 'EDR version'],
  ['node_class', 'Type'],
  ['discovery_source', 'Found by'],
  ['last_online', 'Last online'],
  ['last_contact', 'Last contact'],
  ['last_callback_at', 'Last check-in'],
  ['public_ip', 'Public IP'],
];

function stamp(value: string | null | undefined): string {
  if (!value) return '—';
  const t = Date.parse(value);
  return Number.isNaN(t) ? String(value) : new Date(t).toISOString().slice(0, 16).replace('T', ' ') + ' UTC';
}

/** The rows of the side-by-side comparison: what a person weighs up before merging two machines. A row is "same" when both sides agree. */
export function compareRows(a: DeviceRow, b: DeviceRow): { label: string; a: string; b: string; same: boolean }[] {
  const text = (v: unknown): string => (v === null || v === undefined || v === '' ? '—' : String(v));
  const rows: [string, string, string][] = [
    ['Name', a.hostname, b.hostname],
    ['Serial number', text(a.serial_number), text(b.serial_number)],
    ['Operating system', [a.os, a.os_version].filter(Boolean).join(' ') || '—', [b.os, b.os_version].filter(Boolean).join(' ') || '—'],
    ['Make and model', [a.manufacturer, a.model].filter(Boolean).join(' ') || '—', [b.manufacturer, b.model].filter(Boolean).join(' ') || '—'],
    ['IP addresses', a.ip_addresses.join(', ') || '—', b.ip_addresses.join(', ') || '—'],
    ['First seen', stamp(a.first_seen), stamp(b.first_seen)],
    ['Last online', stamp(a.last_online), stamp(b.last_online)],
    ['Online now', a.online === null || a.online === undefined ? '—' : a.online ? 'Yes' : 'No', b.online === null || b.online === undefined ? '—' : b.online ? 'Yes' : 'No'],
    ['Open alerts', String(a.open_alerts ?? 0), String(b.open_alerts ?? 0)],
  ];
  return rows.map(([label, x, y]) => ({ label, a: x, b: y, same: x.toLowerCase() === y.toLowerCase() }));
}

/** The tool-reported facts worth comparing for one side, e.g. "NinjaOne: Last online 2026-10-18 20:35 UTC". */
export function sourceFacts(d: DeviceRow): { vendor: string; name: string; seen: string; facts: [string, string][]; attention: string[] }[] {
  return d.sources.map((s) => {
    const details = (s.details ?? {}) as Record<string, unknown>;
    const facts: [string, string][] = [];
    for (const [key, label] of VENDOR_FACTS) {
      const v = details[key];
      if (typeof v === 'string' && v) facts.push([label, key.includes('last') ? stamp(v) : v]);
    }
    const attention = Array.isArray(details.needs_attention) ? (details.needs_attention as unknown[]).filter((x): x is string => typeof x === 'string' && x !== '') : [];
    return { vendor: s.vendor, name: s.name ?? '', seen: stamp(s.last_seen), facts, attention };
  });
}

/** Tools that list BOTH devices (as separate records). When one tool already counts them as two machines, that is a reason to think they really are two. */
export function sharedTools(a: DeviceRow, b: DeviceRow): string[] {
  const mine = new Set(a.sources.map((s) => s.vendor));
  return [...new Set(b.sources.map((s) => s.vendor))].filter((v) => mine.has(v)).sort();
}

function Compare({ a, b }: { a: DeviceRow; b: DeviceRow }) {
  const rows = compareRows(a, b);
  const shared = sharedTools(a, b);
  const sides = [a, b];
  return (
    <div className="mt-3 w-full border-t border-gray-800 pt-3 text-xs" data-testid="duplicate-compare">
      {shared.length > 0 && (
        <p className="mb-2 rounded border border-sky-500/30 bg-sky-500/10 p-2 text-sky-200">
          {shared.map((v) => vendorLabel(v)).join(' and ')} already lists these as two separate machines, so they may really be two.
        </p>
      )}
      <table className="w-full text-left">
        <thead>
          <tr className="text-gray-500">
            <th className="w-36 py-1 font-normal" />
            <th className="py-1 font-medium text-gray-300">First</th>
            <th className="py-1 font-medium text-gray-300">Second</th>
          </tr>
        </thead>
        <tbody>
          {rows.map((r) => (
            <tr key={r.label} className="border-t border-gray-800/70">
              <th className="py-1 pr-2 font-normal text-gray-500">{r.label}</th>
              <td className={r.same ? 'py-1 text-gray-400' : 'py-1 text-amber-300'}>{r.a}</td>
              <td className={r.same ? 'py-1 text-gray-400' : 'py-1 text-amber-300'}>{r.b}</td>
            </tr>
          ))}
        </tbody>
      </table>
      <div className="mt-2 grid gap-3 sm:grid-cols-2">
        {sides.map((d, i) => (
          <div key={d.id}>
            <div className="mb-1 font-medium text-gray-300">{i === 0 ? 'First' : 'Second'}: reported by</div>
            {sourceFacts(d).map((s) => (
              <div key={`${s.vendor}-${s.name}`} className="mb-1 text-gray-400">
                <span className="text-gray-200">{vendorLabel(s.vendor)}</span>
                {s.name ? <> as “{s.name}”</> : null}, synced {s.seen}
                {s.facts.map(([k, v]) => (
                  <div key={k} className="pl-3">
                    {k}: {v}
                  </div>
                ))}
                {s.attention.map((x) => (
                  <div key={x} className="pl-3 text-red-300">
                    ⚠ {x}
                  </div>
                ))}
              </div>
            ))}
            {(d.alerts ?? []).slice(0, 3).map((al) => (
              <div key={al.id} className="pl-3 text-gray-400">
                Alert: {al.title}
              </div>
            ))}
          </div>
        ))}
      </div>
    </div>
  );
}

function Side({ d }: { d: DeviceRow }) {
  return (
    <div className="min-w-0 flex-1">
      <div className="truncate text-sm font-medium text-white">{d.hostname}</div>
      <div className="mt-0.5 flex flex-wrap items-center gap-1 text-xs text-gray-400">
        {tools(d).map((v) => (
          <VendorBadge key={v} vendor={v} />
        ))}
        <span>{[d.os, d.model].filter(Boolean).join(' · ') || 'no details'}</span>
      </div>
    </div>
  );
}

export default function DuplicateDevices({ clientId, onChanged }: { clientId?: string; onChanged: () => void }) {
  const [pairs, setPairs] = useState<DuplicatePair[]>([]);
  const [busy, setBusy] = useState<string | null>(null);
  const [open, setOpen] = useState<string | null>(null);

  const [reloads, setReloads] = useState(0);

  useEffect(() => {
    let live = true;
    devicesApi
      .duplicates(clientId)
      .then((r) => live && setPairs(r.items))
      .catch(() => live && setPairs([])); // a side panel: the device list itself reports its own failures
    return () => {
      live = false;
    };
  }, [clientId, reloads]);

  const act = async (key: string, work: () => Promise<unknown>, done: string) => {
    setBusy(key);
    try {
      await work();
      toast.success(done);
      setReloads((n) => n + 1);
      onChanged();
    } catch (err) {
      toast.error(err instanceof Error ? err.message : 'That did not work.');
    } finally {
      setBusy(null);
    }
  };

  if (pairs.length === 0) return null;
  return (
    <section role="region" aria-label="Possible duplicate devices" className="rounded-lg border border-amber-500/30 bg-amber-500/5 p-4">
      <h2 className="text-xs font-medium uppercase tracking-wider text-amber-400">Possible duplicates ({pairs.length})</h2>
      <p className="mt-1 text-xs text-gray-400">Same name, and no serial number to tell whether they are one machine. Nothing is merged until you say so.</p>
      <ul className="mt-3 space-y-2">
        {pairs.map(({ a, b }) => {
          const key = `${a.id}:${b.id}`;
          const expanded = open === key;
          return (
            <li
              key={key}
              className="flex cursor-pointer flex-wrap items-center gap-3 rounded-md border border-gray-800 bg-gray-900/60 p-3 hover:border-gray-700"
              onClick={() => setOpen(expanded ? null : key)}
            >
              <button
                type="button"
                aria-expanded={expanded}
                aria-label={`${expanded ? 'Hide' : 'Show'} details of ${a.hostname}`}
                onClick={(e) => {
                  e.stopPropagation();
                  setOpen(expanded ? null : key);
                }}
                className="shrink-0 text-xs text-gray-400 hover:text-white"
              >
                {expanded ? '▾' : '▸'}
              </button>
              <span className="w-28 shrink-0 truncate text-xs text-gray-400">{a.client_name}</span>
              <Side d={a} />
              <Side d={b} />
              <div className="flex shrink-0 flex-wrap gap-2" onClick={(e) => e.stopPropagation()}>
                <button
                  type="button"
                  disabled={busy === key}
                  onClick={() => void act(key, () => devicesApi.mergeDuplicates(a.id, b.id), `Merged into the first ${a.hostname}.`)}
                  className="rounded-md bg-amber-600/80 px-2 py-1 text-xs text-white hover:bg-amber-600 disabled:opacity-50"
                  aria-label={`Merge ${b.hostname} into the first ${a.hostname}`}
                >
                  Merge into first
                </button>
                <button
                  type="button"
                  disabled={busy === key}
                  onClick={() => void act(key, () => devicesApi.mergeDuplicates(b.id, a.id), `Merged into the second ${b.hostname}.`)}
                  className="rounded-md bg-amber-600/80 px-2 py-1 text-xs text-white hover:bg-amber-600 disabled:opacity-50"
                  aria-label={`Merge ${a.hostname} into the second ${b.hostname}`}
                >
                  Merge into second
                </button>
                <button
                  type="button"
                  disabled={busy === key}
                  onClick={() => void act(key, () => devicesApi.dismissDuplicate(a.id, b.id), 'Got it. They will not be suggested again.')}
                  className="rounded-md px-2 py-1 text-xs text-gray-300 hover:bg-gray-800 disabled:opacity-50"
                >
                  Not a duplicate
                </button>
              </div>
              {expanded && <Compare a={a} b={b} />}
            </li>
          );
        })}
      </ul>
    </section>
  );
}
