'use client';

import { useEffect, useState } from 'react';
import toast from 'react-hot-toast';
import { devicesApi, type DeviceRow, type DuplicatePair } from '@/lib/api';
import VendorBadge from '@/components/mssp/VendorBadge';

/**
 * Devices that share a name but have no serial number to prove they are the same machine are never merged automatically. They are listed here for a person to decide:
 * merge them into one, or say they are different machines. The decision is remembered for the whole organization.
 */

function tools(d: DeviceRow): string[] {
  return [...new Set(d.sources.map((s) => s.vendor))].sort();
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
          return (
            <li key={key} className="flex flex-wrap items-center gap-3 rounded-md border border-gray-800 bg-gray-900/60 p-3">
              <span className="w-28 shrink-0 truncate text-xs text-gray-400">{a.client_name}</span>
              <Side d={a} />
              <Side d={b} />
              <div className="flex shrink-0 flex-wrap gap-2">
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
            </li>
          );
        })}
      </ul>
    </section>
  );
}
