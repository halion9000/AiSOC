'use client';

/**
 * Devices by client: how many each client has, and how many need attention, have a protection agent that has gone quiet, are missing from Huntress, or have been offline a week.
 * Worst clients first. Picking a row narrows the Devices list to that client.
 */
import { useEffect, useState } from 'react';
import { devicesApi, type ClientRollup } from '@/lib/api';

export function ClientRollupTable({ onPick }: { onPick: (clientId: string) => void }) {
  const [rows, setRows] = useState<ClientRollup[] | null>(null);
  const [open, setOpen] = useState(false);

  useEffect(() => {
    if (!open || rows !== null) return;
    let live = true;
    void (async () => {
      try {
        const r = await devicesApi.rollup();
        if (live) setRows(r);
      } catch {
        if (live) setRows([]); // a side panel: the main list reports its own failures
      }
    })();
    return () => {
      live = false;
    };
  }, [open, rows]);

  return (
    <section aria-label="Devices by client" className="rounded-lg border border-gray-800 bg-gray-900/40">
      <button type="button" aria-expanded={open} onClick={() => setOpen(!open)} className="flex w-full items-center gap-2 px-4 py-2 text-left text-sm text-gray-300 hover:text-white">
        <span>{open ? '▾' : '▸'}</span>
        <span className="font-medium">By client</span>
        <span className="text-xs text-gray-500">which clients have the most devices that need a look</span>
      </button>
      {open && (
        <div className="overflow-x-auto px-4 pb-3">
          {rows === null ? (
            <p className="py-3 text-sm text-gray-400" data-testid="rollup-loading">
              Loading...
            </p>
          ) : rows.length === 0 ? (
            <p className="py-3 text-sm text-gray-400">No devices yet.</p>
          ) : (
            <table className="w-full text-left text-sm">
              <thead className="text-xs uppercase text-gray-500">
                <tr>
                  <th className="py-1 pr-3">Client</th>
                  <th className="px-2 text-right">Devices</th>
                  <th className="px-2 text-right">Need attention</th>
                  <th className="px-2 text-right">Stale agent</th>
                  <th className="px-2 text-right">Not in Huntress</th>
                  <th className="px-2 text-right">Offline 7+ days</th>
                </tr>
              </thead>
              <tbody>
                {rows.map((r) => (
                  <tr key={r.client_id} onClick={() => onPick(r.client_id)} className="cursor-pointer border-t border-gray-800 hover:bg-gray-900/60">
                    <td className="py-1.5 pr-3 text-gray-200">{r.client_name ?? 'Your own organization'}</td>
                    <td className="px-2 text-right text-gray-300">{r.devices}</td>
                    <td className={`px-2 text-right ${r.needs_attention > 0 ? 'text-red-300' : 'text-gray-500'}`}>{r.needs_attention}</td>
                    <td className={`px-2 text-right ${r.stale_agents > 0 ? 'text-amber-300' : 'text-gray-500'}`}>{r.stale_agents}</td>
                    <td className={`px-2 text-right ${r.not_in_huntress > 0 ? 'text-amber-300' : 'text-gray-500'}`}>{r.not_in_huntress}</td>
                    <td className="px-2 text-right text-gray-400">{r.offline}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}
        </div>
      )}
    </section>
  );
}
