'use client';

/**
 * Devices a tool reports for one of its clients that is not mapped to a client here yet. A device needs a client to be stored, so they are not in the list below; this panel is where to find
 * them, by tool and client, with the machine names, and a link to map the client. Backed by GET /api/v1/devices/unmapped.
 */

import { useState } from 'react';
import Link from 'next/link';
import useSWR from 'swr';
import { devicesApi } from '@/lib/api';
import VendorBadge from '@/components/mssp/VendorBadge';
import { vendorLabel } from '@/components/mssp/ClientMapping';

export default function UnmappedDevices() {
  const { data } = useSWR('devices-unmapped', () => devicesApi.unmapped().catch(() => []), { revalidateOnFocus: false });
  const [open, setOpen] = useState(false);
  const [expanded, setExpanded] = useState<string | null>(null);
  const groups = data ?? [];
  if (groups.length === 0) return null;
  const total = groups.reduce((n, g) => n + g.devices, 0);

  return (
    <section className="rounded-lg border border-amber-500/40 bg-amber-500/5" data-testid="unmapped-devices">
      <button type="button" aria-expanded={open} onClick={() => setOpen((v) => !v)} className="flex w-full items-center gap-2 px-4 py-3 text-left">
        <span aria-hidden="true" className="text-xs text-amber-300">
          {open ? '▾' : '▸'}
        </span>
        <span className="text-sm font-semibold uppercase text-amber-300">Waiting for a client ({total})</span>
        <span className="text-xs text-gray-400">devices tools report for clients not mapped yet: they are not in the list until the client is mapped</span>
      </button>
      {open && (
        <div className="overflow-x-auto px-4 pb-4">
          <table className="min-w-full text-left text-sm">
            <thead className="text-xs uppercase text-gray-500">
              <tr>
                <th className="px-2 py-1">Tool</th>
                <th className="px-2 py-1">Its client</th>
                <th className="px-2 py-1 text-right">Devices</th>
                <th className="px-2 py-1">Machines</th>
                <th className="px-2 py-1" />
              </tr>
            </thead>
            <tbody>
              {groups.map((g) => {
                const key = `${g.vendor}:${g.vendor_client_id}`;
                const shown = expanded === key ? g.hostnames : g.hostnames.slice(0, 5);
                return (
                  <tr key={key} className="border-t border-gray-800 align-top" data-testid="unmapped-group">
                    <td className="px-2 py-2">
                      <span className="flex items-center gap-2">
                        <VendorBadge vendor={g.vendor} />
                        <span className="text-gray-200">{vendorLabel(g.vendor)}</span>
                      </span>
                    </td>
                    <td className="px-2 py-2 text-gray-300">{g.name ?? <span className="font-mono text-xs text-gray-500">{g.vendor_client_id}</span>}</td>
                    <td className="px-2 py-2 text-right tabular-nums text-gray-200">{g.devices}</td>
                    <td className="px-2 py-2 text-xs text-gray-400">
                      {shown.join(', ')}
                      {g.hostnames.length > 5 && (
                        <button type="button" onClick={() => setExpanded(expanded === key ? null : key)} className="ml-2 text-blue-300 hover:underline">
                          {expanded === key ? 'show fewer' : `show all ${g.hostnames.length}`}
                        </button>
                      )}
                    </td>
                    <td className="px-2 py-2 text-right">
                      <Link href={`/mssp?vendor=${encodeURIComponent(g.vendor)}`} className="rounded border border-amber-500/40 px-2 py-1 text-xs text-amber-200 hover:bg-amber-500/10">
                        Map clients
                      </Link>
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>
      )}
    </section>
  );
}
