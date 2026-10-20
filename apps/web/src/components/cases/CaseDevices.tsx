'use client';

import Link from 'next/link';
import useSWR from 'swr';
import { casesApi } from '@/lib/api';

/** The machines this case is about, each with a link into every tool that knows it (Huntress, NinjaOne), and to its alerts here. Shows nothing when the case names no machine. */
export function CaseDevices({ caseId }: { caseId: string }) {
  const { data } = useSWR(['case:devices', caseId], () => casesApi.devices(caseId), { shouldRetryOnError: false });
  if (!Array.isArray(data) || data.length === 0) return null;
  return (
    <div className="overflow-hidden rounded-xl border border-slate-800/80 bg-slate-900/40" data-testid="case-devices">
      <div className="border-b border-slate-800/80 px-3 py-2">
        <h3 className="text-xs font-semibold uppercase tracking-wide text-slate-300">Devices ({data.length})</h3>
      </div>
      <ul className="divide-y divide-slate-800/60">
        {data.map((d) => (
          <li key={d.hostname} className="space-y-1.5 px-3 py-2 text-xs">
            <div className="flex items-baseline justify-between gap-2">
              <span className="break-all font-mono text-slate-200">{d.hostname}</span>
              {d.os && <span className="shrink-0 text-[10px] text-slate-500">{d.os}</span>}
            </div>
            <div className="flex flex-wrap gap-1.5">
              {d.links.map((l) => (
                <a
                  key={l.vendor}
                  href={l.url}
                  target="_blank"
                  rel="noopener noreferrer"
                  className="rounded border border-slate-700 px-2 py-0.5 text-[11px] text-blue-300 hover:border-slate-600 hover:text-blue-200"
                >
                  Open in {l.label} ↗
                </a>
              ))}
              <Link href={`/devices?search=${encodeURIComponent(d.hostname)}`} className="rounded border border-slate-700 px-2 py-0.5 text-[11px] text-slate-300 hover:border-slate-600">
                In Devices
              </Link>
            </div>
            {d.links.length === 0 && <p className="text-[11px] text-slate-500">No tool has given a link to this machine yet.</p>}
          </li>
        ))}
      </ul>
    </div>
  );
}
