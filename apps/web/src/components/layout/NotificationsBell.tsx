'use client';

import { useEffect, useRef, useState } from 'react';
import Link from 'next/link';
import useSWR from 'swr';
import { safeDistance } from '@/lib/safe-date';
import { alertsApi, type Alert } from '@/lib/api';

/** The newest critical and high alerts nobody has picked up yet, newest first. */
export function needsAttention(critical: Alert[], high: Alert[], limit = 6): Alert[] {
  return [...critical, ...high].sort((a, b) => Date.parse(b.createdAt) - Date.parse(a.createdAt)).slice(0, limit);
}

export function NotificationsBell() {
  const [open, setOpen] = useState(false);
  const box = useRef<HTMLDivElement>(null);
  const { data, error, isLoading } = useSWR(
    'topbar-notifications',
    async () => {
      const [critical, high] = await Promise.all([
        alertsApi.list({ severity: 'critical', status: 'new', pageSize: 6 }),
        alertsApi.list({ severity: 'high', status: 'new', pageSize: 6 }),
      ]);
      return { criticalCount: critical.total, highCount: high.total, items: needsAttention(critical.alerts, high.alerts) };
    },
    { refreshInterval: 60_000, shouldRetryOnError: false },
  );

  useEffect(() => {
    if (!open) return;
    const onDown = (e: MouseEvent) => {
      if (box.current && !box.current.contains(e.target as Node)) setOpen(false);
    };
    const onKey = (e: KeyboardEvent) => {
      if (e.key === 'Escape') setOpen(false);
    };
    document.addEventListener('mousedown', onDown);
    document.addEventListener('keydown', onKey);
    return () => {
      document.removeEventListener('mousedown', onDown);
      document.removeEventListener('keydown', onKey);
    };
  }, [open]);

  const criticalCount = data?.criticalCount ?? 0;
  const total = criticalCount + (data?.highCount ?? 0);

  return (
    <div ref={box} className="relative">
      <button
        type="button"
        aria-label="Open notifications"
        aria-expanded={open}
        onClick={() => setOpen((o) => !o)}
        className="relative p-1.5 text-fg-muted hover:text-fg-primary transition-colors focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-brand-500/50"
      >
        <svg className="w-5 h-5" fill="none" viewBox="0 0 24 24" stroke="currentColor" aria-hidden>
          <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={1.5} d="M14.857 17.082a23.848 23.848 0 005.454-1.31A8.967 8.967 0 0118 9.75v-.7V9A6 6 0 006 9v.75a8.967 8.967 0 01-2.312 6.022c1.733.64 3.56 1.085 5.455 1.31m5.714 0a24.255 24.255 0 01-5.714 0m5.714 0a3 3 0 11-5.714 0" />
        </svg>
        {criticalCount > 0 ? (
          <span aria-hidden data-testid="bell-dot" className="absolute top-1 right-1 w-2 h-2 bg-red-500 rounded-full ring-2 ring-surface-raised" />
        ) : null}
      </button>

      {open ? (
        <div role="dialog" aria-label="Notifications" className="absolute right-0 mt-2 w-80 rounded-xl border border-gray-800 bg-gray-900 shadow-xl z-50">
          <div className="px-4 py-3 border-b border-gray-800">
            <p className="text-sm font-medium text-gray-100">Needs attention</p>
            <p className="text-xs text-gray-500">
              {error ? 'Could not load alerts.' : isLoading ? 'Loading…' : total === 0 ? 'No new critical or high alerts.' : `${criticalCount} critical, ${data?.highCount ?? 0} high, not yet picked up`}
            </p>
          </div>
          {data && data.items.length > 0 ? (
            <ul className="max-h-80 overflow-auto divide-y divide-gray-800/60">
              {data.items.map((a) => (
                <li key={a.id}>
                  <Link href={`/alerts/${a.id}`} onClick={() => setOpen(false)} className="block px-4 py-2.5 hover:bg-gray-800/50">
                    <p className="text-sm text-gray-200 truncate">{a.title}</p>
                    <p className="text-xs text-gray-500">
                      <span className={a.severity === 'critical' ? 'text-red-400' : 'text-orange-400'}>{a.severity}</span>
                      {a.clientName ? ` · ${a.clientName}` : ''} · {safeDistance(a.createdAt, { addSuffix: true })}
                    </p>
                  </Link>
                </li>
              ))}
            </ul>
          ) : null}
          <Link href="/alerts" onClick={() => setOpen(false)} className="block px-4 py-2.5 text-sm text-blue-400 hover:bg-gray-800/50 border-t border-gray-800 rounded-b-xl">
            View all alerts
          </Link>
        </div>
      ) : null}
    </div>
  );
}
