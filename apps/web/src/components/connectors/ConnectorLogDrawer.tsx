'use client';

/**
 * The running log of one connector: what it reported, newest first.
 *
 * The card shows only the latest message. The API adds a line here when a connector's status or message changes (never on a repeat), so a card that says "Warning" can be
 * traced back to when it started and what it said before. Refreshes while open.
 */

import { useEffect } from 'react';
import useSWR from 'swr';
import { clsx } from 'clsx';
import { connectorsApi, type Connector, type ConnectorLogEntry } from '@/lib/api';

const ENTRY_STYLE: Record<ConnectorLogEntry['status'], { label: string; dot: string; text: string }> = {
  ok: { label: 'Healthy', dot: 'bg-green-400', text: 'text-green-400' },
  warning: { label: 'Warning', dot: 'bg-amber-400', text: 'text-amber-300' },
  error: { label: 'Error', dot: 'bg-red-400', text: 'text-red-400' },
};

export function describeEntry(e: ConnectorLogEntry): string {
  if (e.message) return e.message;
  return e.status === 'ok' ? `Running normally: ${e.fetched.toLocaleString()} fetched, ${e.sent.toLocaleString()} sent in that run.` : 'No details were reported.';
}

interface ConnectorLogDrawerProps {
  connector: Connector;
  onClose: () => void;
}

export function ConnectorLogDrawer({ connector, onClose }: ConnectorLogDrawerProps) {
  const { data, error, isLoading } = useSWR(['connector-log', connector.id], () => connectorsApi.log(connector.id), {
    refreshInterval: 30_000,
  });

  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      if (e.key === 'Escape') onClose();
    };
    window.addEventListener('keydown', onKey);
    return () => window.removeEventListener('keydown', onKey);
  }, [onClose]);

  return (
    <div className="fixed inset-0 z-50 flex" role="dialog" aria-modal="true" aria-label={`${connector.name} log`}>
      <button type="button" onClick={onClose} aria-label="Close log" className="flex-1 bg-black/60 backdrop-blur-sm" />
      <aside className="w-full max-w-xl bg-gray-950 border-l border-gray-800 shadow-2xl flex flex-col">
        <header className="flex items-start justify-between gap-3 border-b border-gray-800 px-6 py-4">
          <div className="min-w-0">
            <h2 className="text-base font-semibold text-white truncate">{connector.name}</h2>
            <p className="text-xs text-gray-500 mt-0.5">Log: a line is added when the status or message changes, newest first.</p>
          </div>
          <button type="button" onClick={onClose} className="text-xs text-gray-400 hover:text-gray-200 px-2 py-1 rounded-lg border border-gray-800">
            Close
          </button>
        </header>

        <div className="flex-1 overflow-y-auto px-6 py-4">
          {isLoading && <p className="text-sm text-gray-500">Loading the log…</p>}
          {error && !data && (
            <p role="alert" className="text-sm text-red-300">
              Couldn&apos;t load the log. Try again in a moment.
            </p>
          )}
          {data && data.length === 0 && (
            <p className="text-sm text-gray-500">Nothing logged yet. The first line appears after CORE&apos;s next report for this connector.</p>
          )}
          {data && data.length > 0 && (
            <ol className="space-y-3">
              {data.map((e, i) => {
                const style = ENTRY_STYLE[e.status] ?? ENTRY_STYLE.warning;
                return (
                  <li key={`${e.at}-${i}`} className="rounded-lg border border-gray-800 bg-gray-900/60 p-3">
                    <div className="flex items-center justify-between gap-2 text-xs">
                      <span className={clsx('flex items-center gap-1.5 font-medium', style.text)}>
                        <span className={clsx('w-1.5 h-1.5 rounded-full', style.dot)} />
                        {style.label}
                      </span>
                      <time dateTime={e.at} className="text-gray-500">
                        {new Date(e.at).toLocaleString()}
                      </time>
                    </div>
                    <p className="mt-1.5 text-sm text-gray-300 break-words">{describeEntry(e)}</p>
                  </li>
                );
              })}
            </ol>
          )}
        </div>
      </aside>
    </div>
  );
}
