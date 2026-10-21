'use client';

import { useEffect, useRef, useState } from 'react';
import toast from 'react-hot-toast';
import useSWR from 'swr';
import { alertsApi } from '@/lib/api';

/** How long after the request the alert is read again: CORE collects a request within about 15 seconds, then reads the tool and reports back. */
export const REFRESH_CHECKS_MS = [20_000, 40_000, 60_000] as const;

/**
 * Asks CORE to re-read this alert's own tool, not every tool, so the alert's status catches up with the tool's. The alert is then re-read a few times while the answer arrives.
 */
/** "just now", "4 min ago", "3 h ago", "2 days ago" for a time in the past; empty for one that cannot be read. */
export function agoLabel(iso: string | null | undefined, now: number = Date.now()): string {
  const t = iso ? new Date(iso).getTime() : NaN;
  if (Number.isNaN(t)) return '';
  const min = Math.max(0, Math.floor((now - t) / 60_000));
  if (min < 1) return 'just now';
  if (min < 60) return `${min} min ago`;
  if (min < 48 * 60) return `${Math.floor(min / 60)} h ago`;
  return `${Math.floor(min / 1440)} days ago`;
}

export function RefreshStatusButton({ alertId, onRefreshed }: { alertId: string; onRefreshed: () => void }) {
  const [waiting, setWaiting] = useState(false);
  // When CORE last told AiSOC this incident's state (shared with the remediation panel, so one request serves both).
  const { data: actions, mutate: recheck } = useSWR(['alerts', alertId, 'vendor-actions'] as const, () => alertsApi.vendorActions(alertId), { shouldRetryOnError: false });
  const checked = agoLabel(actions?.vendor_state?.at);
  const timers = useRef<ReturnType<typeof setTimeout>[]>([]);
  useEffect(() => () => timers.current.forEach(clearTimeout), []);

  async function ask() {
    setWaiting(true);
    try {
      const out = await alertsApi.refresh(alertId);
      toast.success(`Asked CORE to re-check ${out.vendor}. This alert updates within about a minute.`);
      timers.current = REFRESH_CHECKS_MS.map((ms, i) =>
        setTimeout(() => {
          onRefreshed();
          void recheck();
          if (i === REFRESH_CHECKS_MS.length - 1) setWaiting(false);
        }, ms),
      );
    } catch (e) {
      setWaiting(false);
      toast.error(e instanceof Error ? e.message : 'Could not ask CORE to re-check this alert.');
    }
  }

  return (
    <span className="inline-flex flex-col items-end gap-0.5">
    <button
      type="button"
      onClick={() => void ask()}
      disabled={waiting}
      title="Ask CORE to re-read this alert's tool now, so its status here is current. Other tools are not re-read."
      className="inline-flex items-center gap-1.5 rounded-lg border border-gray-700 bg-gray-800 px-3 py-1.5 text-sm text-gray-200 transition-colors hover:border-gray-600 disabled:opacity-60"
    >
      {waiting ? 'Checking…' : 'Refresh status'}
    </button>
    {checked && (
      <span className="text-[11px] text-gray-500" data-testid="status-checked">
        status checked {checked}
      </span>
    )}
    </span>
  );
}
