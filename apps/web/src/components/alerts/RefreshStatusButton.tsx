'use client';

import { useEffect, useRef, useState } from 'react';
import toast from 'react-hot-toast';
import { alertsApi } from '@/lib/api';

/** How long after the request the alert is read again: CORE collects a request within about 15 seconds, then reads the tool and reports back. */
export const REFRESH_CHECKS_MS = [20_000, 40_000, 60_000] as const;

/**
 * Asks CORE to re-read this alert's own tool, not every tool, so the alert's status catches up with the tool's. The alert is then re-read a few times while the answer arrives.
 */
export function RefreshStatusButton({ alertId, onRefreshed }: { alertId: string; onRefreshed: () => void }) {
  const [waiting, setWaiting] = useState(false);
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
          if (i === REFRESH_CHECKS_MS.length - 1) setWaiting(false);
        }, ms),
      );
    } catch (e) {
      setWaiting(false);
      toast.error(e instanceof Error ? e.message : 'Could not ask CORE to re-check this alert.');
    }
  }

  return (
    <button
      type="button"
      onClick={() => void ask()}
      disabled={waiting}
      title="Ask CORE to re-read this alert's tool now, so its status here is current. Other tools are not re-read."
      className="inline-flex items-center gap-1.5 rounded-lg border border-gray-700 bg-gray-800 px-3 py-1.5 text-sm text-gray-200 transition-colors hover:border-gray-600 disabled:opacity-60"
    >
      {waiting ? 'Checking…' : 'Refresh status'}
    </button>
  );
}
