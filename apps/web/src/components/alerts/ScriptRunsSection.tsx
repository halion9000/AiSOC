'use client';

import useSWR from 'swr';
import { alertsApi, type AlertScriptRun } from '@/lib/api';
import { agoLabel } from './RefreshStatusButton';

export const SCRIPT_RUNS_KEY = (alertId: string) => ['alerts', alertId, 'script-runs'] as const;

const STATUS_LABEL: Record<string, string> = {
  pending: 'Waiting for CORE',
  claimed: 'CORE is working on it',
  done: 'Sent to CORE',
  failed: 'Did not run',
  expired: 'CORE did not pick it up',
};

const open = (r: AlertScriptRun) => r.status === 'pending' || r.status === 'claimed';

/** The scripts asked for from this alert and how each went (what CORE reported back). Shows nothing when none was asked. The output itself is on the ticket and the case. */
export function ScriptRunsSection({ alertId }: { alertId: string }) {
  const { data } = useSWR(SCRIPT_RUNS_KEY(alertId), () => alertsApi.scriptRuns(alertId), {
    shouldRetryOnError: false,
    refreshInterval: (latest) => (latest?.some(open) ? 15_000 : 0),
  });
  if (!data || data.length === 0) return null;
  return (
    <section aria-label="Script runs" className="px-4 py-4 border-b border-gray-800/40" data-testid="script-runs">
      <h3 className="mb-2 text-[11px] font-semibold uppercase tracking-wider text-gray-500">Script runs</h3>
      <ul className="space-y-2 text-xs">
        {data.map((r) => (
          <li key={r.id} className="space-y-0.5">
            <div className="flex flex-wrap items-baseline gap-x-2">
              <span className="font-medium text-gray-200">{r.script_name}</span>
              {r.device && <span className="font-mono text-gray-400">{r.device}</span>}
              <span className="text-gray-500">{agoLabel(r.created_at)}</span>
            </div>
            <div className={r.status === 'failed' || r.status === 'expired' ? 'text-red-300' : 'text-gray-300'}>
              {STATUS_LABEL[r.status] ?? r.status}
              {r.ticket_id ? ` · ticket ${r.ticket_id}` : r.new_ticket ? ' · new ticket' : ''}
            </div>
            {r.result_message && <div className="text-gray-400">{r.result_message}</div>}
          </li>
        ))}
      </ul>
    </section>
  );
}
