'use client';

import { useState } from 'react';
import toast from 'react-hot-toast';
import { alertsApi, type AlertScriptOptions, type BulkScriptRun } from '@/lib/api';

/** "Disk Space Scan" on 3 machines, a new HaloPSA ticket for each, CORE asks once; and how many were left out. */
export function bulkRunSummary(r: BulkScriptRun): string {
  const machines = `${r.queued} machine${r.queued === 1 ? '' : 's'}`;
  const left = r.skipped > 0 ? ` ${r.skipped} left out.` : '';
  const how = r.runs_at_once ? 'It is set to run at once in CORE.' : 'CORE asks you once, for all of them.';
  return `"${r.script_name}" on ${machines}, a new HaloPSA ticket for each. ${how}${left}`;
}

/** Shown above the alert list while rows are ticked: pick one of CORE's scripts, see which machines it would run on, confirm once. */
export default function BulkScriptBar({ alertIds, onDone }: { alertIds: string[]; onDone: () => void }) {
  const [open, setOpen] = useState(false);
  const [options, setOptions] = useState<AlertScriptOptions | null>(null);
  const [scriptId, setScriptId] = useState<number | null>(null);
  const [plan, setPlan] = useState<BulkScriptRun | null>(null);
  const [error, setError] = useState('');
  const [busy, setBusy] = useState(false);
  if (alertIds.length === 0) return null;

  const reset = () => {
    setOpen(false);
    setPlan(null);
    setError('');
  };

  const show = async () => {
    setOpen(true);
    setPlan(null);
    setError('');
    try {
      const o = await alertsApi.scriptOptions(alertIds[0]);
      setOptions(o);
      setScriptId(o.suggested_script_id ?? o.scripts[0]?.id ?? null);
      if (o.scripts.length === 0) setError(o.blocked ?? 'CORE has not shared any scripts.');
    } catch (e) {
      setError(e instanceof Error ? e.message : 'Could not load the scripts.');
    }
  };

  const ask = async (preview: boolean) => {
    if (scriptId === null) return;
    setBusy(true);
    setError('');
    try {
      const r = await alertsApi.runScriptBulk({ script_id: scriptId, alert_ids: alertIds, preview });
      if (preview) setPlan(r);
      else {
        toast.success(`Asked CORE to run "${r.script_name}" on ${r.queued} machine${r.queued === 1 ? '' : 's'}.${r.skipped ? ` ${r.skipped} left out.` : ''}`);
        reset();
        onDone();
      }
    } catch (e) {
      setError(e instanceof Error ? e.message : 'Could not ask CORE.');
    } finally {
      setBusy(false);
    }
  };

  return (
    <div data-testid="bulk-script-bar" className="border-b border-gray-800/60 bg-amber-500/5 px-4 py-2 text-xs text-gray-300">
      <div className="flex items-center gap-2">
        <span>{alertIds.length} selected</span>
        {!open ? (
          <button type="button" onClick={() => void show()} className="rounded border border-amber-500/40 bg-amber-500/10 px-2 py-1 text-amber-300 hover:bg-amber-500/20">
            Run script on these machines
          </button>
        ) : (
          <>
            <select
              aria-label="Script"
              value={scriptId ?? ''}
              onChange={(e) => {
                setScriptId(Number(e.target.value));
                setPlan(null);
              }}
              className="rounded border border-gray-700 bg-gray-900 px-2 py-1"
            >
              {(options?.scripts ?? []).map((s) => (
                <option key={s.id} value={s.id}>
                  {s.name}
                </option>
              ))}
            </select>
            <button
              type="button"
              disabled={busy || scriptId === null}
              onClick={() => void ask(true)}
              className="rounded border border-amber-500/40 bg-amber-500/10 px-2 py-1 text-amber-300 hover:bg-amber-500/20 disabled:opacity-40"
            >
              {busy && !plan ? 'Checking...' : 'See which machines'}
            </button>
            <button type="button" onClick={reset} className="ml-auto text-gray-500 hover:text-gray-300">
              Cancel
            </button>
          </>
        )}
      </div>
      {error && (
        <p role="alert" className="mt-2 text-red-300">
          {error}
        </p>
      )}
      {plan && (
        <div className="mt-2" data-testid="bulk-script-plan">
          <p className="text-gray-200">{bulkRunSummary(plan)}</p>
          <ul className="mt-1 space-y-0.5 text-gray-400">
            {plan.items.map((i) => (
              <li key={i.alert_id}>
                {i.outcome === 'queued' ? '✓' : '–'} {i.device ?? 'no machine'}
                {i.reason ? ` (${i.reason})` : ''}
              </li>
            ))}
          </ul>
          <button
            type="button"
            disabled={busy || plan.queued === 0}
            onClick={() => void ask(false)}
            className="mt-2 rounded border border-amber-500/50 bg-amber-500/20 px-2 py-1 text-amber-200 hover:bg-amber-500/30 disabled:opacity-40"
          >
            {busy ? 'Asking CORE...' : `Confirm: run on ${plan.queued} machine${plan.queued === 1 ? '' : 's'}`}
          </button>
        </div>
      )}
    </div>
  );
}
