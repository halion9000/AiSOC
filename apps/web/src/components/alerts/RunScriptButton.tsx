'use client';

import { useState } from 'react';
import toast from 'react-hot-toast';
import { useSWRConfig } from 'swr';
import { alertsApi, casesApi, type AlertScriptOptions } from '@/lib/api';
import { SCRIPT_RUNS_KEY } from './ScriptRunsSection';

export interface ScriptChoice {
  scriptId: number | null;
  /** ``linked``: one of the tickets the alert already has; ``number``: another existing ticket; ``create``: open a new one. */
  ticketMode: 'linked' | 'number' | 'create';
  linked: string;
  number: string;
}

export interface RunPlan {
  scriptId: number;
  ticket: { mode: 'link' | 'create'; number?: string };
  /** A ticket number to link to the alert first (one it does not have yet). */
  linkTicket?: string;
  /** The alert has no case yet: open one before running, so the result has somewhere to go. */
  needCase: boolean;
}

const plainNumber = (n: string) => n.replace(/^0+(?=\d)/, '');

/** What pressing Run does, or why it cannot yet. Pure, so the choices can be tested without a page. */
export function planRun(options: AlertScriptOptions, c: ScriptChoice): { ok: true; plan: RunPlan } | { ok: false; error: string } {
  if (c.scriptId === null || !options.scripts.some((s) => s.id === c.scriptId)) return { ok: false, error: 'Choose a script.' };
  const needCase = options.case_id === null;
  if (c.ticketMode === 'create') return { ok: true, plan: { scriptId: c.scriptId, ticket: { mode: 'create' }, needCase } };
  const number = (c.ticketMode === 'linked' ? c.linked : c.number).trim().replace(/^#/, '').trim();
  if (!/^[0-9]{1,12}$/.test(number)) return { ok: false, error: 'Enter the HaloPSA ticket number (digits only), or choose to open a new ticket.' };
  const plain = plainNumber(number);
  const known = options.tickets.some((t) => plainNumber(t) === plain);
  return { ok: true, plan: { scriptId: c.scriptId, ticket: { mode: 'link', number: plain }, ...(known ? {} : { linkTicket: plain }), needCase } };
}

const CASE_SEVERITY: Record<string, 'critical' | 'high' | 'medium' | 'low'> = { critical: 'critical', high: 'high', medium: 'medium', low: 'low', info: 'low' };

/** The button on an alert: pick one of CORE's scripts, say which Halo ticket gets the result (existing, by number, or a new one), and the result lands on the ticket and the alert's case (opened if there is none). */
export function RunScriptButton({ alertId, title, severity, onDone }: { alertId: string; title: string; severity?: string; onDone?: () => void }) {
  const { mutate: refreshRuns } = useSWRConfig();
  const [open, setOpen] = useState(false);
  const [options, setOptions] = useState<AlertScriptOptions | null>(null);
  const [loadError, setLoadError] = useState('');
  const [busy, setBusy] = useState(false);
  const [choice, setChoice] = useState<ScriptChoice>({ scriptId: null, ticketMode: 'number', linked: '', number: '' });

  async function show() {
    setOpen(true);
    setOptions(null);
    setLoadError('');
    try {
      const o = await alertsApi.scriptOptions(alertId);
      setOptions(o);
      setChoice({ scriptId: o.suggested_script_id ?? o.scripts[0]?.id ?? null, ticketMode: o.tickets.length > 0 ? 'linked' : 'number', linked: o.tickets[0] ?? '', number: '' });
    } catch (e) {
      setLoadError(e instanceof Error ? e.message : 'Could not load the scripts.');
    }
  }

  async function run() {
    if (!options) return;
    const planned = planRun(options, choice);
    if (!planned.ok) return void toast.error(planned.error);
    const { plan } = planned;
    setBusy(true);
    try {
      let caseId = options.case_id ?? undefined;
      if (plan.needCase) {
        const made = await casesApi.create({ title: title.slice(0, 200) || 'Alert', severity: CASE_SEVERITY[severity ?? ''] ?? 'medium', alertIds: [alertId] });
        caseId = made.id;
      }
      if (plan.linkTicket) await alertsApi.addTicket(alertId, { id: plan.linkTicket });
      const out = await alertsApi.runScript(alertId, { script_id: plan.scriptId, ticket: plan.ticket, ...(caseId ? { case_id: caseId } : {}) });
      toast.success(
        out.runs_at_once
          ? 'Asked CORE to run the script. It starts within about 15 seconds; the result goes on the ticket and the case.'
          : 'Asked CORE. It will ask you to approve the script in CORE first, then the result goes on the ticket and the case.',
      );
      setOpen(false);
      void refreshRuns([...SCRIPT_RUNS_KEY(alertId)]);
      onDone?.();
    } catch (e) {
      toast.error(e instanceof Error ? e.message : 'Could not ask CORE to run the script.');
    } finally {
      setBusy(false);
    }
  }

  const chosen = options?.scripts.find((s) => s.id === choice.scriptId);
  return (
    <>
      <button
        type="button"
        onClick={() => void show()}
        title="Run one of the NinjaOne scripts CORE offers on this alert's machine, and put the result on the ticket and case"
        className="inline-flex items-center gap-1.5 rounded-lg border border-gray-700 bg-gray-800 px-3 py-1.5 text-sm text-gray-200 transition-colors hover:border-gray-600"
      >
        Run script
      </button>
      {open && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 p-4" role="dialog" aria-modal="true" aria-label="Run a script" data-testid="run-script-dialog">
          <div className="w-full max-w-lg space-y-4 rounded-xl border border-gray-700 bg-gray-900 p-5 text-sm text-gray-200">
            <h2 className="text-base font-semibold text-white">Run a script on this machine</h2>
            {loadError && (
              <p role="alert" className="text-red-300">
                {loadError}
              </p>
            )}
            {!options && !loadError && <p className="text-gray-400">Loading…</p>}
            {options?.blocked && (
              <p className="text-amber-300" data-testid="run-script-blocked">
                {options.blocked}
              </p>
            )}
            {options && !options.blocked && (
              <>
                <p className="text-gray-400">
                  Machine: <span className="font-mono text-gray-200">{options.device}</span>
                </p>
                <label className="block">
                  <span className="mb-1 block text-xs uppercase tracking-wide text-gray-400">Script</span>
                  <select
                    aria-label="Script"
                    value={choice.scriptId ?? ''}
                    onChange={(e) => setChoice({ ...choice, scriptId: Number(e.target.value) })}
                    className="w-full rounded-lg border border-gray-700 bg-gray-800 px-3 py-2"
                  >
                    {options.scripts.map((s) => (
                      <option key={s.id} value={s.id}>
                        {s.name}
                      </option>
                    ))}
                  </select>
                  {chosen && <span className="mt-1 block text-xs text-gray-500">{chosen.one_click ? 'CORE runs this at once.' : 'CORE will ask you to approve it first.'}</span>}
                </label>
                <fieldset className="space-y-2">
                  <legend className="mb-1 text-xs uppercase tracking-wide text-gray-400">HaloPSA ticket for the result</legend>
                  {options.tickets.length > 0 && (
                    <label className="flex items-center gap-2">
                      <input type="radio" name="ticket" checked={choice.ticketMode === 'linked'} onChange={() => setChoice({ ...choice, ticketMode: 'linked' })} />
                      <span>Linked ticket</span>
                      <select
                        aria-label="Linked ticket"
                        value={choice.linked}
                        onChange={(e) => setChoice({ ...choice, ticketMode: 'linked', linked: e.target.value })}
                        className="rounded border border-gray-700 bg-gray-800 px-2 py-1"
                      >
                        {options.tickets.map((t) => (
                          <option key={t} value={t}>
                            #{t}
                          </option>
                        ))}
                      </select>
                    </label>
                  )}
                  <label className="flex items-center gap-2">
                    <input type="radio" name="ticket" checked={choice.ticketMode === 'number'} onChange={() => setChoice({ ...choice, ticketMode: 'number' })} />
                    <span>{options.tickets.length > 0 ? 'Another ticket number' : 'Link a ticket number'}</span>
                    <input
                      aria-label="Ticket number"
                      value={choice.number}
                      onChange={(e) => setChoice({ ...choice, ticketMode: 'number', number: e.target.value })}
                      placeholder="e.g. 553688"
                      className="w-32 rounded border border-gray-700 bg-gray-800 px-2 py-1"
                    />
                  </label>
                  <label className="flex items-center gap-2">
                    <input type="radio" name="ticket" checked={choice.ticketMode === 'create'} onChange={() => setChoice({ ...choice, ticketMode: 'create' })} />
                    <span>Open a new ticket for this alert</span>
                  </label>
                </fieldset>
                <p className="text-xs text-gray-500" data-testid="run-script-case">
                  {options.case_id ? `The output is also added to case ${options.case_number ?? 'of this alert'}.` : 'This alert has no case yet: one is opened so the output has somewhere to go.'}
                </p>
              </>
            )}
            <div className="flex justify-end gap-2">
              <button type="button" onClick={() => setOpen(false)} className="rounded-lg border border-gray-700 px-3 py-1.5 hover:bg-gray-800">
                Cancel
              </button>
              {options && !options.blocked && (
                <button type="button" disabled={busy} onClick={() => void run()} className="rounded-lg bg-blue-600 px-4 py-1.5 font-medium text-white hover:bg-blue-500 disabled:opacity-60">
                  {busy ? 'Asking CORE…' : 'Run'}
                </button>
              )}
            </div>
          </div>
        </div>
      )}
    </>
  );
}
