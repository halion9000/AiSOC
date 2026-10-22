'use client';

/**
 * Remediation plan and actions for a Huntress alert, in the investigation rail.
 *
 * Shows what Huntress says about the incident (status, the remediation plan, the PSA ticket Huntress opened) and offers the three things Huntress allows: approve the plan,
 * reject it (sending the incident back to the Huntress SOC, with a reason), and resolve the incident once every remediation is approved. A.C.O.R.N holds no Huntress key:
 * a click is queued, CORE carries it out within about a minute, and the result shows here. Every action asks for confirmation first, because it changes a live security tool
 * (approving runs "assisted" remediations on the endpoint straight away).
 *
 * Renders nothing for an alert this does not apply to.
 */

import { useState } from 'react';
import useSWR from 'swr';
import { clsx } from 'clsx';
import { safeDistance } from '@/lib/safe-date';
import { alertsApi, ApiError, type VendorActionItem, type VendorRemediation, type VendorState } from '@/lib/api';

export const REJECT_REASONS: { value: string; label: string }[] = [
  { value: 'unspecified', label: 'No specific reason' },
  { value: 'approved_application', label: 'Approved application' },
  { value: 'manually_remediated', label: 'Already remediated by hand' },
  { value: 'host_reimaged', label: 'Host was re-imaged' },
  { value: 'testing_security_controls', label: 'Testing security controls' },
  { value: 'approved_user_login_location_m365', label: 'Approved sign-in location (M365)' },
  { value: 'approved_user_email_forwarding_rule_m365', label: 'Approved forwarding rule (M365)' },
  { value: 'approved_application_m365', label: 'Approved application (M365)' },
  { value: 'manually_remediated_m365', label: 'Already remediated by hand (M365)' },
  { value: 'testing_security_controls_m365', label: 'Testing security controls (M365)' },
  { value: 'approved_vpn_or_proxy_usage_m365', label: 'Approved VPN or proxy (M365)' },
  { value: 'other', label: 'Other' },
  { value: 'other_m365', label: 'Other (M365)' },
];

export type VendorActionName = 'approve' | 'reject' | 'resolve';

/** Which of the three actions make sense right now. Mirrors Huntress's rules (and A.C.O.R.N's server-side check), so a button is not offered that would be refused. */
export function availableActions(state: VendorState | null, busy: boolean): Record<VendorActionName, { enabled: boolean; why: string }> {
  const none = (why: string) => ({ enabled: false, why });
  if (busy) {
    const w = 'An action for this incident is already waiting for CORE.';
    return { approve: none(w), reject: none(w), resolve: none(w) };
  }
  if (!state) {
    const w = "CORE hasn't reported this incident's state yet; it does on every sync.";
    return { approve: none(w), reject: none(w), resolve: none(w) };
  }
  if (state.status.toLowerCase() !== 'sent') {
    const w = `The incident is ${state.status} in Huntress; only an open incident can be acted on.`;
    return { approve: none(w), reject: none(w), resolve: none(w) };
  }
  const unapproved = state.remediations.filter((r) => (r.status ?? '').toLowerCase() === 'unapproved').length;
  const planWhy = unapproved === 0 ? 'No unapproved remediations left.' : '';
  return {
    approve: { enabled: unapproved > 0, why: planWhy },
    reject: { enabled: unapproved > 0, why: planWhy },
    resolve: { enabled: unapproved === 0, why: unapproved > 0 ? `${unapproved} remediation(s) still need approval first.` : '' },
  };
}

const STATUS_STYLE: Record<string, string> = {
  pending: 'text-amber-300 bg-amber-500/10 border-amber-500/30',
  claimed: 'text-blue-300 bg-blue-500/10 border-blue-500/30',
  done: 'text-emerald-300 bg-emerald-500/10 border-emerald-500/30',
  failed: 'text-red-300 bg-red-500/10 border-red-500/30',
  expired: 'text-gray-400 bg-gray-500/10 border-gray-500/30',
};

const STATUS_LABEL: Record<string, string> = {
  pending: 'Waiting for CORE',
  claimed: 'CORE is doing it',
  done: 'Done',
  failed: 'Failed',
  expired: 'Expired',
};

const ACTION_LABEL: Record<VendorActionName, string> = { approve: 'Approve plan', reject: 'Reject plan', resolve: 'Resolve incident' };

const CONFIRM_TEXT: Record<VendorActionName, string> = {
  approve: 'Approve every unapproved remediation at Huntress? Assisted remediations run on the endpoint straight away.',
  reject: 'Reject the plan and send the incident back to the Huntress SOC?',
  resolve: 'Resolve this incident at Huntress?',
};

function inFlight(actions: VendorActionItem[]): boolean {
  return actions.some((a) => a.status === 'pending' || a.status === 'claimed');
}

export function VendorActionsSection({ alertId }: { alertId: string }) {
  const { data, mutate } = useSWR(['alerts', alertId, 'vendor-actions'] as const, () => alertsApi.vendorActions(alertId), {
    revalidateOnFocus: false,
    shouldRetryOnError: false,
    // Poll while CORE still has something to do, so the outcome appears without a refresh.
    refreshInterval: (d) => (d && inFlight(d.actions) ? 4000 : 0),
  });
  const [asking, setAsking] = useState<VendorActionName | null>(null);
  const [comment, setComment] = useState('');
  const [reason, setReason] = useState('unspecified');
  const [useful, setUseful] = useState(true);
  const [sending, setSending] = useState(false);
  const [problem, setProblem] = useState('');

  if (!data || !data.supported) return null;
  if (data.vendor === 'blumira' || data.vendor === 'fieldeffect') {
    return <ResolveOnlyPanel alertId={alertId} vendor={data.vendor} actions={data.actions} onChanged={() => void mutate()} />;
  }

  const busy = inFlight(data.actions);
  const avail = availableActions(data.vendor_state, busy);
  const state = data.vendor_state;

  const send = async (action: VendorActionName) => {
    setSending(true);
    setProblem('');
    try {
      await alertsApi.requestVendorAction(alertId, {
        action,
        ...(action === 'reject' ? { comment: comment.trim(), reason, useful } : {}),
      });
      setAsking(null);
      setComment('');
      await mutate();
    } catch (e) {
      let msg = e instanceof Error ? e.message : 'Request failed.';
      if (e instanceof ApiError) {
        try {
          const detail = (JSON.parse(e.body) as { detail?: unknown }).detail;
          if (typeof detail === 'string') msg = detail;
        } catch {
          // keep the generic message
        }
        if (e.status === 403) msg = 'Your role can’t change connectors, which this needs.';
      }
      setProblem(msg);
    } finally {
      setSending(false);
    }
  };

  const rejectReady = comment.trim().length > 0;

  return (
    <section className="px-4 py-4 border-b border-gray-800/40" aria-label="Huntress remediation">
      <div className="flex items-baseline justify-between mb-2">
        <h3 className="text-[11px] uppercase tracking-wider text-gray-500 font-semibold">Huntress remediation</h3>
        {state && <span className="text-[11px] text-gray-500">Incident {state.status}</span>}
      </div>

      {!state ? (
        <p className="text-xs text-gray-500">Waiting for CORE to report this incident&apos;s remediation plan (it does on every sync).</p>
      ) : (
        <>
          {state.remediations.length === 0 ? (
            <p className="text-xs text-gray-500">Huntress has no remediation steps on this incident.</p>
          ) : (
            <ul className="space-y-1.5">
              {state.remediations.map((r) => (
                <RemediationRow key={r.id} r={r} />
              ))}
            </ul>
          )}
          {state.psa_ticket_eids.length > 0 && (
            <p className="mt-2 text-[11px] text-gray-500">
              Ticket Huntress opened in your PSA: <span className="font-mono text-gray-300">{state.psa_ticket_eids.join(', ')}</span>
            </p>
          )}
        </>
      )}

      <div className="mt-3 flex flex-wrap gap-2">
        {(['approve', 'reject', 'resolve'] as const).map((a) => (
          <button
            key={a}
            type="button"
            disabled={!avail[a].enabled || sending}
            title={avail[a].why || undefined}
            onClick={() => {
              setProblem('');
              setAsking(a);
            }}
            className={clsx(
              'text-xs px-2.5 py-1.5 rounded-lg border transition-colors disabled:opacity-40 disabled:cursor-not-allowed',
              asking === a ? 'border-blue-500 bg-blue-600/20 text-blue-200' : 'border-gray-700 text-gray-300 hover:bg-gray-800/60'
            )}
          >
            {ACTION_LABEL[a]}
          </button>
        ))}
      </div>

      {asking && (
        <div className="mt-3 rounded-lg border border-gray-700 bg-gray-900/60 p-3 text-xs text-gray-300" role="group" aria-label={`Confirm ${ACTION_LABEL[asking]}`}>
          <p>{CONFIRM_TEXT[asking]}</p>
          {asking === 'reject' && (
            <div className="mt-2 space-y-2">
              <label className="block">
                <span className="text-gray-500">Reason</span>
                <select value={reason} onChange={(e) => setReason(e.target.value)} className="mt-1 w-full rounded bg-gray-950 border border-gray-700 px-2 py-1 text-gray-200">
                  {REJECT_REASONS.map((r) => (
                    <option key={r.value} value={r.value}>
                      {r.label}
                    </option>
                  ))}
                </select>
              </label>
              <label className="block">
                <span className="text-gray-500">Comment for the Huntress SOC (required)</span>
                <textarea
                  value={comment}
                  maxLength={2048}
                  onChange={(e) => setComment(e.target.value)}
                  rows={3}
                  className="mt-1 w-full rounded bg-gray-950 border border-gray-700 px-2 py-1 text-gray-200"
                />
              </label>
              <label className="flex items-center gap-2">
                <input type="checkbox" checked={useful} onChange={(e) => setUseful(e.target.checked)} />
                <span>The plan was useful</span>
              </label>
            </div>
          )}
          <p className="mt-2 text-gray-500">A.C.O.R.N doesn&apos;t talk to Huntress itself. CORE carries this out within about a minute.</p>
          <div className="mt-2 flex gap-2">
            <button
              type="button"
              disabled={sending || (asking === 'reject' && !rejectReady)}
              onClick={() => void send(asking)}
              className="px-2.5 py-1.5 rounded-lg bg-blue-600 text-white disabled:opacity-40 disabled:cursor-not-allowed"
            >
              {sending ? 'Sending…' : `Confirm: ${ACTION_LABEL[asking]}`}
            </button>
            <button type="button" disabled={sending} onClick={() => setAsking(null)} className="px-2.5 py-1.5 rounded-lg border border-gray-700 text-gray-300">
              Cancel
            </button>
          </div>
        </div>
      )}
      {problem && (
        <p role="alert" className="mt-2 text-xs text-red-300">
          {problem}
        </p>
      )}

      {data.actions.length > 0 && (
        <ul className="mt-3 space-y-1.5" aria-label="Requested actions">
          {data.actions.slice(0, 5).map((a) => (
            <li key={a.id} className="text-xs text-gray-400">
              <span className={clsx('inline-block mr-2 px-1.5 py-0.5 rounded border text-[10px] uppercase tracking-wider', STATUS_STYLE[a.status] ?? STATUS_STYLE.pending)}>
                {STATUS_LABEL[a.status] ?? a.status}
              </span>
              {ACTION_LABEL[a.action] ?? a.action}
              <span className="text-gray-600"> · {safeDistance(a.created_at, { addSuffix: true })}</span>
              {a.result_message && <p className="mt-0.5 ml-1 text-gray-500">{a.result_message}</p>}
            </li>
          ))}
        </ul>
      )}
    </section>
  );
}

function RemediationRow({ r }: { r: VendorRemediation }) {
  const done = ['approved', 'completed'].includes((r.status ?? '').toLowerCase());
  return (
    <li className="rounded border border-gray-800/60 bg-gray-900/40 px-2.5 py-1.5 text-xs">
      <div className="flex items-center justify-between gap-2">
        <span className="text-gray-200">{r.action ?? `Remediation ${r.id}`}</span>
        <span className={clsx('text-[10px] uppercase tracking-wider', done ? 'text-emerald-300' : 'text-amber-300')}>{r.status ?? 'unknown'}</span>
      </div>
      {r.type && <p className="text-[11px] text-gray-500">{r.type === 'manual' ? 'Manual: someone must do this by hand' : r.type}</p>}
      {r.parameters.map((p) => (
        <p key={p.name} className="text-[11px] text-gray-500 break-all">
          {p.name}: <span className="font-mono text-gray-400">{p.description}</span>
        </p>
      ))}
    </li>
  );
}

export const BLUMIRA_RESOLUTIONS: { value: number; label: string }[] = [
  { value: 10, label: 'Valid (a real threat, and it was handled)' },
  { value: 20, label: 'False positive' },
  { value: 30, label: 'No action needed' },
  { value: 40, label: 'Risk accepted' },
];

const VENDOR_NAME: Record<'blumira' | 'fieldeffect', string> = { blumira: 'Blumira', fieldeffect: 'Field Effect' };

/**
 * Blumira findings and Field Effect AROs can only be resolved from here (no remediation plan to approve first). Same path as the Huntress actions: queued in A.C.O.R.N,
 * carried out by CORE, result shown below. Blumira needs the reason it is closed (its own list of four); Field Effect just takes an optional comment.
 */
export function ResolveOnlyPanel({
  alertId,
  vendor,
  actions,
  onChanged,
}: {
  alertId: string;
  vendor: 'blumira' | 'fieldeffect';
  actions: VendorActionItem[];
  onChanged: () => void;
}) {
  const name = VENDOR_NAME[vendor];
  const [asking, setAsking] = useState(false);
  const [resolution, setResolution] = useState<number | ''>('');
  const [comment, setComment] = useState('');
  const [sending, setSending] = useState(false);
  const [problem, setProblem] = useState('');
  const busy = inFlight(actions);
  const done = actions.some((a) => a.action === 'resolve' && a.status === 'done');
  const ready = vendor === 'fieldeffect' || resolution !== '';

  const send = async () => {
    setSending(true);
    setProblem('');
    try {
      await alertsApi.requestVendorAction(alertId, {
        action: 'resolve',
        ...(comment.trim() ? { comment: comment.trim() } : {}),
        ...(vendor === 'blumira' && resolution !== '' ? { resolution } : {}),
      });
      setAsking(false);
      setComment('');
      onChanged();
    } catch (e) {
      let msg = e instanceof Error ? e.message : 'Request failed.';
      if (e instanceof ApiError) {
        try {
          const detail = (JSON.parse(e.body) as { detail?: unknown }).detail;
          if (typeof detail === 'string') msg = detail;
        } catch {
          // keep the generic message
        }
        if (e.status === 403) msg = 'Your role can’t change connectors, which this needs.';
      }
      setProblem(msg);
    } finally {
      setSending(false);
    }
  };

  return (
    <section className="px-4 py-4 border-b border-gray-800/40" aria-label={`${name} resolve`}>
      <h3 className="mb-2 text-[11px] uppercase tracking-wider text-gray-500 font-semibold">{name}</h3>
      <button
        type="button"
        disabled={busy || sending || done}
        title={busy ? 'An action for this alert is already waiting for CORE.' : done ? 'Already resolved.' : undefined}
        onClick={() => {
          setProblem('');
          setAsking(true);
        }}
        className="text-xs px-2.5 py-1.5 rounded-lg border border-gray-700 text-gray-300 hover:bg-gray-800/60 disabled:opacity-40 disabled:cursor-not-allowed"
      >
        Resolve in {name}
      </button>

      {asking && (
        <div className="mt-3 rounded-lg border border-gray-700 bg-gray-900/60 p-3 text-xs text-gray-300" role="group" aria-label={`Confirm resolve in ${name}`}>
          <p>Close this alert in {name}? It changes a live security tool.</p>
          <div className="mt-2 space-y-2">
            {vendor === 'blumira' && (
              <label className="block">
                <span className="text-gray-500">Why it is closed (required)</span>
                <select
                  value={resolution}
                  onChange={(e) => setResolution(e.target.value === '' ? '' : Number(e.target.value))}
                  className="mt-1 w-full rounded bg-gray-950 border border-gray-700 px-2 py-1 text-gray-200"
                >
                  <option value="">Choose…</option>
                  {BLUMIRA_RESOLUTIONS.map((r) => (
                    <option key={r.value} value={r.value}>
                      {r.label}
                    </option>
                  ))}
                </select>
              </label>
            )}
            <label className="block">
              <span className="text-gray-500">Note (optional)</span>
              <textarea
                value={comment}
                maxLength={2048}
                onChange={(e) => setComment(e.target.value)}
                rows={2}
                className="mt-1 w-full rounded bg-gray-950 border border-gray-700 px-2 py-1 text-gray-200"
              />
            </label>
          </div>
          <p className="mt-2 text-gray-500">A.C.O.R.N doesn&apos;t talk to {name} itself. CORE carries this out within about a minute.</p>
          <div className="mt-2 flex gap-2">
            <button
              type="button"
              disabled={sending || !ready}
              onClick={() => void send()}
              className="px-2.5 py-1.5 rounded-lg bg-blue-600 text-white disabled:opacity-40 disabled:cursor-not-allowed"
            >
              {sending ? 'Sending…' : `Confirm: resolve in ${name}`}
            </button>
            <button type="button" disabled={sending} onClick={() => setAsking(false)} className="px-2.5 py-1.5 rounded-lg border border-gray-700 text-gray-300">
              Cancel
            </button>
          </div>
        </div>
      )}
      {problem && (
        <p role="alert" className="mt-2 text-xs text-red-300">
          {problem}
        </p>
      )}

      {actions.length > 0 && (
        <ul className="mt-3 space-y-1.5" aria-label="Requested actions">
          {actions.slice(0, 5).map((a) => (
            <li key={a.id} className="text-xs text-gray-400">
              <span className={clsx('inline-block mr-2 px-1.5 py-0.5 rounded border text-[10px] uppercase tracking-wider', STATUS_STYLE[a.status] ?? STATUS_STYLE.pending)}>
                {STATUS_LABEL[a.status] ?? a.status}
              </span>
              Resolve in {name}
              <span className="text-gray-600"> · {safeDistance(a.created_at, { addSuffix: true })}</span>
              {a.result_message && <p className="mt-0.5 ml-1 text-gray-500">{a.result_message}</p>}
            </li>
          ))}
        </ul>
      )}
    </section>
  );
}
