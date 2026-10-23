'use client';

import { useState } from 'react';
import toast from 'react-hot-toast';
import { alertsApi, type Alert } from '@/lib/api';

export type HideScope = 'device' | 'client' | 'all';

/** The number of days typed, as a whole number from 1 to 3650, or null when it is not one. */
export function parseDays(text: string): number | null {
  const t = text.trim();
  if (!/^\d{1,4}$/.test(t)) return null;
  const n = Number(t);
  return n >= 1 && n <= 3650 ? n : null;
}

interface Props {
  open: boolean;
  onClose: () => void;
  alert: Pick<Alert, 'id' | 'title' | 'clientName' | 'affectedHosts' | 'device' | 'source'>;
  onHidden?: () => void;
}

/**
 * "Hide this alert type": hides every alert of the same type (same rule, same tool) for one device, for the whole client, or for every client, for a number of days or without end.
 * Nothing is deleted: the alerts are put aside and come back, as they were, when the rule is lifted or runs out.
 */
export function HideAlertTypeModal({ open, onClose, alert, onHidden }: Props) {
  const hosts = alert.affectedHosts && alert.affectedHosts.length > 0 ? alert.affectedHosts : alert.device ? [alert.device] : [];
  const [scope, setScope] = useState<HideScope>(hosts.length > 0 ? 'device' : 'client');
  const [device, setDevice] = useState(hosts[0] ?? '');
  const [indefinite, setIndefinite] = useState(false);
  const [days, setDays] = useState('30');
  const [busy, setBusy] = useState(false);

  if (!open) return null;

  const parsed = parseDays(days);
  const valid = (indefinite || parsed !== null) && (scope !== 'device' || device !== '');

  const submit = async () => {
    if (!valid) return;
    setBusy(true);
    try {
      const out = await alertsApi.hideType({ alertId: alert.id, scope, days: indefinite ? null : parsed, device: scope === 'device' ? device : undefined });
      toast.success(out.hidden_alerts > 0 ? `Hidden: ${out.hidden_alerts} alert${out.hidden_alerts === 1 ? '' : 's'} of this type` : 'This alert type is hidden');
      onHidden?.();
      onClose();
    } catch (err) {
      toast.error(err instanceof Error ? err.message : 'Could not hide this alert type');
    } finally {
      setBusy(false);
    }
  };

  const choice = (value: HideScope, label: string, detail: string, disabled = false) => (
    <label key={value} className={`flex items-start gap-2 rounded-lg border p-3 ${scope === value ? 'border-blue-500 bg-blue-500/10' : 'border-gray-700'} ${disabled ? 'opacity-50' : 'cursor-pointer'}`}>
      <input type="radio" name="hide-scope" value={value} checked={scope === value} disabled={disabled} onChange={() => setScope(value)} className="mt-1" />
      <span>
        <span className="block text-sm font-medium text-gray-100">{label}</span>
        <span className="block text-xs text-gray-400">{detail}</span>
      </span>
    </label>
  );

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 p-4" role="dialog" aria-modal="true" aria-label="Hide this alert type">
      <div className="w-full max-w-lg space-y-4 rounded-xl border border-gray-800 bg-gray-950 p-5 shadow-2xl">
        <div>
          <h2 className="text-lg font-semibold text-gray-100">Hide this alert type</h2>
          <p className="mt-1 text-sm text-gray-400">
            Hides every alert like <span className="text-gray-200">{alert.title}</span>
            {alert.source ? <> from {alert.source}</> : null}. Nothing is deleted: they come back as they were when this ends.
          </p>
        </div>

        <fieldset className="space-y-2">
          <legend className="mb-1 text-xs font-semibold uppercase text-gray-500">Hide it for</legend>
          {choice('device', 'This device only', hosts.length > 0 ? `Only on ${hosts.length === 1 ? hosts[0] : 'the device you pick'}` : 'This alert names no device', hosts.length === 0)}
          {scope === 'device' && hosts.length > 1 && (
            <select aria-label="Device" value={device} onChange={(e) => setDevice(e.target.value)} className="ml-6 rounded-md border border-gray-700 bg-gray-900 px-2 py-1.5 text-sm text-white">
              {hosts.map((h) => (
                <option key={h} value={h}>
                  {h}
                </option>
              ))}
            </select>
          )}
          {choice('client', 'This client', `Every device of ${alert.clientName ?? 'this client'}`)}
          {choice('all', 'All clients', 'Everywhere this alert type appears')}
        </fieldset>

        <fieldset className="space-y-2">
          <legend className="mb-1 text-xs font-semibold uppercase text-gray-500">For how long</legend>
          <div className="flex items-center gap-2">
            <input
              aria-label="Days"
              inputMode="numeric"
              value={days}
              disabled={indefinite}
              onChange={(e) => setDays(e.target.value)}
              className="w-24 rounded-md border border-gray-700 bg-gray-900 px-2 py-1.5 text-sm text-white disabled:opacity-40"
            />
            <span className="text-sm text-gray-300">days</span>
          </div>
          {!indefinite && parsed === null && <p className="text-xs text-red-300">Enter a whole number of days from 1 to 3650.</p>}
          <label className="flex cursor-pointer items-center gap-2 text-sm text-gray-200">
            <input type="checkbox" checked={indefinite} onChange={(e) => setIndefinite(e.target.checked)} />
            Hide indefinitely
          </label>
        </fieldset>

        <div className="flex justify-end gap-2">
          <button type="button" onClick={onClose} className="rounded-lg px-4 py-2 text-sm text-gray-300 hover:bg-gray-800">
            Cancel
          </button>
          <button
            type="button"
            onClick={() => void submit()}
            disabled={!valid || busy}
            className="rounded-lg bg-amber-600 px-4 py-2 text-sm font-medium text-white hover:bg-amber-500 disabled:opacity-50"
          >
            {busy ? 'Hiding…' : 'Hide alert type'}
          </button>
        </div>
      </div>
    </div>
  );
}
