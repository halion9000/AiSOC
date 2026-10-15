'use client';

import { useState } from 'react';
import toast from 'react-hot-toast';
import { alertsApi } from '@/lib/api';

export type ManualAlertInput = {
  title: string;
  severity: 'info' | 'low' | 'medium' | 'high' | 'critical';
  description?: string;
  host?: string;
  user?: string;
  ip?: string;
};

/** The body `POST /alerts/submit` takes for one hand-entered alert. Blank optional fields are left out. */
export function buildManualAlert(input: ManualAlertInput, now: Date = new Date()) {
  const title = input.title.trim();
  const host = input.host?.trim();
  const user = input.user?.trim();
  const ip = input.ip?.trim();
  const description = input.description?.trim();
  const event: Record<string, unknown> = { displayMessage: title, severity: input.severity, published: now.toISOString() };
  if (user) event.actor = { alternateId: user };
  if (ip || host) event.client = { ...(ip ? { ipAddress: ip } : {}), ...(host ? { device: host } : {}) };
  return {
    events: [event],
    connector_type: 'manual',
    title,
    severity: input.severity,
    ...(description ? { description } : {}),
    tags: ['manual'],
  };
}

const SEVERITIES: ManualAlertInput['severity'][] = ['critical', 'high', 'medium', 'low', 'info'];
const field = 'w-full rounded-lg border border-gray-700 bg-gray-800 px-3 py-2 text-sm text-white focus:border-blue-500 focus:outline-none';

/** Hand-enter one alert (something seen outside the connected tools). */
export function CreateAlertModal({ open, onClose, onCreated }: { open: boolean; onClose: () => void; onCreated: () => void }) {
  const [title, setTitle] = useState('');
  const [severity, setSeverity] = useState<ManualAlertInput['severity']>('medium');
  const [description, setDescription] = useState('');
  const [host, setHost] = useState('');
  const [user, setUser] = useState('');
  const [ip, setIp] = useState('');
  const [busy, setBusy] = useState(false);

  if (!open) return null;

  const submit = async () => {
    if (busy) return;
    if (title.trim().length < 3) {
      toast.error('Give the alert a title (at least 3 characters).');
      return;
    }
    setBusy(true);
    try {
      await alertsApi.create(buildManualAlert({ title, severity, description, host, user, ip }));
      toast.success('Alert created');
      setTitle('');
      setDescription('');
      setHost('');
      setUser('');
      setIp('');
      onCreated();
      onClose();
    } catch (err) {
      toast.error(err instanceof Error && err.message ? err.message : 'Could not create the alert.');
    } finally {
      setBusy(false);
    }
  };

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 p-4" role="dialog" aria-modal="true" aria-label="Create alert" onClick={onClose}>
      <div className="w-full max-w-lg rounded-xl border border-gray-800 bg-gray-900 shadow-2xl" onClick={(e) => e.stopPropagation()}>
        <div className="flex items-center justify-between border-b border-gray-800 px-5 py-4">
          <h2 className="text-base font-semibold text-white">Create alert</h2>
          <button type="button" onClick={onClose} className="text-gray-400 hover:text-white" aria-label="Close">
            ✕
          </button>
        </div>
        <div className="space-y-4 px-5 py-4">
          <div>
            <label htmlFor="alert-title" className="mb-1 block text-xs font-medium text-gray-400">
              Title
            </label>
            <input id="alert-title" value={title} onChange={(e) => setTitle(e.target.value)} className={field} placeholder="What happened?" />
          </div>
          <div>
            <label htmlFor="alert-severity" className="mb-1 block text-xs font-medium text-gray-400">
              Severity
            </label>
            <select id="alert-severity" value={severity} onChange={(e) => setSeverity(e.target.value as ManualAlertInput['severity'])} className={field}>
              {SEVERITIES.map((s) => (
                <option key={s} value={s}>
                  {s.charAt(0).toUpperCase() + s.slice(1)}
                </option>
              ))}
            </select>
          </div>
          <div>
            <label htmlFor="alert-description" className="mb-1 block text-xs font-medium text-gray-400">
              Description <span className="text-gray-600">(optional)</span>
            </label>
            <textarea id="alert-description" value={description} onChange={(e) => setDescription(e.target.value)} rows={3} className={`${field} resize-none`} />
          </div>
          <div className="grid grid-cols-3 gap-3">
            <div>
              <label htmlFor="alert-host" className="mb-1 block text-xs font-medium text-gray-400">
                Host
              </label>
              <input id="alert-host" value={host} onChange={(e) => setHost(e.target.value)} className={field} />
            </div>
            <div>
              <label htmlFor="alert-user" className="mb-1 block text-xs font-medium text-gray-400">
                User
              </label>
              <input id="alert-user" value={user} onChange={(e) => setUser(e.target.value)} className={field} />
            </div>
            <div>
              <label htmlFor="alert-ip" className="mb-1 block text-xs font-medium text-gray-400">
                IP address
              </label>
              <input id="alert-ip" value={ip} onChange={(e) => setIp(e.target.value)} className={field} />
            </div>
          </div>
        </div>
        <div className="flex justify-end gap-2 border-t border-gray-800 px-5 py-3">
          <button type="button" onClick={onClose} className="rounded-lg px-4 py-2 text-sm text-gray-300 hover:text-white">
            Cancel
          </button>
          <button
            type="button"
            disabled={busy}
            onClick={() => void submit()}
            className="rounded-lg bg-blue-600 px-4 py-2 text-sm text-white hover:bg-blue-500 disabled:opacity-40"
          >
            {busy ? 'Creating…' : 'Create alert'}
          </button>
        </div>
      </div>
    </div>
  );
}
