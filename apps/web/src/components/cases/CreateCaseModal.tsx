'use client';

import { useState } from 'react';
import toast from 'react-hot-toast';
import { casesApi } from '@/lib/api';

const SEVERITIES = ['critical', 'high', 'medium', 'low'] as const;
export type CaseSeverityChoice = (typeof SEVERITIES)[number];
const field = 'w-full rounded-lg border border-gray-700 bg-gray-800 px-3 py-2 text-sm text-white focus:border-blue-500 focus:outline-none';

/** What `casesApi.create` is given for a hand-opened case. A blank description is left out. */
export function buildNewCase(input: { title: string; severity: CaseSeverityChoice; description?: string }) {
  const description = input.description?.trim();
  return { title: input.title.trim(), severity: input.severity, ...(description ? { description } : {}) };
}

/** Open a case by hand (an investigation that did not start from an alert). */
export function CreateCaseModal({ open, onClose, onCreated }: { open: boolean; onClose: () => void; onCreated: () => void }) {
  const [title, setTitle] = useState('');
  const [severity, setSeverity] = useState<CaseSeverityChoice>('medium');
  const [description, setDescription] = useState('');
  const [busy, setBusy] = useState(false);

  if (!open) return null;

  const submit = async () => {
    if (busy) return;
    if (title.trim().length < 3) {
      toast.error('Give the case a title (at least 3 characters).');
      return;
    }
    setBusy(true);
    try {
      await casesApi.create(buildNewCase({ title, severity, description }));
      toast.success('Case created');
      setTitle('');
      setDescription('');
      onCreated();
      onClose();
    } catch (err) {
      toast.error(err instanceof Error && err.message ? err.message : 'Could not create the case.');
    } finally {
      setBusy(false);
    }
  };

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 p-4" role="dialog" aria-modal="true" aria-label="Create case" onClick={onClose}>
      <div className="w-full max-w-lg rounded-xl border border-gray-800 bg-gray-900 shadow-2xl" onClick={(e) => e.stopPropagation()}>
        <div className="flex items-center justify-between border-b border-gray-800 px-5 py-4">
          <h2 className="text-base font-semibold text-white">New case</h2>
          <button type="button" onClick={onClose} className="text-gray-400 hover:text-white" aria-label="Close">
            ✕
          </button>
        </div>
        <div className="space-y-4 px-5 py-4">
          <div>
            <label htmlFor="case-title" className="mb-1 block text-xs font-medium text-gray-400">
              Title
            </label>
            <input id="case-title" value={title} onChange={(e) => setTitle(e.target.value)} className={field} placeholder="What are you investigating?" />
          </div>
          <div>
            <label htmlFor="case-severity" className="mb-1 block text-xs font-medium text-gray-400">
              Severity
            </label>
            <select id="case-severity" value={severity} onChange={(e) => setSeverity(e.target.value as CaseSeverityChoice)} className={field}>
              {SEVERITIES.map((s) => (
                <option key={s} value={s}>
                  {s.charAt(0).toUpperCase() + s.slice(1)}
                </option>
              ))}
            </select>
          </div>
          <div>
            <label htmlFor="case-description" className="mb-1 block text-xs font-medium text-gray-400">
              Description <span className="text-gray-600">(optional)</span>
            </label>
            <textarea id="case-description" value={description} onChange={(e) => setDescription(e.target.value)} rows={4} className={`${field} resize-none`} />
          </div>
        </div>
        <div className="flex justify-end gap-2 border-t border-gray-800 px-5 py-3">
          <button type="button" onClick={onClose} className="rounded-lg px-4 py-2 text-sm text-gray-300 hover:text-white">
            Cancel
          </button>
          <button type="button" disabled={busy} onClick={() => void submit()} className="rounded-lg bg-blue-600 px-4 py-2 text-sm text-white hover:bg-blue-500 disabled:opacity-40">
            {busy ? 'Creating…' : 'Create case'}
          </button>
        </div>
      </div>
    </div>
  );
}
