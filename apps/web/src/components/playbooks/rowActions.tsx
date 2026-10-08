'use client';

/**
 * Shared per-row action primitives for the Playbooks page.
 *
 * Extracted from PlaybooksView.tsx so the gallery can reuse them without a
 * circular import. The original behavior is preserved exactly (same fetch
 * URLs, same SWR cache keys, same UX).
 */

import React, { useState } from 'react';
import { mutate } from 'swr';
import type { Playbook } from './types';
import { isShippedPack } from './packHelpers';
import { authFetch } from '@/lib/auth-session';

/**
 * Small toggle that flips Playbook.enabled via PUT /api/v1/playbooks/<id>.
 *
 * A shared LIBRARY playbook is read-only: its toggle is locked (the server would answer 403), with the reason in the tooltip. To run your own version, fork it, then enable the copy. A failed request is
 * shown, not swallowed: the toggle used to ignore the response, so a refusal looked like the switch silently flipping back.
 */
export function EnabledToggle({ playbook }: { playbook: Playbook }) {
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const locked = isShippedPack(playbook);
  async function toggle() {
    setLoading(true);
    setError(null);
    try {
      const res = await authFetch(`/api/v1/playbooks/${encodeURIComponent(playbook.id)}`, {
        method: 'PUT',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ enabled: !playbook.enabled }),
      });
      if (!res.ok) {
        const text = await res.text().catch(() => '');
        let detail = text;
        try {
          const parsed = JSON.parse(text);
          if (typeof parsed?.detail === 'string') detail = parsed.detail;
        } catch {
          /* not JSON */
        }
        setError(detail || `Could not change this playbook (HTTP ${res.status}).`);
        return;
      }
      await mutate('/api/v1/playbooks');
    } catch (e) {
      setError(e instanceof Error ? e.message : 'Could not change this playbook.');
    } finally {
      setLoading(false);
    }
  }
  const lockedReason = 'Shared library playbook (read-only). Fork it to run your own version, then enable the copy.';
  return (
    <>
      <button
        onClick={toggle}
        disabled={loading || locked}
        title={locked ? lockedReason : playbook.enabled ? 'Enabled \u2014 click to disable' : 'Disabled \u2014 click to enable'}
        aria-label={`${playbook.enabled ? 'Disable' : 'Enable'} ${playbook.name}`}
        aria-pressed={playbook.enabled}
        aria-disabled={locked || undefined}
        className={`relative inline-flex h-5 w-9 items-center rounded-full transition-colors focus:outline-none focus:ring-2 focus:ring-blue-500 ${
          locked ? 'cursor-not-allowed opacity-50 ' : ''
        }${playbook.enabled ? 'bg-green-600' : 'bg-gray-700'}`}
      >
        <span
          className={`inline-block h-3.5 w-3.5 rounded-full bg-white transition-transform ${
            playbook.enabled ? 'translate-x-4' : 'translate-x-1'
          }`}
        />
      </button>
      {error && (
        <span role="alert" className="ml-2 text-[10px] text-red-400">
          {error}
        </span>
      )}
    </>
  );
}

/** "Run" / dry-run button that POSTs to /api/v1/playbooks/<id>/run. */
export function RunButton({ playbook }: { playbook: Playbook }) {
  const [status, setStatus] = useState<'idle' | 'running' | 'done' | 'err'>('idle');
  async function run() {
    setStatus('running');
    try {
      const res = await authFetch(`/api/v1/playbooks/${playbook.id}/run`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ context: {}, dry_run: true }),
      });
      if (!res.ok) throw new Error();
      setStatus('done');
    } catch {
      setStatus('err');
    }
    setTimeout(() => setStatus('idle'), 3000);
  }
  const label = { idle: 'Run', running: '…', done: 'OK', err: 'Err' }[status];
  const color = {
    idle:    'text-green-500 hover:text-green-400',
    running: 'text-yellow-500',
    done:    'text-green-400',
    err:     'text-red-400',
  }[status];
  return (
    <button
      onClick={run}
      disabled={status === 'running'}
      title="Dry run"
      aria-label={`Dry-run ${playbook.name}`}
      className={`text-xs px-2.5 py-1 rounded border border-gray-700 transition-colors ${color}`}
    >
      {label}
    </button>
  );
}

/** Delete a playbook (used only for user-created playbooks, not shipped packs). */
export async function deletePlaybook(id: string) {
  if (!confirm('Delete this playbook?')) return;
  await authFetch(`/api/v1/playbooks/${id}`, { method: 'DELETE' });
  await mutate('/api/v1/playbooks');
}
