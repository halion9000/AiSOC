'use client';

import { useEffect, useState } from 'react';

import { ApiError, copilotApi, type CopilotPendingAction } from '@/lib/api';

type Phase = 'idle' | 'working' | 'done' | 'failed' | 'cancelled';

/** The server's own reason (expired, not issued to you, ...) when it gave one, otherwise a plain fallback. */
function reasonFrom(err: unknown): string {
  if (err instanceof ApiError) {
    try {
      const detail = (JSON.parse(err.body) as { detail?: unknown }).detail;
      if (typeof detail === 'string' && detail) return detail;
    } catch {
      /* not JSON: fall through */
    }
    if (err.status === 0) return 'The AiSOC API could not be reached. Nothing was changed.';
  }
  return 'Could not confirm. Nothing was changed.';
}

/**
 * Asks the analyst to approve a destructive action the Copilot requested. NOTHING has happened until they click the confirm button, which makes their own
 * authenticated call; the confirmation token is signed, expires, and is bound to them, so a message in the conversation can never approve it on their behalf.
 */
export function PendingActionPrompt({ action }: { action: CopilotPendingAction }) {
  const [phase, setPhase] = useState<Phase>('idle');
  const [detail, setDetail] = useState('');
  const [expired, setExpired] = useState(() => Date.now() / 1000 >= action.expiresAt);

  useEffect(() => {
    if (expired) return;
    const ms = Math.max(0, action.expiresAt * 1000 - Date.now());
    const timer = setTimeout(() => setExpired(true), ms);
    return () => clearTimeout(timer);
  }, [action.expiresAt, expired]);

  const destructive = action.action.startsWith('delete');
  const settled = phase === 'done' || phase === 'failed' || phase === 'cancelled';

  const confirm = async () => {
    if (phase !== 'idle' || expired) return;
    setPhase('working');
    try {
      const res = await copilotApi.confirmAction(action.token);
      if (res.status === 'done') {
        setDetail(destructive ? 'Deleted.' : 'Done.');
        setPhase('done');
      } else {
        const why = typeof res.result?.error === 'string' ? res.result.error : 'It could not be completed.';
        setDetail(`${why} Nothing was changed.`);
        setPhase('failed');
      }
    } catch (err) {
      setDetail(reasonFrom(err));
      setPhase('failed');
    }
  };

  return (
    <div
      role="group"
      aria-label="Confirmation required"
      className="mt-2 rounded-lg border border-amber-500/40 bg-amber-500/10 p-3 text-sm text-amber-100"
    >
      <p className="font-medium">Confirmation required</p>
      <p className="mt-1 whitespace-normal text-amber-50/90">{action.summary}</p>
      {settled ? (
        <p role="status" className="mt-2 text-xs text-amber-100/80">
          {phase === 'cancelled' ? 'Cancelled. Nothing was changed.' : detail}
        </p>
      ) : expired ? (
        <p role="status" className="mt-2 text-xs text-amber-100/80">
          This confirmation has expired. Ask the Copilot again if you still want to do this.
        </p>
      ) : (
        <div className="mt-2 flex gap-2">
          <button
            type="button"
            onClick={() => void confirm()}
            disabled={phase === 'working'}
            className="rounded-md bg-red-600 px-3 py-1 text-xs font-semibold text-white hover:bg-red-500 disabled:opacity-60"
          >
            {phase === 'working' ? 'Working...' : destructive ? 'Delete' : 'Confirm'}
          </button>
          <button
            type="button"
            onClick={() => setPhase('cancelled')}
            disabled={phase === 'working'}
            className="rounded-md border border-slate-600 px-3 py-1 text-xs text-slate-200 hover:bg-slate-800 disabled:opacity-60"
          >
            Cancel
          </button>
        </div>
      )}
    </div>
  );
}
