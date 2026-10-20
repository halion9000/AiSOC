'use client';

import { useState } from 'react';
import toast from 'react-hot-toast';
import { alertsApi } from '@/lib/api';

type AddTicket = (alertId: string, body: { id: string }) => Promise<unknown>;

export interface BulkResult {
  linked: number;
  failed: { alertId: string; message: string }[];
}

/** Link ticket ``ticketId`` to each alert, one request per alert (the same call the alert page uses). A failure on one never stops the others. */
export async function linkTicketToAlerts(alertIds: string[], ticketId: string, addTicket: AddTicket = alertsApi.addTicket): Promise<BulkResult> {
  const result: BulkResult = { linked: 0, failed: [] };
  for (const alertId of alertIds) {
    try {
      await addTicket(alertId, { id: ticketId });
      result.linked++;
    } catch (err) {
      result.failed.push({ alertId, message: err instanceof Error ? err.message : 'Could not link the ticket' });
    }
  }
  return result;
}

/** "Linked ticket 4521 to 3 alerts." / "Linked ticket 4521 to 2 alerts; 1 failed: ..." */
export function bulkSummary(ticketId: string, r: BulkResult): string {
  const noun = (n: number) => `${n} alert${n === 1 ? '' : 's'}`;
  const base = `Linked ticket ${ticketId} to ${noun(r.linked)}`;
  return r.failed.length === 0 ? `${base}.` : `${base}; ${r.failed.length} failed: ${r.failed[0].message}`;
}

/** Shown above the alert list while rows are ticked: one ticket number, linked to every ticked alert. */
export default function BulkTicketBar({ alertIds, onDone, onClear }: { alertIds: string[]; onDone: () => void; onClear: () => void }) {
  const [ticket, setTicket] = useState('');
  const [busy, setBusy] = useState(false);
  if (alertIds.length === 0) return null;

  const submit = async () => {
    const id = ticket.trim().replace(/^#/, '');
    if (!id) return;
    setBusy(true);
    try {
      const result = await linkTicketToAlerts(alertIds, id);
      if (result.failed.length === 0) toast.success(bulkSummary(id, result));
      else toast.error(bulkSummary(id, result));
      if (result.linked > 0) onDone();
      if (result.failed.length === 0) {
        setTicket('');
        onClear();
      }
    } finally {
      setBusy(false);
    }
  };

  return (
    <div data-testid="bulk-ticket-bar" className="flex items-center gap-2 border-b border-gray-800/60 bg-blue-500/5 px-4 py-2 text-xs text-gray-300">
      <span>{alertIds.length} selected</span>
      <input
        aria-label="Ticket number"
        value={ticket}
        onChange={(e) => setTicket(e.target.value)}
        onKeyDown={(e) => {
          if (e.key === 'Enter') void submit();
        }}
        placeholder="Halo ticket number"
        className="w-40 rounded border border-gray-700 bg-gray-900 px-2 py-1"
      />
      <button
        type="button"
        disabled={busy || !ticket.trim()}
        onClick={() => void submit()}
        className="rounded border border-blue-500/40 bg-blue-500/10 px-2 py-1 text-blue-300 hover:bg-blue-500/20 disabled:opacity-40"
      >
        {busy ? 'Linking...' : 'Link ticket'}
      </button>
      <button type="button" onClick={onClear} className="ml-auto text-gray-500 hover:text-gray-300">
        Clear selection
      </button>
    </div>
  );
}
