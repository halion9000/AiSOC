'use client';

import { useState } from 'react';
import Link from 'next/link';
import useSWR from 'swr';
import toast from 'react-hot-toast';
import { alertsApi, type AlertSuppression } from '@/lib/api';
import { safeFormat } from '@/lib/safe-date';

/** Who a rule covers, in words. */
export function coverage(r: Pick<AlertSuppression, 'scope' | 'client_name' | 'device'>): string {
  if (r.scope === 'all') return 'All clients';
  if (r.scope === 'client') return r.client_name ?? 'One client';
  return `${r.device ?? 'One device'}${r.client_name ? ` (${r.client_name})` : ''}`;
}

/** How long a rule lasts, in words. */
export function lasts(r: Pick<AlertSuppression, 'indefinite' | 'expires_at'>): string {
  if (r.indefinite || !r.expires_at) return 'Hidden indefinitely';
  const days = Math.ceil((Date.parse(r.expires_at) - Date.now()) / 86_400_000);
  return days <= 0 ? 'Ending now' : `Until ${safeFormat(r.expires_at, 'PP')} (${days} day${days === 1 ? '' : 's'} left)`;
}

/** The alert types currently hidden, who each is hidden for and until when, with a way to stop hiding any of them. */
export function HiddenAlertTypes() {
  const { data, error, isLoading, mutate } = useSWR('alert-suppressions', () => alertsApi.suppressions(), { revalidateOnFocus: false });
  const [busy, setBusy] = useState<string | null>(null);

  const lift = async (r: AlertSuppression) => {
    setBusy(r.id);
    try {
      const out = await alertsApi.liftSuppression(r.id);
      toast.success(out.hidden_alerts > 0 ? `Showing ${out.hidden_alerts} alert${out.hidden_alerts === 1 ? '' : 's'} again` : 'No longer hidden');
      await mutate();
    } catch (err) {
      toast.error(err instanceof Error ? err.message : 'Could not stop hiding this alert type');
    } finally {
      setBusy(null);
    }
  };

  return (
    <div className="max-w-5xl space-y-4">
      <div className="flex items-end justify-between gap-3">
        <div>
          <h1 className="text-xl font-semibold text-gray-100">Hidden alert types</h1>
          <p className="mt-0.5 text-sm text-gray-500">Alert types you chose to hide, for a device, a client or everyone. Nothing is deleted: stopping a rule, or letting it run out, brings its alerts back as they were.</p>
        </div>
        <Link href="/alerts" className="text-sm text-blue-400 hover:underline">
          Back to alerts
        </Link>
      </div>

      {error ? (
        <p role="alert" className="rounded border border-red-500/40 bg-red-500/10 p-3 text-sm text-red-300">
          Could not load the hidden alert types{error instanceof Error ? `: ${error.message}` : ''}.
        </p>
      ) : isLoading ? (
        <p className="text-sm text-gray-500">Loading…</p>
      ) : (data ?? []).length === 0 ? (
        <p data-testid="none" className="rounded border border-gray-800 p-4 text-sm text-gray-400">
          Nothing is hidden. Open an alert and press &ldquo;Hide alert type&rdquo; to hide that type of alert.
        </p>
      ) : (
        <table className="w-full text-left text-sm">
          <thead className="text-xs uppercase text-gray-500">
            <tr className="border-b border-gray-800">
              <th className="px-3 py-2">Alert type</th>
              <th className="px-3 py-2">Tool</th>
              <th className="px-3 py-2">Hidden for</th>
              <th className="px-3 py-2">How long</th>
              <th className="px-3 py-2 text-right">Hiding now</th>
              <th className="px-3 py-2" />
            </tr>
          </thead>
          <tbody>
            {(data ?? []).map((r) => (
              <tr key={r.id} className="border-b border-gray-800" data-testid="rule">
                <td className="px-3 py-2 text-gray-100">{r.title || '—'}</td>
                <td className="px-3 py-2 text-gray-300">{r.source ?? '—'}</td>
                <td className="px-3 py-2 text-gray-300">{coverage(r)}</td>
                <td className="px-3 py-2 text-gray-400">{lasts(r)}</td>
                <td className="px-3 py-2 text-right tabular-nums text-gray-200">{r.hidden_alerts}</td>
                <td className="px-3 py-2 text-right">
                  <button
                    type="button"
                    onClick={() => void lift(r)}
                    disabled={busy === r.id}
                    aria-label={`Stop hiding ${r.title}`}
                    className="rounded border border-gray-700 px-2 py-1 text-xs text-gray-200 hover:bg-gray-800 disabled:opacity-50"
                  >
                    Stop hiding
                  </button>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
    </div>
  );
}
