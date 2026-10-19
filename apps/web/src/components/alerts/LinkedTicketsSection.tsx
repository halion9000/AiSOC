'use client';

/**
 * The PSA tickets (HaloPSA) linked to an alert, in the investigation rail.
 *
 * CORE reads the ticket ids a security tool recorded on its incident (Huntress opens a PSA ticket per incident) and looks each one up in HaloPSA, so the analyst sees the
 * ticket's summary and status here and can open it. Renders nothing for an alert with no linked tickets. Shares its request with the remediation section (same SWR key).
 */

import useSWR from 'swr';
import { alertsApi, type LinkedTicket } from '@/lib/api';

/** The ticket's own link, only when it is a plain https address (it comes from CORE, so never a script or data URL). */
export function safeTicketUrl(url: string | undefined): string | null {
  return typeof url === 'string' && /^https:\/\/[^\s]+$/i.test(url) ? url : null;
}

export function LinkedTicketsList({ tickets }: { tickets: LinkedTicket[] }) {
  if (tickets.length === 0) return null;
  return (
    <section aria-label="Linked tickets" className="space-y-2">
      <h3 className="text-xs font-medium uppercase tracking-wider text-gray-500">Linked tickets</h3>
      <ul className="space-y-2">
        {tickets.map((t) => {
          const href = safeTicketUrl(t.url);
          return (
            <li key={`${t.system}:${t.id}`} className="rounded-lg border border-gray-800/60 bg-gray-900/40 px-3 py-2 text-sm">
              <div className="flex items-center justify-between gap-2">
                {href ? (
                  <a href={href} target="_blank" rel="noopener noreferrer" className="font-mono text-blue-400 hover:text-blue-300">
                    #{t.id}
                  </a>
                ) : (
                  <span className="font-mono text-gray-300">#{t.id}</span>
                )}
                {t.status ? <span className="text-xs text-gray-400">{t.status}</span> : null}
              </div>
              <p className="mt-0.5 text-gray-200">{t.summary ?? 'Not found in HaloPSA'}</p>
              {t.client ? <p className="text-xs text-gray-500">{t.client}</p> : null}
            </li>
          );
        })}
      </ul>
    </section>
  );
}

export function LinkedTicketsSection({ alertId }: { alertId: string }) {
  const { data } = useSWR(['alerts', alertId, 'vendor-actions'] as const, () => alertsApi.vendorActions(alertId));
  return <LinkedTicketsList tickets={data?.tickets ?? []} />;
}
