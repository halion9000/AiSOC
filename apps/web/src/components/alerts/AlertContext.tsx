'use client';

/**
 * Who and where an alert is about, at the top of the alert page: the company, the device, the people and addresses it names, and the HaloPSA ticket if one matched. Until now the page
 * showed only the alert's own text and a raw tenant id, so an analyst had to open other pages to learn whose machine this was.
 */

import { useState } from 'react';
import Link from 'next/link';
import toast from 'react-hot-toast';
import useSWR from 'swr';
import { alertsApi, type Alert, type LinkedTicket } from '@/lib/api';
import { vendorLabel } from '@/components/mssp/ClientMapping';
import { safeTicketUrl } from './LinkedTicketsSection';

function Row({ label, children }: { label: string; children: React.ReactNode }) {
  return (
    <div className="flex items-start gap-4">
      <span className="w-32 shrink-0 pt-0.5 text-xs text-gray-500">{label}</span>
      <span className="min-w-0 text-sm text-gray-200">{children}</span>
    </div>
  );
}

const none = (text: string) => <span className="text-gray-500">{text}</span>;

export function TicketRows({ tickets, onRemove }: { tickets: LinkedTicket[]; onRemove?: (id: string) => void }) {
  if (tickets.length === 0) return none('No HaloPSA ticket matched');
  return (
    <ul className="space-y-1">
      {tickets.map((t) => {
        const href = safeTicketUrl(t.url);
        return (
          <li key={`${t.system}:${t.id}`}>
            {href ? (
              <a href={href} target="_blank" rel="noopener noreferrer" className="font-mono text-blue-400 hover:text-blue-300">
                #{t.id}
              </a>
            ) : (
              <span className="font-mono text-gray-300">#{t.id}</span>
            )}{' '}
            {t.summary ?? 'Not found in HaloPSA'}
            {t.status ? <span className="text-gray-400"> · {t.status}</span> : null}{' '}
            {href ? (
              <a href={href} target="_blank" rel="noopener noreferrer" className="text-xs text-blue-400 hover:text-blue-300">
                Open in HaloPSA
              </a>
            ) : null}
            {t.manual ? <span className="ml-1 rounded bg-gray-800 px-1.5 py-0.5 text-[10px] text-gray-400">added by hand</span> : null}
            {t.manual && onRemove ? (
              <button type="button" onClick={() => onRemove(t.id)} className="ml-2 text-xs text-gray-500 hover:text-red-300" aria-label={`Remove ticket ${t.id}`}>
                Remove
              </button>
            ) : null}
          </li>
        );
      })}
    </ul>
  );
}

/** The pure part: what the section shows for an alert and its tickets, so it can be tested without a page. */
export function alertContextOf(alert: Pick<Alert, 'clientName' | 'affectedHosts' | 'affectedUsers' | 'affectedIps' | 'device'>) {
  const hosts = alert.affectedHosts && alert.affectedHosts.length > 0 ? alert.affectedHosts : alert.device ? [alert.device] : [];
  return { company: alert.clientName ?? null, hosts, users: alert.affectedUsers ?? [], ips: alert.affectedIps ?? [] };
}

/** The form to link a ticket by hand. The number is required; the summary and link are optional. */
export function AddTicket({ alertId, onAdded }: { alertId: string; onAdded: () => void }) {
  const [open, setOpen] = useState(false);
  const [number, setNumber] = useState('');
  const [summary, setSummary] = useState('');
  const [url, setUrl] = useState('');
  const [busy, setBusy] = useState(false);

  async function save() {
    setBusy(true);
    try {
      await alertsApi.addTicket(alertId, { id: number.trim(), ...(summary.trim() ? { summary: summary.trim() } : {}), ...(url.trim() ? { url: url.trim() } : {}) });
      toast.success(`Ticket ${number.trim().replace(/^#/, '')} linked.`);
      setNumber('');
      setSummary('');
      setUrl('');
      setOpen(false);
      onAdded();
    } catch (err) {
      toast.error(err instanceof Error ? err.message : 'Could not link the ticket.');
    } finally {
      setBusy(false);
    }
  }

  if (!open) {
    return (
      <button type="button" onClick={() => setOpen(true)} className="mt-1 text-xs text-blue-400 hover:text-blue-300">
        Add a ticket
      </button>
    );
  }
  const input = 'w-full rounded border border-gray-700 bg-gray-900 px-2 py-1 text-sm text-gray-200';
  return (
    <div className="mt-2 space-y-2 rounded border border-gray-800 p-2" data-testid="add-ticket">
      <input aria-label="Ticket number" className={input} placeholder="Ticket number, e.g. 4521" value={number} onChange={(e) => setNumber(e.target.value)} />
      <input aria-label="Ticket summary" className={input} placeholder="What it is about (optional)" value={summary} onChange={(e) => setSummary(e.target.value)} />
      <input aria-label="Ticket link" className={input} placeholder="https:// link to the ticket (optional)" value={url} onChange={(e) => setUrl(e.target.value)} />
      <div className="flex gap-2">
        <button type="button" disabled={busy || number.trim().replace(/^#/, '') === ''} onClick={() => void save()} className="rounded bg-blue-600 px-3 py-1 text-xs text-white disabled:opacity-50">
          Link ticket
        </button>
        <button type="button" onClick={() => setOpen(false)} className="rounded border border-gray-700 px-3 py-1 text-xs text-gray-300">
          Cancel
        </button>
      </div>
    </div>
  );
}

/** The link to the alert in the tool that raised it, only when it is a plain https address. */
export function sourceLink(alert: Pick<Alert, 'source' | 'sourceUrl'>): { href: string; label: string } | null {
  const href = safeTicketUrl(alert.sourceUrl);
  if (href === null) return null;
  return { href, label: `Open in ${vendorLabel(alert.source)}` };
}

export function AlertContext({ alert }: { alert: Alert }) {
  const { data, mutate } = useSWR(['alerts', alert.id, 'vendor-actions'] as const, () => alertsApi.vendorActions(alert.id));
  async function remove(ticketId: string) {
    try {
      await alertsApi.removeTicket(alert.id, ticketId);
      await mutate();
    } catch (err) {
      toast.error(err instanceof Error ? err.message : 'Could not remove the ticket.');
    }
  }
  const { company, hosts, users, ips } = alertContextOf(alert);
  return (
    <section aria-label="Where and who" className="rounded-xl border border-gray-800/60 bg-gray-900/60 p-5" data-testid="alert-context">
      <h3 className="mb-4 text-xs font-semibold uppercase tracking-wider text-gray-400">Where and who</h3>
      <div className="space-y-3">
        <Row label="Company">{company ?? none('Your own organization')}</Row>
        <Row label="Device">
          {hosts.length === 0 ? (
            none('This alert names no device')
          ) : (
            <span className="flex flex-wrap gap-x-3 gap-y-1">
              {hosts.map((h) => (
                <Link key={h} href={`/devices?search=${encodeURIComponent(h)}`} className="text-blue-400 hover:text-blue-300" title="Find this device on the Devices page">
                  {h}
                </Link>
              ))}
            </span>
          )}
        </Row>
        <Row label="User">{users.length === 0 ? none('This alert names no user') : users.join(', ')}</Row>
        {ips.length > 0 && <Row label="Address">{ips.join(', ')}</Row>}
        {sourceLink(alert) && (
          <Row label="Source alert">
            <a href={sourceLink(alert)!.href} target="_blank" rel="noopener noreferrer" className="text-blue-400 hover:text-blue-300">
              {sourceLink(alert)!.label}
            </a>
          </Row>
        )}
        <Row label="HaloPSA ticket">
          <div>
            <TicketRows tickets={data?.tickets ?? []} onRemove={(id) => void remove(id)} />
            <AddTicket alertId={alert.id} onAdded={() => void mutate()} />
          </div>
        </Row>
      </div>
    </section>
  );
}
