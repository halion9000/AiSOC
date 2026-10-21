import type { AlertFilters } from '@/lib/api';

/**
 * Which Alerts filters are remembered between visits, and how a saved set is put back. Search, the device, the page and the time range are for the moment and are never kept. A saved value
 * that is no longer valid (an older build saved something else) is ignored rather than trusted.
 */
const SEVERITIES = ['critical', 'high', 'medium', 'low', 'info'] as const;
const STATUSES = ['open', 'new', 'investigating', 'resolved', 'false_positive'] as const;

export interface RememberedAlertFilters {
  severity?: string;
  /** "all" means every status; the list's own default (open) is a status like the others. */
  status: string;
  source?: string;
  clientId?: string;
  ticket?: 'linked' | 'none';
  /** One row for each group of repeat alerts. */
  collapse?: boolean;
}

/** What to keep from the current filters. */
export function rememberable(f: AlertFilters): RememberedAlertFilters {
  return { severity: f.severity, status: f.status ?? 'all', source: f.source, clientId: f.clientId, ticket: f.ticket, collapse: f.collapse };
}

const text = (v: unknown, max = 100): string | undefined => (typeof v === 'string' && v.trim() && v.length <= max ? v : undefined);

/** ``base`` with the saved filters put back. Anything missing or invalid leaves ``base`` as it was. */
export function restoreFilters(base: AlertFilters, saved: unknown): AlertFilters {
  if (!saved || typeof saved !== 'object' || Array.isArray(saved)) return base;
  const s = saved as Record<string, unknown>;
  const out: AlertFilters = { ...base, page: 1 };
  const severity = text(s.severity);
  if (severity && (SEVERITIES as readonly string[]).includes(severity)) out.severity = severity;
  if (s.status === 'all') delete out.status;
  else if (typeof s.status === 'string' && (STATUSES as readonly string[]).includes(s.status)) out.status = s.status;
  const source = text(s.source);
  if (source) out.source = source;
  const clientId = text(s.clientId);
  if (clientId) out.clientId = clientId;
  if (s.ticket === 'linked' || s.ticket === 'none') out.ticket = s.ticket;
  if (s.collapse === true) out.collapse = true;
  return out;
}
