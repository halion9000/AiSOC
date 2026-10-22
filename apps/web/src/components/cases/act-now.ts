import type { Case } from '@/lib/api';

const RANK: Record<string, number> = { critical: 0, high: 1, medium: 2, low: 3 };
/** A case somebody still has to deal with. */
const LIVE = new Set<Case['status']>(['open', 'in_progress', 'pending']);

export interface ActNow {
  /** Cases not resolved or closed. */
  open: number;
  /** Of those, how many have nobody assigned. */
  unassigned: number;
  /** The one to start with, or null when nothing is open. */
  first: Case | null;
  /** The first few in the order to work them (most severe, then no owner, then oldest). */
  top: Case[];
  /** One plain sentence for the top of the page. */
  headline: string;
}

/** Most severe first; among equals, one with no owner before one somebody has; then the oldest, which has waited longest. */
export function workOrder(a: Case, b: Case): number {
  const sev = (RANK[a.severity] ?? 4) - (RANK[b.severity] ?? 4);
  if (sev !== 0) return sev;
  const owner = Number(Boolean(a.assignee)) - Number(Boolean(b.assignee));
  if (owner !== 0) return owner;
  return Date.parse(a.createdAt) - Date.parse(b.createdAt) || a.title.localeCompare(b.title);
}

/**
 * What to look at first: "12 open cases, 8 with no owner. Start with Ransomware Attempt."
 * `cases` are the ones to pick from; `totals` are the counts over the whole caseload when the caller has them (the list is one page of it, so counting it would understate).
 */
export function actNow(cases: readonly Case[], howMany = 3, totals?: { open: number; unassigned: number }): ActNow {
  const live = cases.filter((c) => LIVE.has(c.status)).sort(workOrder);
  const unassigned = totals?.unassigned ?? live.filter((c) => !c.assignee).length;
  const openCount = totals?.open ?? live.length;
  const first = live[0] ?? null;
  const plural = (n: number, word: string) => `${n} ${word}${n === 1 ? '' : 's'}`;
  const headline =
    openCount === 0
      ? 'No open cases. Nothing needs you right now.'
      : `${plural(openCount, 'open case')}, ${unassigned === 0 ? 'all with an owner' : `${unassigned} with no owner`}. Start with ${first?.title ?? ''}.`;
  return { open: openCount, unassigned, first, top: live.slice(0, howMany), headline };
}
