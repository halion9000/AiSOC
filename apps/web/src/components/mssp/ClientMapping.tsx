'use client';

import { useCallback, useEffect, useRef, useState } from 'react';
import toast from 'react-hot-toast';
import { msspApi, type DuplicateGroup, type ManagedTenantRow, type VendorClient } from '@/lib/api';

/**
 * Each customer has a different name in every tool ("Acme Dental, LLC" in Petra, "ACME" in Halo). CORE sends each tool's client list; here a person says which of
 * their clients each one is. Unmapped clients wait here (they are never dropped), a client you do not manage can be ignored, and a mapping can be undone.
 */

export interface ClientGroups {
  unmapped: VendorClient[];
  mapped: VendorClient[];
  ignored: VendorClient[];
  /** Mapped to a client tenant that was hidden (test clients). Kept apart so they leave the lists. */
  hidden: VendorClient[];
}

export type SortBy = 'name' | 'tool' | 'tenant';

const byText = (a: string, b: string) => a.localeCompare(b, undefined, { sensitivity: 'base', numeric: true });

/** A sorted copy. By name, the same customer from two tools lands side by side (that is how duplicates are spotted); ties break on tool. */
export function sortClients(clients: VendorClient[], by: SortBy): VendorClient[] {
  const key = (c: VendorClient) => (by === 'tool' ? c.vendor : by === 'tenant' ? (c.child_tenant_name ?? '') : c.vendor_client_name);
  return [...clients].sort((a, b) => byText(key(a), key(b)) || byText(a.vendor_client_name, b.vendor_client_name) || byText(a.vendor, b.vendor));
}

/** The tool named by ``?vendor=`` in a page's query string, or ``null`` when absent or not a plausible tool id. */
export function vendorFromSearch(search: string): string | null {
  const v = new URLSearchParams(search).get('vendor');
  return v && /^[a-z0-9][a-z0-9_-]{0,39}$/.test(v) ? v : null;
}

/** One tab per tool, with how many of its clients still need mapping, so each tool can be worked through on its own. */
export function toolTabs(clients: VendorClient[]): { vendor: string; total: number; unmapped: number }[] {
  const tabs = new Map<string, { vendor: string; total: number; unmapped: number }>();
  for (const c of clients) {
    const t = tabs.get(c.vendor) ?? { vendor: c.vendor, total: 0, unmapped: 0 };
    t.total += 1;
    if (!c.ignored && c.child_tenant_id === null) t.unmapped += 1;
    tabs.set(c.vendor, t);
  }
  return [...tabs.values()].sort((a, b) => byText(a.vendor, b.vendor));
}

/** The clients of one tool (or all, for tab === null) whose name contains the search text. */
export function filterClients(clients: VendorClient[], tab: string | null, search: string): VendorClient[] {
  const q = search.trim().toLowerCase();
  return clients.filter((c) => (tab === null || c.vendor === tab) && (q === '' || c.vendor_client_name.toLowerCase().includes(q) || (c.child_tenant_name ?? '').toLowerCase().includes(q)));
}

/** "; kept 3: Acme (it has audit records), ..." for the tenants a reset could not remove (the first few, then a count). */
export function keptSummary(kept: { name: string; reason: string }[]): string {
  if (kept.length === 0) return '';
  const shown = kept.slice(0, 3).map((k) => `${k.name} (${k.reason})`);
  return `; kept ${kept.length}: ${shown.join(', ')}${kept.length > 3 ? `, and ${kept.length - 3} more` : ''}`;
}

/** Remove clients one at a time (each request is short, so none is abandoned by the proxy). A failure for one is reported and the rest carry on. */
export async function removeClients(
  clients: { tenant_id: string; name: string }[],
  remove: (tenantId: string) => Promise<{ removed: boolean; name: string; reason: string | null }>,
  onProgress?: (done: number, total: number) => void,
): Promise<{ removed: number; kept: { name: string; reason: string }[] }> {
  let removed = 0;
  const kept: { name: string; reason: string }[] = [];
  for (const [i, c] of clients.entries()) {
    try {
      const out = await remove(c.tenant_id);
      if (out.removed) removed += 1;
      else kept.push({ name: out.name, reason: out.reason ?? 'it could not be removed' });
    } catch (err) {
      kept.push({ name: c.name, reason: err instanceof Error && err.message ? err.message : 'the request failed' });
    }
    onProgress?.(i + 1, clients.length);
  }
  return { removed, kept };
}

export function groupClients(clients: VendorClient[], by: SortBy = 'name'): ClientGroups {
  const sorted = sortClients(clients, by);
  const hidden = (c: VendorClient) => c.child_tenant_id !== null && c.child_tenant_hidden === true;
  return {
    unmapped: sorted.filter((c) => !c.ignored && c.child_tenant_id === null),
    mapped: sorted.filter((c) => !c.ignored && c.child_tenant_id !== null && !hidden(c)),
    ignored: sorted.filter((c) => c.ignored),
    hidden: sorted.filter((c) => !c.ignored && hidden(c)),
  };
}

/** How many unmapped clients each tool has, most first: what an "import all" button offers. */
export function unmappedByVendor(unmapped: VendorClient[]): { vendor: string; count: number }[] {
  const counts = new Map<string, number>();
  for (const c of unmapped) counts.set(c.vendor, (counts.get(c.vendor) ?? 0) + 1);
  return [...counts.entries()].map(([vendor, count]) => ({ vendor, count })).sort((a, b) => b.count - a.count || a.vendor.localeCompare(b.vendor));
}

/** The tools that have sent clients, with whether each adds its clients as tenants automatically. */
export function sourceChoices(clients: VendorClient[], synced: string[]): { vendor: string; on: boolean }[] {
  const vendors = new Set([...clients.map((c) => c.vendor), ...synced]);
  return [...vendors].sort().map((vendor) => ({ vendor, on: synced.includes(vendor) }));
}

const VENDOR_NAMES: Record<string, string> = { halopsa: 'HaloPSA', ninjaone: 'NinjaOne', petra: 'Petra', huntress: 'Huntress', blumira: 'Blumira', addigy: 'Addigy', liongard: 'Liongard', threatmate: 'ThreatMate', fieldeffect: 'Field Effect', dnsfilter: 'DNSFilter', autoelevate: 'AutoElevate', cipp: 'CIPP', screenconnect: 'ScreenConnect' };

/** "halopsa" -> "HaloPSA", "petra" -> "Petra"; a tool it doesn't know is capitalized. */
export function vendorLabel(vendor: string): string {
  return VENDOR_NAMES[vendor] ?? vendor.charAt(0).toUpperCase() + vendor.slice(1);
}

/**
 * The best suggested client for each of one tool's unmapped rows (id -> tenant id).
 * Rows with no suggestion are left out, and nothing is saved: this only fills in the dropdowns.
 */
export function suggestedChoices(unmapped: VendorClient[], vendor: string): Record<string, string> {
  const out: Record<string, string> = {};
  for (const c of unmapped) {
    const best = c.suggestions[0]?.tenant_id;
    if (c.vendor === vendor && c.child_tenant_id === null && !c.ignored && best) out[c.id] = best;
  }
  return out;
}

const NEW_CLIENT = '__new__';

function UnmappedRow({
  client,
  tenants,
  onChanged,
  prefill,
  checked,
  onCheck,
  onChoice,
}: {
  client: VendorClient;
  tenants: ManagedTenantRow[];
  onChanged: () => void;
  prefill?: { tenantId: string; n: number };
  checked: boolean;
  onCheck: (checked: boolean) => void;
  onChoice: (choice: string) => void;
}) {
  const best = client.suggestions[0]?.tenant_id ?? '';
  const [choice, setChoice] = useState<string>(best);
  const [busy, setBusy] = useState(false);

  useEffect(() => {
    if (prefill) setChoice(prefill.tenantId);
  }, [prefill]);

  useEffect(() => {
    onChoice(choice);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [choice]);

  const run = async (work: () => Promise<unknown>, done: string) => {
    setBusy(true);
    try {
      await work();
      toast.success(done);
      onChanged();
    } catch (err) {
      toast.error(err instanceof Error && err.message ? err.message : 'Could not save that.');
    } finally {
      setBusy(false);
    }
  };

  const save = () => {
    if (!choice) return;
    if (choice === NEW_CLIENT) {
      return run(() => msspApi.mapClient(client.id, { newTenantName: client.vendor_client_name }), `Added ${client.vendor_client_name} as a new client`);
    }
    return run(() => msspApi.mapClient(client.id, { childTenantId: choice }), `Mapped ${client.vendor_client_name}`);
  };

  return (
    <li className="flex flex-wrap items-center gap-3 px-5 py-3 border-b border-gray-800/40">
      <input
        type="checkbox"
        aria-label={`Select ${client.vendor_client_name}`}
        checked={checked}
        onChange={(e) => onCheck(e.target.checked)}
        className="h-4 w-4 rounded border-gray-600"
      />
      <div className="min-w-[14rem] flex-1">
        <p className="font-medium text-white">{client.vendor_client_name}</p>
        <p className="text-xs text-gray-500">{vendorLabel(client.vendor)}</p>
      </div>
      <label className="sr-only" htmlFor={`map-${client.id}`}>
        Client for {client.vendor_client_name}
      </label>
      <select
        id={`map-${client.id}`}
        value={choice}
        onChange={(e) => setChoice(e.target.value)}
        className="rounded-lg border border-gray-700 bg-gray-900 px-3 py-1.5 text-sm text-gray-200"
      >
        <option value="">Choose a client…</option>
        {client.suggestions.length > 0 ? (
          <optgroup label="Suggested">
            {client.suggestions.map((s) => (
              <option key={s.tenant_id} value={s.tenant_id}>
                {s.name} ({Math.round(s.score * 100)}%)
                {s.reason ? ` — ${s.reason}` : ''}
              </option>
            ))}
          </optgroup>
        ) : null}
        <optgroup label="All clients">
          {tenants
            .filter((t) => !client.suggestions.some((s) => s.tenant_id === t.tenant_id))
            .map((t) => (
              <option key={t.tenant_id} value={t.tenant_id}>
                {t.name}
              </option>
            ))}
        </optgroup>
        <option value={NEW_CLIENT}>＋ Add “{client.vendor_client_name}” as a new client</option>
      </select>
      <button
        type="button"
        disabled={busy || !choice}
        onClick={() => void save()}
        className="rounded-lg bg-blue-600 px-3 py-1.5 text-sm text-white hover:bg-blue-500 disabled:opacity-40 disabled:hover:bg-blue-600 transition-colors"
      >
        Map
      </button>
      <button
        type="button"
        disabled={busy}
        onClick={() => void run(() => msspApi.ignoreClient(client.id, true), `Ignoring ${client.vendor_client_name}`)}
        className="rounded-lg px-3 py-1.5 text-sm text-gray-400 hover:text-gray-200 transition-colors"
      >
        Ignore
      </button>
    </li>
  );
}

function SimpleRow({
  client,
  label,
  action,
  onClick,
  extraAction,
  onExtra,
}: {
  client: VendorClient;
  label: string;
  action: string;
  onClick: () => void;
  extraAction?: string;
  onExtra?: () => void;
}) {
  return (
    <li className="flex flex-wrap items-center gap-3 px-5 py-3 border-b border-gray-800/40">
      <div className="min-w-[14rem] flex-1">
        <p className="font-medium text-white">{client.vendor_client_name}</p>
        <p className="text-xs text-gray-500">{vendorLabel(client.vendor)}</p>
      </div>
      <p className="text-sm text-gray-300">{label}</p>
      <button type="button" onClick={onClick} className="rounded-lg px-3 py-1.5 text-sm text-gray-400 hover:text-gray-200 transition-colors">
        {action}
      </button>
      {extraAction && onExtra ? (
        <button type="button" onClick={onExtra} className="rounded-lg px-3 py-1.5 text-sm text-gray-400 hover:text-gray-200 transition-colors">
          {extraAction}
        </button>
      ) : null}
    </li>
  );
}

export default function ClientMapping({ tenants, onChanged }: { tenants: ManagedTenantRow[]; onChanged: () => void }) {
  const [clients, setClients] = useState<VendorClient[] | null>(null);
  const [synced, setSynced] = useState<string[]>([]);
  const [moving, setMoving] = useState(false);
  const [duplicates, setDuplicates] = useState<DuplicateGroup[]>([]);
  const [pairKeep, setPairKeep] = useState('');
  const [pairMerge, setPairMerge] = useState('');
  const [error, setError] = useState<string | null>(null);
  const [sortBy, setSortBy] = useState<SortBy>('name');
  const [tab, setTab] = useState<string | null>(null);
  const [search, setSearch] = useState('');
  const [confirmReset, setConfirmReset] = useState(false);
  const [typedReset, setTypedReset] = useState('');
  const [progress, setProgress] = useState<{ done: number; total: number } | null>(null);
  const [showHidden, setShowHidden] = useState(false);
  const [checked, setChecked] = useState<Set<string>>(new Set());
  const choices = useRef<Record<string, string>>({});
  const [approving, setApproving] = useState(false);
  const [prefills, setPrefills] = useState<Record<string, { tenantId: string; n: number }>>({});

  // A link such as /mssp?vendor=ninjaone (the Connectors card's "Map clients" button) opens on that tool's tab. Read once on mount; an unknown tool falls back to "all".
  useEffect(() => {
    const wanted = vendorFromSearch(window.location.search);
    if (wanted) setTab(wanted);
  }, []);

  const load = useCallback(async () => {
    try {
      const result = await msspApi.clients();
      setClients(result.clients);
      setSynced(result.sync_vendors ?? []);
      setDuplicates(result.duplicates ?? []);
      setError(null);
    } catch (err) {
      setError(err instanceof Error && err.message ? err.message : 'Could not load client mappings.');
    }
  }, []);

  useEffect(() => {
    void load();
  }, [load]);

  const changed = () => {
    void load();
    onChanged(); // a client created while mapping must show in the tenant table
  };

  const undo = async (work: () => Promise<unknown>, done: string) => {
    try {
      await work();
      toast.success(done);
      changed();
    } catch (err) {
      toast.error(err instanceof Error && err.message ? err.message : 'Could not save that.');
    }
  };

  if (error) {
    return (
      <p role="alert" className="text-sm text-red-400">
        {error}
      </p>
    );
  }
  if (clients === null) return <p role="status" className="text-sm text-gray-400">Loading client mappings…</p>;

  const tabs = toolTabs(clients);
  const activeTab = tab !== null && tabs.some((t) => t.vendor === tab) ? tab : null;
  const groups = groupClients(filterClients(clients, activeTab, search), sortBy);

  const toggleSource = async (vendor: string, on: boolean) => {
    const label = vendorLabel(vendor);
    if (on && !window.confirm(`Add every ${label} client as a client tenant now, and add new ones automatically from here on? A client whose name matches one you already have is linked to it instead.`)) return;
    try {
      const next = on ? [...synced, vendor] : synced.filter((v) => v !== vendor);
      const result = await msspApi.setClientSources(next);
      toast.success(on ? `${label}: ${result.created} added, ${result.linked} linked to existing clients` : `${label} clients are no longer added automatically`);
      changed();
    } catch (err) {
      toast.error(err instanceof Error && err.message ? err.message : 'Could not save that.');
    }
  };

  const moveExistingAlerts = async () => {
    if (!window.confirm('Move the alerts already received from your tools under the client each one belongs to? Alerts, their cases and actions are moved, not copied or deleted. It is safe to run again.')) return;
    setMoving(true);
    try {
      const r = await msspApi.rerouteAlerts();
      const dup = r.left_duplicates > 0 ? ` ${r.left_duplicates} already existed under their client and were left alone.` : '';
      toast.success(r.moved === 0 ? `Nothing to move.${dup}` : `Moved ${r.moved} alert${r.moved === 1 ? '' : 's'} and ${r.cases_moved} case${r.cases_moved === 1 ? '' : 's'} to ${Object.keys(r.by_client).length} client${Object.keys(r.by_client).length === 1 ? '' : 's'}.${dup}`);
      changed();
    } catch (err) {
      toast.error(err instanceof Error && err.message ? err.message : 'Could not move the alerts.');
    } finally {
      setMoving(false);
    }
  };

  const hideClient = async (c: VendorClient, hidden: boolean) => {
    if (c.child_tenant_id === null) return;
    const name = c.child_tenant_name ?? c.vendor_client_name;
    await undo(() => msspApi.setClientHidden(c.child_tenant_id as string, hidden), hidden ? `Hid ${name} (from every tool)` : `Showing ${name}`);
  };

  const startOver = async (mode: 'remove' | 'archive') => {
    setProgress({ done: 0, total: 0 });
    try {
      await msspApi.setClientSources([]); // first, so nothing re-creates a client while they are being cleared
      const everyone = (await msspApi.tenants(true)).filter((t) => mode === 'remove' || !t.hidden);
      setProgress({ done: 0, total: everyone.length });
      const work = (id: string) => (mode === 'remove' ? msspApi.removeClient(id) : msspApi.archiveClient(id));
      const result = await removeClients(everyone, work, (done, total) => setProgress({ done, total }));
      const verb = mode === 'remove' ? 'Removed' : 'Archived';
      toast.success(`${verb} ${result.removed} client tenant${result.removed === 1 ? '' : 's'}${keptSummary(result.kept)}`, { duration: result.kept.length > 0 ? 15000 : 4000 });
      setConfirmReset(false);
      setTypedReset('');
      changed();
    } catch (err) {
      toast.error(err instanceof Error && err.message ? err.message : 'Could not clear the client tenants.');
    } finally {
      setProgress(null);
    }
  };

  const checkedRows = groups.unmapped.filter((c) => checked.has(c.id));
  const toggle = (id: string, on: boolean) =>
    setChecked((prev) => {
      const next = new Set(prev);
      if (on) next.add(id);
      else next.delete(id);
      return next;
    });
  // These tenants are one customer: point every other tenant in the group's tool clients at this one and hide the extras (nothing is deleted).
  const keepOne = async (group: DuplicateGroup, keep: { tenant_id: string; name: string }) => {
    const others = group.tenants.filter((t) => t.tenant_id !== keep.tenant_id);
    if (!window.confirm(`Keep "${keep.name}" and merge ${others.map((t) => `"${t.name}"`).join(', ')} into it? Their tool clients will map to "${keep.name}" and the extras will be hidden. Alerts and cases already in them stay where they are, and showing a hidden client again undoes this.`)) return;
    let moved = 0;
    const failed: string[] = [];
    for (const t of others) {
      try {
        moved += (await msspApi.mergeClient(t.tenant_id, keep.tenant_id)).remapped;
      } catch {
        failed.push(t.name);
      }
    }
    if (failed.length) toast.error(`Could not merge: ${failed.join(', ')}`);
    else toast.success(`Merged into ${keep.name}; ${moved} tool client${moved === 1 ? '' : 's'} re-pointed.`);
    await load();
    onChanged();
  };

  const notDuplicate = async (group: DuplicateGroup) => {
    try {
      await msspApi.dismissDuplicates(group.tenants.map((t) => t.tenant_id));
      toast.success('Got it. They will not be listed as duplicates again.');
    } catch {
      toast.error('Could not save that.');
    }
    await load();
  };

  const mergePair = async () => {
    const keep = tenants.find((t) => t.tenant_id === pairKeep);
    const merge = tenants.find((t) => t.tenant_id === pairMerge);
    if (!keep || !merge || keep.tenant_id === merge.tenant_id) return;
    if (!window.confirm(`Keep "${keep.name}" and merge "${merge.name}" into it? Its tool clients will map to "${keep.name}" and "${merge.name}" will be hidden. Alerts and cases already in it stay where they are, and showing a hidden client again undoes this.`)) return;
    try {
      const r = await msspApi.mergeClient(merge.tenant_id, keep.tenant_id);
      toast.success(`Merged into ${keep.name}; ${r.remapped} tool client${r.remapped === 1 ? '' : 's'} re-pointed.`);
      setPairKeep('');
      setPairMerge('');
    } catch {
      toast.error(`Could not merge ${merge.name}.`);
    }
    await load();
    onChanged();
  };

  const approveChecked = async () => {
    const todo = checkedRows.filter((c) => choices.current[c.id]);
    const skipped = checkedRows.length - todo.length;
    if (todo.length === 0) {
      toast.error('Choose a client for each checked row first.');
      return;
    }
    if (!window.confirm(`Map ${todo.length} checked client${todo.length === 1 ? '' : 's'} to the clients chosen in their dropdowns?`)) return;
    setApproving(true);
    let done = 0;
    const failed: string[] = [];
    for (const c of todo) {
      const choice = choices.current[c.id];
      try {
        await msspApi.mapClient(c.id, choice === NEW_CLIENT ? { newTenantName: c.vendor_client_name } : { childTenantId: choice });
        done += 1;
      } catch {
        failed.push(c.vendor_client_name);
      }
    }
    setApproving(false);
    setChecked(new Set());
    const extra = `${skipped ? `, ${skipped} skipped (no client chosen)` : ''}${failed.length ? `, ${failed.length} failed: ${failed.slice(0, 3).join(', ')}` : ''}`;
    (failed.length ? toast.error : toast.success)(`Mapped ${done} of ${checkedRows.length}${extra}`);
    changed();
  };

  const suggestFor = (vendor: string) => {
    const picks = suggestedChoices(groups.unmapped, vendor);
    const total = groups.unmapped.filter((c) => c.vendor === vendor).length;
    const found = Object.keys(picks).length;
    if (found === 0) {
      toast.error(`No close matches found for ${vendorLabel(vendor)}. Pick clients by hand, or import them as new.`);
      return;
    }
    const n = Date.now();
    setPrefills((prev) => ({ ...prev, ...Object.fromEntries(Object.entries(picks).map(([id, tenantId]) => [id, { tenantId, n }])) }));
    toast.success(`Suggested a client for ${found} of ${total} ${vendorLabel(vendor)} rows. Review each one, then click Map. Nothing is saved yet.`);
  };

  const importAll = async (vendor: string, count: number) => {
    const label = vendorLabel(vendor);
    if (!window.confirm(`Add ${count} ${label} client${count === 1 ? '' : 's'} as client tenants? A client whose name matches one you already have is linked to it instead.`)) return;
    try {
      const result = await msspApi.importClients(vendor);
      const skipped = result.skipped ?? [];
      const note = skipped.length ? `; ${skipped.length} left for you to map by hand because a hidden client already has that name (${skipped.slice(0, 3).join(', ')})` : '';
      toast.success(`${label}: ${result.created} added, ${result.linked} linked to existing clients${note}`, { duration: skipped.length ? 12000 : 4000 });
      changed();
    } catch (err) {
      toast.error(err instanceof Error && err.message ? err.message : 'Could not import those clients.');
    }
  };

  return (
    <section aria-labelledby="client-mapping-title" className="rounded-xl border border-gray-800/60 bg-gray-900/40 overflow-hidden">
      <div className="px-5 py-4 border-b border-gray-800/60">
        <h2 id="client-mapping-title" className="text-lg font-semibold text-white">
          Client mapping
        </h2>
        <p className="mt-1 text-sm text-gray-400">
          Say which of your clients each tool&apos;s customer is. Exact name matches are linked for you; everything else waits here.
        </p>
      </div>

      {duplicates.length > 0 ? (
        <div className="px-5 py-4 border-b border-gray-800/60" role="region" aria-label="Possible duplicates">
          <h3 className="text-xs font-medium uppercase tracking-wider text-amber-400">Possible duplicates ({duplicates.length})</h3>
          <p className="mt-1 text-xs text-gray-500">These client tenants have near-identical names. If they are one customer, pick the one to keep and the others are merged into it.</p>
          <ul className="mt-2 space-y-3">
            {duplicates.map((g) => (
              <li key={g.tenants.map((t) => t.tenant_id).join('-')} className="rounded-lg border border-gray-800/60 p-3">
                <div className="flex justify-end">
                  <button type="button" onClick={() => void notDuplicate(g)} className="rounded-md px-2 py-0.5 text-xs text-gray-400 hover:bg-gray-800 hover:text-gray-200">
                    Not a duplicate
                  </button>
                </div>
                {g.tenants.map((t) => (
                  <div key={t.tenant_id} className="flex flex-wrap items-baseline gap-x-3 py-0.5">
                    <span className="font-medium text-white">{t.name}</span>
                    <span className="text-xs text-gray-400">{t.mapped_from.length > 0 ? t.mapped_from.join(' · ') : 'nothing mapped to it'}</span>
                    <button type="button" onClick={() => void keepOne(g, t)} className="ml-auto rounded-md border border-gray-700 px-2 py-0.5 text-xs text-gray-200 hover:bg-gray-800">
                      Keep this one
                    </button>
                  </div>
                ))}
              </li>
            ))}
          </ul>
        </div>
      ) : null}

      {tenants.length > 1 ? (
        <div className="px-5 py-3 border-b border-gray-800/60" role="region" aria-label="Merge two clients">
          <h3 className="text-xs font-medium uppercase tracking-wider text-gray-400">Merge two clients</h3>
          <div className="mt-2 flex flex-wrap items-center gap-2 text-sm text-gray-300">
            <label className="flex items-center gap-2">
              Keep
              <select aria-label="Client to keep" value={pairKeep} onChange={(e) => setPairKeep(e.target.value)} className="rounded-lg border border-gray-700 bg-gray-900 px-2 py-1 text-sm text-gray-200">
                <option value="">Choose…</option>
                {tenants.map((t) => (
                  <option key={t.tenant_id} value={t.tenant_id}>
                    {t.name}
                  </option>
                ))}
              </select>
            </label>
            <label className="flex items-center gap-2">
              and merge
              <select aria-label="Client to merge into it" value={pairMerge} onChange={(e) => setPairMerge(e.target.value)} className="rounded-lg border border-gray-700 bg-gray-900 px-2 py-1 text-sm text-gray-200">
                <option value="">Choose…</option>
                {tenants.filter((t) => t.tenant_id !== pairKeep).map((t) => (
                  <option key={t.tenant_id} value={t.tenant_id}>
                    {t.name}
                  </option>
                ))}
              </select>
            </label>
            <button type="button" disabled={!pairKeep || !pairMerge || pairKeep === pairMerge} onClick={() => void mergePair()} className="rounded-lg border border-gray-700 px-3 py-1 text-sm text-gray-200 hover:bg-gray-800 disabled:opacity-40">
              Merge
            </button>
          </div>
        </div>
      ) : null}

      {confirmReset ? (
        <div role="alertdialog" aria-label="Remove all client tenants" className="px-5 py-4 border-b border-red-900/60 bg-red-950/20">
          <p className="text-sm text-red-200">
            This removes EVERY client tenant and its untouched alerts, puts all tool clients back in Unmapped, and turns off automatic adding. Tenants with cases or connectors are kept.
          </p>
          <div className="mt-3 flex flex-wrap items-center gap-3">
            <label className="flex items-center gap-2 text-sm text-gray-200">
              Type REMOVE to confirm
              <input value={typedReset} onChange={(e) => setTypedReset(e.target.value)} className="rounded-lg border border-gray-700 bg-gray-900 px-2 py-1 text-sm text-gray-200" />
            </label>
            <button
              type="button"
              disabled={typedReset.trim() !== 'REMOVE' || progress !== null}
              onClick={() => void startOver('remove')}
              className="rounded-lg bg-red-700 px-3 py-1.5 text-sm text-white hover:bg-red-600 disabled:opacity-40 transition-colors"
            >
              {progress ? (progress.total > 0 ? `Removing ${progress.done} of ${progress.total}…` : 'Starting…') : 'Remove everything'}
            </button>
            <button
              type="button"
              disabled={typedReset.trim() !== 'REMOVE' || progress !== null}
              onClick={() => void startOver('archive')}
              title="Hides every client and renames it, deleting nothing. Use this for clients that cannot be removed."
              className="rounded-lg border border-gray-600 px-3 py-1.5 text-sm text-gray-200 hover:bg-gray-800 disabled:opacity-40 transition-colors"
            >
              Archive instead (deletes nothing)
            </button>
            <button type="button" onClick={() => { setConfirmReset(false); setTypedReset(''); }} className="rounded-lg px-3 py-1.5 text-sm text-gray-400 hover:text-gray-200 transition-colors">
              Cancel
            </button>
          </div>
        </div>
      ) : null}

      {tabs.length > 1 ? (
        <div role="tablist" aria-label="Tool" className="flex flex-wrap gap-1 px-5 pt-3 border-b border-gray-800/60">
          {[{ vendor: null as string | null, label: 'All tools', unmapped: clients.filter((c) => !c.ignored && c.child_tenant_id === null).length }, ...tabs.map((t) => ({ vendor: t.vendor as string | null, label: vendorLabel(t.vendor), unmapped: t.unmapped }))].map((t) => (
            <button
              key={t.vendor ?? 'all'}
              type="button"
              role="tab"
              aria-selected={activeTab === t.vendor}
              onClick={() => setTab(t.vendor)}
              className={`rounded-t-lg px-3 py-2 text-sm transition-colors ${activeTab === t.vendor ? 'bg-white/10 text-white' : 'text-gray-400 hover:text-gray-200'}`}
            >
              {t.label}
              {t.unmapped > 0 ? <span className="ml-2 rounded-full bg-amber-500/20 px-1.5 text-xs text-amber-300">{t.unmapped}</span> : null}
            </button>
          ))}
        </div>
      ) : null}

      {clients.length > 0 ? (
        <div className="flex flex-wrap items-center gap-4 px-5 py-3 border-b border-gray-800/60">
          <label className="flex items-center gap-2 text-sm text-gray-300">
            Sort by
            <select
              value={sortBy}
              onChange={(e) => setSortBy(e.target.value as SortBy)}
              className="rounded-lg border border-gray-700 bg-gray-900 px-2 py-1 text-sm text-gray-200"
            >
              <option value="name">Client name</option>
              <option value="tool">Tool</option>
              <option value="tenant">Mapped to</option>
            </select>
          </label>
          <label className="flex items-center gap-2 text-sm text-gray-300">
            Search
            <input
              type="search"
              value={search}
              onChange={(e) => setSearch(e.target.value)}
              placeholder="Client name"
              className="rounded-lg border border-gray-700 bg-gray-900 px-2 py-1 text-sm text-gray-200"
            />
          </label>
          <button type="button" onClick={() => setConfirmReset((v) => !v)} className="ml-auto rounded-lg border border-red-900/60 px-3 py-1 text-sm text-red-300 hover:bg-red-950/40 transition-colors">
            Remove all client tenants
          </button>
          {groups.hidden.length > 0 ? (
            <label className="flex items-center gap-2 text-sm text-gray-300">
              <input type="checkbox" checked={showHidden} onChange={(e) => setShowHidden(e.target.checked)} />
              Show hidden ({groups.hidden.length})
            </label>
          ) : null}
        </div>
      ) : null}

      {clients.length > 0 ? (
        <fieldset className="px-5 py-4 border-b border-gray-800/60">
          <legend className="text-xs font-medium uppercase tracking-wider text-gray-500">Add clients automatically from</legend>
          <div className="mt-2 flex flex-wrap gap-4">
            {sourceChoices(clients, synced).map(({ vendor, on }) => (
              <label key={vendor} className="flex items-center gap-2 text-sm text-gray-200">
                <input type="checkbox" checked={on} onChange={(e) => void toggleSource(vendor, e.target.checked)} />
                {vendorLabel(vendor)}
              </label>
            ))}
          </div>
          <p className="mt-2 text-xs text-gray-500">Pick the tool that is your master client list. Its clients become client tenants; clients from the other tools are mapped to them below.</p>
          <div className="mt-3 flex flex-wrap items-center gap-3">
            <button
              type="button"
              disabled={moving}
              onClick={() => void moveExistingAlerts()}
              className="rounded-lg border border-gray-700 px-3 py-1.5 text-sm text-gray-200 hover:bg-gray-800 disabled:opacity-50 transition-colors"
            >
              {moving ? 'Moving…' : 'Move existing alerts to their clients'}
            </button>
            <span className="text-xs text-gray-500">New alerts go to the right client automatically; this files the ones that arrived before the mapping.</span>
          </div>
        </fieldset>
      ) : null}

      {clients.length === 0 ? (
        <p className="px-5 py-6 text-sm text-gray-400">
          No clients from your tools yet. They appear here after CORE syncs them (every few minutes) from the tools it is connected to, such as Petra.
        </p>
      ) : (
        <>
          <h3 className="px-5 pt-4 text-xs font-medium uppercase tracking-wider text-gray-500">Unmapped ({groups.unmapped.length})</h3>
          {groups.unmapped.length > 0 ? (
            <div className="flex flex-wrap gap-2 px-5 pt-3">
              {unmappedByVendor(groups.unmapped).map(({ vendor, count }) => (
                <span key={vendor} className="inline-flex gap-2">
                  <button
                    type="button"
                    onClick={() => suggestFor(vendor)}
                    className="rounded-lg border border-blue-500/40 px-3 py-1.5 text-sm text-blue-300 hover:bg-blue-500/10 transition-colors"
                  >
                    Suggest mappings for {vendorLabel(vendor)}
                  </button>
                  <button
                    type="button"
                    onClick={() => void importAll(vendor, count)}
                    className="rounded-lg border border-gray-700 px-3 py-1.5 text-sm text-gray-200 hover:bg-gray-800 transition-colors"
                  >
                    Import all {count} from {vendorLabel(vendor)}
                  </button>
                </span>
              ))}
            </div>
          ) : null}
          {groups.unmapped.length > 0 ? (
            <div className="flex flex-wrap items-center gap-3 px-5 pt-3">
              <label className="flex items-center gap-2 text-sm text-gray-300">
                <input
                  type="checkbox"
                  aria-label="Select all shown"
                  checked={checkedRows.length === groups.unmapped.length}
                  onChange={(e) => setChecked(e.target.checked ? new Set(groups.unmapped.map((c) => c.id)) : new Set())}
                  className="h-4 w-4 rounded border-gray-600"
                />
                Select all shown
              </label>
              <button
                type="button"
                disabled={approving || checkedRows.length === 0}
                onClick={() => void approveChecked()}
                className="rounded-lg bg-blue-600 px-3 py-1.5 text-sm text-white hover:bg-blue-500 disabled:opacity-40 disabled:hover:bg-blue-600 transition-colors"
              >
                Approve all checked ({checkedRows.length})
              </button>
            </div>
          ) : null}
          {groups.unmapped.length === 0 ? (
            <p className="px-5 py-3 text-sm text-gray-400">Everything is mapped.</p>
          ) : (
            <ul>
              {groups.unmapped.map((c) => (
                <UnmappedRow key={c.id} client={c} tenants={tenants} onChanged={changed} prefill={prefills[c.id]}
                  checked={checked.has(c.id)}
                  onCheck={(on) => toggle(c.id, on)}
                  onChoice={(v) => {
                    choices.current[c.id] = v;
                  }}
                />
              ))}
            </ul>
          )}

          {groups.mapped.length > 0 ? (
            <>
              <h3 className="px-5 pt-4 text-xs font-medium uppercase tracking-wider text-gray-500">Mapped ({groups.mapped.length})</h3>
              <ul>
                {groups.mapped.map((c) => (
                  <SimpleRow
                    key={c.id}
                    client={c}
                    label={`→ ${c.child_tenant_name ?? 'a client'}`}
                    action="Unmap"
                    onClick={() => void undo(() => msspApi.unmapClient(c.id), `Unmapped ${c.vendor_client_name}`)}
                    extraAction="Hide"
                    onExtra={() => void hideClient(c, true)}
                  />
                ))}
              </ul>
            </>
          ) : null}

          {showHidden && groups.hidden.length > 0 ? (
            <>
              <h3 className="px-5 pt-4 text-xs font-medium uppercase tracking-wider text-gray-500">Hidden ({groups.hidden.length})</h3>
              <ul>
                {groups.hidden.map((c) => (
                  <SimpleRow
                    key={c.id}
                    client={c}
                    label={`→ ${c.child_tenant_name ?? 'a client'} (hidden)`}
                    action="Show"
                    onClick={() => void hideClient(c, false)}
                  />
                ))}
              </ul>
            </>
          ) : null}

          {groups.ignored.length > 0 ? (
            <>
              <h3 className="px-5 pt-4 text-xs font-medium uppercase tracking-wider text-gray-500">Ignored ({groups.ignored.length})</h3>
              <ul>
                {groups.ignored.map((c) => (
                  <SimpleRow
                    key={c.id}
                    client={c}
                    label="Not one of your clients"
                    action="Restore"
                    onClick={() => void undo(() => msspApi.ignoreClient(c.id, false), `Restored ${c.vendor_client_name}`)}
                  />
                ))}
              </ul>
            </>
          ) : null}
        </>
      )}
    </section>
  );
}
