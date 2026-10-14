'use client';

import { useCallback, useEffect, useState } from 'react';
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

const VENDOR_NAMES: Record<string, string> = { halopsa: 'HaloPSA', ninjaone: 'NinjaOne', petra: 'Petra', huntress: 'Huntress', blumira: 'Blumira' };

/** "halopsa" -> "HaloPSA", "petra" -> "Petra"; a tool it doesn't know is capitalized. */
export function vendorLabel(vendor: string): string {
  return VENDOR_NAMES[vendor] ?? vendor.charAt(0).toUpperCase() + vendor.slice(1);
}

const NEW_CLIENT = '__new__';

function UnmappedRow({ client, tenants, onChanged }: { client: VendorClient; tenants: ManagedTenantRow[]; onChanged: () => void }) {
  const best = client.suggestions[0]?.tenant_id ?? '';
  const [choice, setChoice] = useState<string>(best);
  const [busy, setBusy] = useState(false);

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
  const [duplicates, setDuplicates] = useState<DuplicateGroup[]>([]);
  const [error, setError] = useState<string | null>(null);
  const [sortBy, setSortBy] = useState<SortBy>('name');
  const [tab, setTab] = useState<string | null>(null);
  const [search, setSearch] = useState('');
  const [confirmReset, setConfirmReset] = useState(false);
  const [typedReset, setTypedReset] = useState('');
  const [progress, setProgress] = useState<{ done: number; total: number } | null>(null);
  const [showHidden, setShowHidden] = useState(false);

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

  const hideClient = async (c: VendorClient, hidden: boolean) => {
    if (c.child_tenant_id === null) return;
    const name = c.child_tenant_name ?? c.vendor_client_name;
    await undo(() => msspApi.setClientHidden(c.child_tenant_id as string, hidden), hidden ? `Hid ${name} (from every tool)` : `Showing ${name}`);
  };

  const startOver = async () => {
    setProgress({ done: 0, total: 0 });
    try {
      await msspApi.setClientSources([]); // first, so nothing re-creates a client while they are being removed
      const everyone = await msspApi.tenants(true);
      setProgress({ done: 0, total: everyone.length });
      const result = await removeClients(everyone, (id) => msspApi.removeClient(id), (done, total) => setProgress({ done, total }));
      toast.success(`Removed ${result.removed} client tenant${result.removed === 1 ? '' : 's'}${keptSummary(result.kept)}`, { duration: result.kept.length > 0 ? 15000 : 4000 });
      setConfirmReset(false);
      setTypedReset('');
      changed();
    } catch (err) {
      toast.error(err instanceof Error && err.message ? err.message : 'Could not remove the client tenants.');
    } finally {
      setProgress(null);
    }
  };

  const importAll = async (vendor: string, count: number) => {
    const label = vendorLabel(vendor);
    if (!window.confirm(`Add ${count} ${label} client${count === 1 ? '' : 's'} as client tenants? A client whose name matches one you already have is linked to it instead.`)) return;
    try {
      const result = await msspApi.importClients(vendor);
      toast.success(`${label}: ${result.created} added, ${result.linked} linked to existing clients`);
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
          <p className="mt-1 text-xs text-gray-500">These client tenants have near-identical names. If they are one customer, map each tool&apos;s client to a single tenant and hide the extra.</p>
          <ul className="mt-2 space-y-3">
            {duplicates.map((g) => (
              <li key={g.tenants.map((t) => t.tenant_id).join('-')} className="rounded-lg border border-gray-800/60 p-3">
                {g.tenants.map((t) => (
                  <div key={t.tenant_id} className="flex flex-wrap items-baseline gap-x-3 py-0.5">
                    <span className="font-medium text-white">{t.name}</span>
                    <span className="text-xs text-gray-400">{t.mapped_from.length > 0 ? t.mapped_from.join(' · ') : 'nothing mapped to it'}</span>
                  </div>
                ))}
              </li>
            ))}
          </ul>
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
              onClick={() => void startOver()}
              className="rounded-lg bg-red-700 px-3 py-1.5 text-sm text-white hover:bg-red-600 disabled:opacity-40 transition-colors"
            >
              {progress ? (progress.total > 0 ? `Removing ${progress.done} of ${progress.total}…` : 'Starting…') : 'Remove everything'}
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
                <button
                  key={vendor}
                  type="button"
                  onClick={() => void importAll(vendor, count)}
                  className="rounded-lg border border-gray-700 px-3 py-1.5 text-sm text-gray-200 hover:bg-gray-800 transition-colors"
                >
                  Import all {count} from {vendorLabel(vendor)}
                </button>
              ))}
            </div>
          ) : null}
          {groups.unmapped.length === 0 ? (
            <p className="px-5 py-3 text-sm text-gray-400">Everything is mapped.</p>
          ) : (
            <ul>
              {groups.unmapped.map((c) => (
                <UnmappedRow key={c.id} client={c} tenants={tenants} onChanged={changed} />
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
