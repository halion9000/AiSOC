'use client';

import { useCallback, useEffect, useState } from 'react';
import toast from 'react-hot-toast';
import { msspApi, type ManagedTenantRow, type VendorClient } from '@/lib/api';

/**
 * Each customer has a different name in every tool ("Acme Dental, LLC" in Petra, "ACME" in Halo). CORE sends each tool's client list; here a person says which of
 * their clients each one is. Unmapped clients wait here (they are never dropped), a client you do not manage can be ignored, and a mapping can be undone.
 */

export interface ClientGroups {
  unmapped: VendorClient[];
  mapped: VendorClient[];
  ignored: VendorClient[];
}

export function groupClients(clients: VendorClient[]): ClientGroups {
  return {
    unmapped: clients.filter((c) => !c.ignored && c.child_tenant_id === null),
    mapped: clients.filter((c) => !c.ignored && c.child_tenant_id !== null),
    ignored: clients.filter((c) => c.ignored),
  };
}

/** How many unmapped clients each tool has, most first: what an "import all" button offers. */
export function unmappedByVendor(unmapped: VendorClient[]): { vendor: string; count: number }[] {
  const counts = new Map<string, number>();
  for (const c of unmapped) counts.set(c.vendor, (counts.get(c.vendor) ?? 0) + 1);
  return [...counts.entries()].map(([vendor, count]) => ({ vendor, count })).sort((a, b) => b.count - a.count || a.vendor.localeCompare(b.vendor));
}

/** "petra" -> "Petra" */
export function vendorLabel(vendor: string): string {
  return vendor.charAt(0).toUpperCase() + vendor.slice(1);
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

function SimpleRow({ client, label, action, onClick }: { client: VendorClient; label: string; action: string; onClick: () => void }) {
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
    </li>
  );
}

export default function ClientMapping({ tenants, onChanged }: { tenants: ManagedTenantRow[]; onChanged: () => void }) {
  const [clients, setClients] = useState<VendorClient[] | null>(null);
  const [error, setError] = useState<string | null>(null);

  const load = useCallback(async () => {
    try {
      const result = await msspApi.clients();
      setClients(result.clients);
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

  const groups = groupClients(clients);

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
