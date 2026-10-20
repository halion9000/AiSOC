"use client";

/**
 * Multi-factor status: per client, how many people have a second factor and how many do not (read through CIPP, refreshed daily by CORE).
 * Backed by GET /api/v1/identity/mfa-summary and /api/v1/identity/mfa-users. A client row opens to name the people without one (administrators first).
 */
import { useCallback, useEffect, useState } from "react";

import { authFetch } from "@/lib/auth-session";

export interface MfaClient {
  client_id: string;
  client_name: string | null;
  people: number;
  with_mfa: number;
  not_required: number;
  without_mfa: number;
  admins_without_mfa: number;
  refreshed_at: string | null;
}

export interface MfaPerson {
  upn: string;
  display_name: string | null;
  admin: boolean;
  registered: boolean;
  required: boolean;
  methods: string | null;
}

type Which = "without" | "not_required";
type Open = { id: string; which: Which } | null;

/** "86%" of people covered, or a dash when there are none. */
export function coveragePercent(c: Pick<MfaClient, "people" | "with_mfa">): string {
  return c.people === 0 ? "—" : `${Math.round((100 * c.with_mfa) / c.people)}%`;
}

async function getJson<T>(path: string): Promise<T> {
  const res = await authFetch(path);
  if (!res.ok) throw new Error(`The API answered ${res.status}`);
  return (await res.json()) as T;
}

function People({ clientId, which }: { clientId: string; which: Which }) {
  const [people, setPeople] = useState<MfaPerson[] | null>(null);
  const [error, setError] = useState<string | null>(null);
  useEffect(() => {
    let live = true;
    getJson<MfaPerson[]>(`/api/v1/identity/mfa-users?client_id=${encodeURIComponent(clientId)}&which=${which}`)
      .then((p) => {
        if (live) setPeople(p);
      })
      .catch((e: unknown) => {
        if (live) setError(e instanceof Error ? e.message : "Could not load the people");
      });
    return () => {
      live = false;
    };
  }, [clientId, which]);
  if (error) return <p className="text-sm text-red-300">{error}</p>;
  if (people === null) return <p className="text-sm text-slate-500">Loading...</p>;
  if (people.length === 0) return <p className="text-sm text-slate-500">Nobody.</p>;
  return (
    <ul className="space-y-0.5 text-sm" data-testid={`people-${which}`}>
      {people.map((p) => (
        <li key={p.upn} className="flex items-baseline gap-2">
          <span className="font-mono text-slate-200">{p.upn}</span>
          {p.display_name ? <span className="text-slate-500">{p.display_name}</span> : null}
          {p.admin ? <span className="rounded bg-red-500/20 px-1.5 py-0.5 text-[11px] text-red-300">administrator</span> : null}
        </li>
      ))}
    </ul>
  );
}

function ClientRow({ c, open, setOpen }: { c: MfaClient; open: Open; setOpen: (v: Open) => void }) {
  const shown = open?.id === c.client_id ? open.which : null;
  const toggle = (which: Which) => setOpen(shown === which ? null : { id: c.client_id, which });
  return (
    <>
      <tr className="border-b border-slate-800" data-testid="client-row">
        <td className="py-2 text-slate-200">{c.client_name ?? "This organization"}</td>
        <td className="text-slate-400">{c.people}</td>
        <td className="text-slate-300">{coveragePercent(c)}</td>
        <td>
          {c.not_required > 0 ? (
            <button type="button" onClick={() => toggle("not_required")} className="text-amber-300 hover:underline">
              {c.not_required}
            </button>
          ) : (
            <span className="text-slate-500">0</span>
          )}
        </td>
        <td>
          {c.without_mfa > 0 ? (
            <button type="button" onClick={() => toggle("without")} className="text-red-300 hover:underline">
              {c.without_mfa}
            </button>
          ) : (
            <span className="text-slate-500">0</span>
          )}
        </td>
        <td className={c.admins_without_mfa > 0 ? "text-red-300" : "text-slate-500"}>{c.admins_without_mfa}</td>
      </tr>
      {shown && (
        <tr className="border-b border-slate-800 bg-slate-900/40">
          <td colSpan={6} className="px-3 py-2">
            <p className="mb-1 text-xs uppercase text-slate-500">{shown === "without" ? "No second factor" : "Registered a second factor, but nothing requires it"}</p>
            <People clientId={c.client_id} which={shown} />
          </td>
        </tr>
      )}
    </>
  );
}

export function MfaStatus() {
  const [clients, setClients] = useState<MfaClient[] | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [open, setOpen] = useState<Open>(null);
  const [adminsOnly, setAdminsOnly] = useState(false);

  const load = useCallback(async () => {
    try {
      setClients(await getJson<MfaClient[]>("/api/v1/identity/mfa-summary"));
      setError(null);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Could not load multi-factor status");
    }
  }, []);

  useEffect(() => {
    void load();
  }, [load]);

  const totals = (clients ?? []).reduce((t, c) => ({ people: t.people + c.people, without: t.without + c.without_mfa, admins: t.admins + c.admins_without_mfa }), { people: 0, without: 0, admins: 0 });

  return (
    <div className="space-y-4 p-6">
      <div>
        <h1 className="text-xl font-semibold text-slate-100">Multi-factor status</h1>
        <p className="mt-1 text-sm text-slate-400">
          Who has a second sign-in factor, per client, read through CIPP once a day. Counts cover enabled, licensed member accounts (shared mailboxes, guests and disabled accounts are left out).
        </p>
      </div>
      {error && (
        <p role="alert" className="rounded border border-red-500/40 bg-red-500/10 p-3 text-sm text-red-300">
          {error}
        </p>
      )}
      {clients === null && !error && <p className="text-sm text-slate-500">Loading...</p>}
      {clients !== null && clients.length === 0 && (
        <p data-testid="none" className="text-sm text-slate-400">
          Nothing yet. Once CORE is connected to CIPP and the CIPP tenants are mapped to clients, each client&apos;s multi-factor status appears here after the next daily read.
        </p>
      )}
      {clients !== null && clients.length > 0 && (
        <>
          <p data-testid="totals" className="text-sm text-slate-300">
            {totals.people.toLocaleString()} people across {clients.length} clients: {totals.without.toLocaleString()} with no second factor, {totals.admins.toLocaleString()} of them administrators.
          </p>
          <label className="flex items-center gap-2 text-sm text-slate-300">
            <input type="checkbox" checked={adminsOnly} onChange={(e) => setAdminsOnly(e.target.checked)} data-testid="admins-only" />
            Only clients with administrators that have no second factor
          </label>
          <table className="w-full text-left text-sm">
            <thead>
              <tr className="border-b border-slate-700 text-slate-500">
                <th className="py-2">Client</th>
                <th>People</th>
                <th>Covered</th>
                <th>Registered, not required</th>
                <th>No second factor</th>
                <th>Administrators without</th>
              </tr>
            </thead>
            <tbody>
              {clients.filter((c) => !adminsOnly || c.admins_without_mfa > 0).map((c) => (
                <ClientRow key={c.client_id} c={c} open={open} setOpen={setOpen} />
              ))}
            </tbody>
          </table>
        </>
      )}
    </div>
  );
}
