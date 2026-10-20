"use client";

/**
 * One client's posture on a page you can print for a review: devices, second-factor coverage, open alerts and cases side by side. Read-only; the same numbers as the Devices, Multi-factor status,
 * Alerts and Cases pages. Backed by GET /api/v1/posture/{client_id}.
 */
import { useEffect, useState } from "react";

import { authFetch } from "@/lib/auth-session";

export interface Posture {
  client_id: string;
  client_name: string | null;
  generated_at: string;
  devices: { devices: number; needs_attention: number; stale_agents: number; not_in_huntress: number; offline: number };
  identity: { people: number; with_mfa: number; not_required: number; without_mfa: number; admins_without_mfa: number; refreshed_at: string | null } | null;
  alerts: { open: number; critical: number; high: number; without_ticket: number };
  open_cases: number;
}

interface Client {
  id: string;
  name: string;
}

/** "75%" of people covered, or a dash when there are none. */
export function coverage(i: Pick<NonNullable<Posture["identity"]>, "people" | "with_mfa">): string {
  return i.people === 0 ? "—" : `${Math.round((100 * i.with_mfa) / i.people)}%`;
}

function Stat({ label, value, bad }: { label: string; value: string | number; bad?: boolean }) {
  return (
    <div className="rounded border border-slate-700 p-3">
      <div className={`text-2xl font-semibold ${bad ? "text-red-300" : "text-slate-100"}`}>{value}</div>
      <div className="text-xs uppercase text-slate-500">{label}</div>
    </div>
  );
}

export function ClientPosture() {
  const [clients, setClients] = useState<Client[] | null>(null);
  const [clientId, setClientId] = useState("");
  const [posture, setPosture] = useState<Posture | null>(null);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    let live = true;
    authFetch("/api/v1/mssp/children")
      .then(async (res) => {
        if (!res.ok) throw new Error(`The API answered ${res.status}`);
        const body = (await res.json()) as Client[];
        if (live) setClients([...body].sort((a, b) => a.name.localeCompare(b.name)));
      })
      .catch((e: unknown) => {
        if (live) setError(e instanceof Error ? e.message : "Could not load the clients");
      });
    return () => {
      live = false;
    };
  }, []);

  useEffect(() => {
    if (!clientId) return;
    let live = true;
    authFetch(`/api/v1/posture/${encodeURIComponent(clientId)}`)
      .then(async (res) => {
        if (!res.ok) throw new Error(`The API answered ${res.status}`);
        const body = (await res.json()) as Posture;
        if (live) {
          setPosture(body);
          setError(null);
        }
      })
      .catch((e: unknown) => {
        if (live) setError(e instanceof Error ? e.message : "Could not load this client");
      });
    return () => {
      live = false;
    };
  }, [clientId]);

  const shown = posture && posture.client_id === clientId ? posture : null;

  return (
    <div className="space-y-4 p-6">
      <div className="flex items-end justify-between gap-4 print:hidden">
        <div>
          <h1 className="text-xl font-semibold text-slate-100">Client posture</h1>
          <p className="mt-1 text-sm text-slate-400">One client&apos;s devices, second-factor coverage, open alerts and cases on a page you can print for a review.</p>
        </div>
        {shown && (
          <button type="button" onClick={() => window.print()} className="rounded border border-slate-600 px-3 py-1 text-sm text-slate-200">
            Print
          </button>
        )}
      </div>
      <label className="flex items-center gap-2 text-sm text-slate-300 print:hidden">
        Client
        <select value={clientId} onChange={(e) => setClientId(e.target.value)} className="rounded border border-slate-700 bg-slate-900 px-2 py-1" aria-label="Client">
          <option value="">Pick a client</option>
          {(clients ?? []).map((c) => (
            <option key={c.id} value={c.id}>
              {c.name}
            </option>
          ))}
        </select>
      </label>
      {error && (
        <p role="alert" className="rounded border border-red-500/40 bg-red-500/10 p-3 text-sm text-red-300">
          {error}
        </p>
      )}
      {shown && (
        <div className="space-y-5" data-testid="posture">
          <h2 className="text-lg font-semibold text-slate-100">
            {shown.client_name ?? "This organization"} <span className="text-sm font-normal text-slate-500">as of {new Date(shown.generated_at).toLocaleString()}</span>
          </h2>
          <section>
            <h3 className="mb-2 text-sm uppercase text-slate-500">Devices</h3>
            <div className="grid grid-cols-2 gap-3 md:grid-cols-5">
              <Stat label="Devices" value={shown.devices.devices} />
              <Stat label="Need attention" value={shown.devices.needs_attention} bad={shown.devices.needs_attention > 0} />
              <Stat label="Stale agents" value={shown.devices.stale_agents} bad={shown.devices.stale_agents > 0} />
              <Stat label="Not in Huntress" value={shown.devices.not_in_huntress} bad={shown.devices.not_in_huntress > 0} />
              <Stat label="Offline" value={shown.devices.offline} />
            </div>
          </section>
          <section>
            <h3 className="mb-2 text-sm uppercase text-slate-500">Second factor</h3>
            {shown.identity ? (
              <div className="grid grid-cols-2 gap-3 md:grid-cols-5">
                <Stat label="People" value={shown.identity.people} />
                <Stat label="Covered" value={coverage(shown.identity)} />
                <Stat label="Registered, not required" value={shown.identity.not_required} bad={shown.identity.not_required > 0} />
                <Stat label="No second factor" value={shown.identity.without_mfa} bad={shown.identity.without_mfa > 0} />
                <Stat label="Administrators without" value={shown.identity.admins_without_mfa} bad={shown.identity.admins_without_mfa > 0} />
              </div>
            ) : (
              <p className="text-sm text-slate-400" data-testid="no-identity">
                No second-factor data yet. It arrives once CORE is connected to CIPP and this client&apos;s CIPP tenant is mapped.
              </p>
            )}
          </section>
          <section>
            <h3 className="mb-2 text-sm uppercase text-slate-500">Alerts and cases</h3>
            <div className="grid grid-cols-2 gap-3 md:grid-cols-5">
              <Stat label="Open alerts" value={shown.alerts.open} />
              <Stat label="Critical" value={shown.alerts.critical} bad={shown.alerts.critical > 0} />
              <Stat label="High" value={shown.alerts.high} bad={shown.alerts.high > 0} />
              <Stat label="Open, no ticket" value={shown.alerts.without_ticket} bad={shown.alerts.without_ticket > 0} />
              <Stat label="Open cases" value={shown.open_cases} />
            </div>
          </section>
        </div>
      )}
    </div>
  );
}
