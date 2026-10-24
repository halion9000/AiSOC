"use client";

/**
 * One client's posture on a page you can print for a review: devices, Multi-Factor coverage, open alerts and cases side by side. Read-only; the same numbers as the Devices, Multi-factor status,
 * Alerts and Cases pages. Backed by GET /api/v1/client-posture/{client_id}.
 */
import { useEffect, useState } from "react";
import Link from "next/link";

import { authFetch } from "@/lib/auth-session";
import VendorBadge from "@/components/mssp/VendorBadge";
import { vendorLabel } from "@/components/mssp/ClientMapping";
import { vendorClientUrl } from "@/lib/vendor-links";
import { DomainChecks } from "./DomainChecks";

export interface Posture {
  client_id: string;
  client_name: string | null;
  generated_at: string;
  devices: { devices: number; needs_attention: number; stale_agents: number; not_in_huntress: number; offline: number };
  identity: { people: number; with_mfa: number; not_required: number; without_mfa: number; admins_without_mfa: number; refreshed_at: string | null } | null;
  alerts: { open: number; critical: number; high: number; without_ticket: number };
  open_cases: number;
  /** The tools this client is mapped to. Absent from an older API. */
  tools?: { vendor: string; vendor_client_id: string; vendor_client_name?: string | null; product?: string | null }[];
}

interface Client {
  id: string;
  name: string;
}

/** "75%" of people covered, or a dash when there are none. */
export function coverage(i: Pick<NonNullable<Posture["identity"]>, "people" | "with_mfa">): string {
  return i.people === 0 ? "—" : `${Math.round((100 * i.with_mfa) / i.people)}%`;
}

/** Where each number on the page leads: the list behind it, already filtered to this client (Devices, Multi-Factor, Alerts and Cases read these parameters). */
export function postureLinks(clientId: string): Record<string, string> {
  const id = encodeURIComponent(clientId);
  return {
    devices: `/devices?client=${id}`,
    needsAttention: `/devices?client=${id}&attention=1`,
    stale: `/devices?client=${id}&stale=1`,
    notInHuntress: `/devices?client=${id}&missing=huntress`,
    offline: `/devices?client=${id}&offline=1`,
    people: `/settings/mfa?client=${id}`,
    notRequired: `/settings/mfa?client=${id}&which=not_required`,
    without: `/settings/mfa?client=${id}&which=without`,
    adminsWithout: `/settings/mfa?client=${id}&which=without&admins=1`,
    alerts: `/alerts?client=${id}`,
    critical: `/alerts?client=${id}&severity=critical`,
    high: `/alerts?client=${id}&severity=high`,
    noTicket: `/alerts?client=${id}&ticket=none`,
    cases: `/cases?scope=all&client=${id}`,
  };
}

/** The tools this client is linked to, as their logos. A logo opens the client's own page in that tool when its address is known. */
export function LinkedTools({ tools }: { tools: NonNullable<Posture["tools"]> }) {
  if (tools.length === 0) return null;
  return (
    <section aria-label="Tools this client is linked to" className="print:hidden">
      <h3 className="mb-2 text-sm uppercase text-slate-500">Linked tools</h3>
      <ul className="flex flex-wrap gap-2">
        {tools.map((t) => {
          const url = vendorClientUrl(t.vendor, t.vendor_client_id, t.product);
          const label = vendorLabel(t.vendor);
          const detail = t.vendor_client_name && t.vendor_client_name !== label ? `${label}: ${t.vendor_client_name}` : label;
          const chip = (
            <>
              <VendorBadge vendor={t.vendor} />
              <span>{label}</span>
            </>
          );
          return (
            <li key={`${t.vendor}:${t.vendor_client_id}`}>
              {url ? (
                <a href={url} target="_blank" rel="noopener noreferrer" title={`Open ${detail} in ${label}`} className="flex items-center gap-2 rounded border border-slate-700 px-2 py-1 text-sm text-slate-200 hover:border-sky-500/60 hover:bg-slate-800/60">
                  {chip}
                </a>
              ) : (
                <span title={`${detail} (no link to this tool's page yet)`} className="flex items-center gap-2 rounded border border-slate-800 px-2 py-1 text-sm text-slate-400">
                  {chip}
                </span>
              )}
            </li>
          );
        })}
      </ul>
    </section>
  );
}

function Stat({ label, value, bad, href }: { label: string; value: string | number; bad?: boolean; href?: string }) {
  const body = (
    <>
      <div className={`text-2xl font-semibold ${bad ? "text-red-300" : "text-slate-100"}`}>{value}</div>
      <div className="text-xs uppercase text-slate-500">{label}</div>
    </>
  );
  if (!href) return <div className="rounded border border-slate-700 p-3">{body}</div>;
  return (
    <Link href={href} aria-label={`${label}: ${value}. Open the list`} className="block rounded border border-slate-700 p-3 transition-colors hover:border-sky-500/60 hover:bg-slate-800/60 print:border-slate-300">
      {body}
    </Link>
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
    authFetch(`/api/v1/client-posture/${encodeURIComponent(clientId)}`)
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
  const links = postureLinks(clientId);

  return (
    <div className="space-y-4 p-6">
      <div className="flex items-end justify-between gap-4 print:hidden">
        <div>
          <h1 className="text-xl font-semibold text-slate-100">Client posture</h1>
          <p className="mt-1 text-sm text-slate-400">One client&apos;s devices, Multi-Factor coverage, open alerts and cases on a page you can print for a review.</p>
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
          <LinkedTools tools={shown.tools ?? []} />
          <section>
            <h3 className="mb-2 text-sm uppercase text-slate-500">Devices</h3>
            <div className="grid grid-cols-2 gap-3 md:grid-cols-5">
              <Stat label="Devices" value={shown.devices.devices} href={links.devices} />
              <Stat label="Need attention" value={shown.devices.needs_attention} bad={shown.devices.needs_attention > 0} href={links.needsAttention} />
              <Stat label="Stale agents" value={shown.devices.stale_agents} bad={shown.devices.stale_agents > 0} href={links.stale} />
              <Stat label="Not in Huntress" value={shown.devices.not_in_huntress} bad={shown.devices.not_in_huntress > 0} href={links.notInHuntress} />
              <Stat label="Offline" value={shown.devices.offline} href={links.offline} />
            </div>
          </section>
          <section>
            <h3 className="mb-2 text-sm uppercase text-slate-500">Multi-Factor</h3>
            {shown.identity ? (
              <div className="grid grid-cols-2 gap-3 md:grid-cols-5">
                <Stat label="People" value={shown.identity.people} href={links.people} />
                <Stat label="Covered" value={coverage(shown.identity)} href={links.people} />
                <Stat label="Registered, not required" value={shown.identity.not_required} bad={shown.identity.not_required > 0} href={links.notRequired} />
                <Stat label="No Multi-Factor" value={shown.identity.without_mfa} bad={shown.identity.without_mfa > 0} href={links.without} />
                <Stat label="Administrators without" value={shown.identity.admins_without_mfa} bad={shown.identity.admins_without_mfa > 0} href={links.adminsWithout} />
              </div>
            ) : (
              <p className="text-sm text-slate-400" data-testid="no-identity">
                No Multi-Factor data yet. It arrives once CORE is connected to CIPP and this client&apos;s CIPP tenant is mapped.
              </p>
            )}
          </section>
          <DomainChecks clientId={shown.client_id} />
          <section>
            <h3 className="mb-2 text-sm uppercase text-slate-500">Alerts and cases</h3>
            <div className="grid grid-cols-2 gap-3 md:grid-cols-5">
              <Stat label="Open alerts" value={shown.alerts.open} href={links.alerts} />
              <Stat label="Critical" value={shown.alerts.critical} bad={shown.alerts.critical > 0} href={links.critical} />
              <Stat label="High" value={shown.alerts.high} bad={shown.alerts.high > 0} href={links.high} />
              <Stat label="Open, no ticket" value={shown.alerts.without_ticket} bad={shown.alerts.without_ticket > 0} href={links.noTicket} />
              <Stat label="Open cases" value={shown.open_cases} href={links.cases} />
            </div>
          </section>
        </div>
      )}
    </div>
  );
}
