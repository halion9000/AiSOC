"use client";

/**
 * Platform health: is each internal service (fusion, connectors, agents, ...) answering its own probe right now?
 * Backed by GET /api/v1/health/services. Refreshes every 15 s; a service that does not answer is shown as down, never hidden.
 */
import { useCallback, useEffect, useState } from "react";

import { authFetch } from "@/lib/auth-session";

interface ServiceRow {
  service: string;
  status: "up" | "down";
  latency_ms: number;
  detail: string;
}

interface DatabaseSecurity {
  enforced: boolean | null;
  reason: string;
  fix?: string;
  pool?: {
    known: boolean;
    in_use?: number;
    limit?: number;
    percent?: number;
    near_limit?: boolean;
    peak_last_hour?: { samples: number; peak_in_use?: number; peak_limit?: number; peak_percent?: number; peak_minutes_ago?: number };
  };
}

interface DeviceFeed {
  vendor: string;
  devices: number;
  last_synced: string | null;
  minutes_ago: number | null;
  stalled: boolean;
}

/** How long ago, in plain words. */
export function agoLabel(minutes: number | null): string {
  if (minutes === null) return "never";
  if (minutes < 2) return "just now";
  if (minutes < 120) return `${minutes} minutes ago`;
  if (minutes < 60 * 48) return `${Math.floor(minutes / 60)} hours ago`;
  return `${Math.floor(minutes / 1440)} days ago`;
}

interface Snapshot {
  overall: "ok" | "degraded";
  down: string[];
  services: ServiceRow[];
  device_feeds?: DeviceFeed[];
  signins?: { last_24h: number; scored_last_24h: number; unscored: number; users_last_24h: number; newest_received: string | null } | null;
  core_feed?: { sources: number; last_report: string | null; minutes_ago: number | null; silent: boolean } | null;
  warnings?: { key: string; level: "error" | "warn"; text: string }[];
  database?: DatabaseSecurity;
  generated_at: string;
}

export function PlatformHealth() {
  const [snapshot, setSnapshot] = useState<Snapshot | null>(null);
  const [error, setError] = useState<string | null>(null);

  const load = useCallback(async () => {
    try {
      const res = await authFetch("/api/v1/health/services");
      if (!res.ok) throw new Error(`The API answered ${res.status}`);
      setSnapshot((await res.json()) as Snapshot);
      setError(null);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Could not load platform health");
    }
  }, []);

  useEffect(() => {
    void load();
    const timer = setInterval(() => void load(), 15000);
    return () => clearInterval(timer);
  }, [load]);

  return (
    <div className="mx-auto max-w-3xl space-y-4 p-6">
      <h1 className="text-xl font-semibold">Platform health</h1>
      {error && (
        <p role="alert" className="rounded border border-red-300 bg-red-50 p-3 text-sm text-red-800">
          {error}
        </p>
      )}
      {!snapshot && !error && <p className="text-sm text-slate-500">Checking the services...</p>}
      {snapshot && (
        <>
          <p className={snapshot.overall === "ok" ? "text-emerald-700" : "text-red-700"} data-testid="overall">
            {snapshot.overall === "ok" ? "Every service is answering." : `Not answering: ${snapshot.down.join(", ")}`}
          </p>
          {snapshot.database && snapshot.database.enforced !== true && (
            <p role="note" data-testid="row-security" className="rounded border border-yellow-500/40 bg-yellow-500/10 p-3 text-sm text-yellow-200">
              {snapshot.database.enforced === false ? 'Tenant isolation in the database is not being enforced: ' : 'Could not check tenant isolation in the database: '}
              {snapshot.database.reason}.{snapshot.database.fix ? ` To fix: ${snapshot.database.fix}.` : ''}
            </p>
          )}
          {snapshot.database?.pool?.peak_last_hour && snapshot.database.pool.peak_last_hour.samples > 0 && (
            <p data-testid="pool-peak" className={`text-sm ${(snapshot.database.pool.peak_last_hour.peak_percent ?? 0) >= 80 ? "text-red-300" : "text-slate-400"}`}>
              Database connections: busiest in the last hour was {snapshot.database.pool.peak_last_hour.peak_percent}% ({snapshot.database.pool.peak_last_hour.peak_in_use} of {snapshot.database.pool.peak_last_hour.peak_limit}),{" "}
              {agoLabel(snapshot.database.pool.peak_last_hour.peak_minutes_ago ?? null)}.
            </p>
          )}
          {snapshot.database?.pool?.known && snapshot.database.pool.near_limit && (
            <p role="note" data-testid="pool-warning" className="rounded border border-red-500/40 bg-red-500/10 p-3 text-sm text-red-200">
              The database connection pool is {snapshot.database.pool.percent}% full ({snapshot.database.pool.in_use} of {snapshot.database.pool.limit} in use). When it is full, pages start failing with 500
              errors until requests finish.
            </p>
          )}
          {(snapshot.warnings ?? []).filter((w) => w.key !== "services" && w.key !== "core").length > 0 && (
            <ul data-testid="warnings" className="space-y-1 rounded border border-amber-500/40 bg-amber-500/10 p-3 text-sm text-amber-200">
              {(snapshot.warnings ?? [])
                .filter((w) => w.key !== "services" && w.key !== "core")
                .map((w) => (
                  <li key={w.key} className={w.level === "error" ? "text-red-300" : undefined}>
                    {w.text}
                  </li>
                ))}
            </ul>
          )}
          {snapshot.core_feed?.silent && (
            <p role="note" data-testid="core-silent" className="rounded border border-amber-500/40 bg-amber-500/10 p-3 text-sm text-amber-200">
              CORE has not reported to AiSOC {snapshot.core_feed.minutes_ago === null ? "yet" : `since ${agoLabel(snapshot.core_feed.minutes_ago).replace(" ago", "")} ago`}. While it is silent, no new alerts, devices or
              links arrive from Huntress, Petra, NinjaOne and the other tools. Check that CORE is running and can reach AiSOC.
            </p>
          )}
          {snapshot.signins && (
            <p data-testid="signins-line" className="text-sm text-slate-300">
              Sign-ins collected through CORE: {snapshot.signins.last_24h.toLocaleString()} in the last 24 hours from {snapshot.signins.users_last_24h.toLocaleString()} people,{" "}
              {snapshot.signins.scored_last_24h.toLocaleString()} scored for unusual behaviour
              {snapshot.signins.unscored > 0 ? `, ${snapshot.signins.unscored.toLocaleString()} waiting to be scored (is the behaviour service up?)` : ""}.
            </p>
          )}
          {snapshot.device_feeds && snapshot.device_feeds.length > 0 && (
            <section aria-label="Device feeds" data-testid="device-feeds">
              <h2 className="mb-1 text-sm font-medium text-slate-300">Device feeds</h2>
              <ul className="space-y-1 text-sm">
                {snapshot.device_feeds.map((f) => (
                  <li key={f.vendor} className={f.stalled ? "text-red-300" : "text-slate-300"}>
                    <span className="font-medium">{f.vendor}</span>: {f.devices.toLocaleString()} devices, last synced {agoLabel(f.minutes_ago)}
                    {f.stalled ? " (nothing for hours: is CORE running, and is this tool's connector working?)" : ""}
                  </li>
                ))}
              </ul>
            </section>
          )}
          <table className="w-full text-left text-sm">
            <thead>
              <tr className="border-b text-slate-500">
                <th className="py-2">Service</th>
                <th>Status</th>
                <th>Answered in</th>
                <th>Detail</th>
              </tr>
            </thead>
            <tbody>
              {snapshot.services.map((s) => (
                <tr key={s.service} className="border-b">
                  <td className="py-2 font-medium">{s.service}</td>
                  <td className={s.status === "up" ? "text-emerald-700" : "text-red-700"}>{s.status}</td>
                  <td>{s.latency_ms} ms</td>
                  <td className="text-slate-500">{s.detail}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </>
      )}
    </div>
  );
}
