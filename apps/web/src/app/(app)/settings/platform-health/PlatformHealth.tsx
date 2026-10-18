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
}

interface Snapshot {
  overall: "ok" | "degraded";
  down: string[];
  services: ServiceRow[];
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
