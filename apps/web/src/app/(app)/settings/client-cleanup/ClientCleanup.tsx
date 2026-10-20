"use client";

/**
 * Client cleanup: the clients that hold nothing (no devices, no alerts, no cases, no tool client mapped to them), as candidates to archive. Archiving hides the client, renames it
 * "<name> (archived)" and deletes nothing. Backed by GET /api/v1/mssp/clients/cleanup and the existing archive route.
 */
import { useCallback, useEffect, useState } from "react";

import { authFetch } from "@/lib/auth-session";

export interface EmptyClient {
  id: string;
  name: string;
  devices: number;
  alerts: number;
  cases: number;
  tool_clients: number;
}

interface Report {
  checked: number;
  empty: EmptyClient[];
}

export function ClientCleanup() {
  const [report, setReport] = useState<Report | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [confirming, setConfirming] = useState<string | null>(null);
  const [busy, setBusy] = useState<string | null>(null);

  const load = useCallback(async () => {
    try {
      const res = await authFetch("/api/v1/mssp/clients/cleanup");
      if (!res.ok) throw new Error(`The API answered ${res.status}`);
      setReport((await res.json()) as Report);
      setError(null);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Could not load the cleanup report");
    }
  }, []);

  useEffect(() => {
    void load();
  }, [load]);

  const archive = async (c: EmptyClient) => {
    setBusy(c.id);
    try {
      const res = await authFetch(`/api/v1/mssp/tenants/${c.id}/archive`, { method: "POST" });
      if (!res.ok) throw new Error(`The API answered ${res.status}`);
      setConfirming(null);
      await load();
    } catch (err) {
      setError(err instanceof Error ? err.message : "Could not archive that client");
    } finally {
      setBusy(null);
    }
  };

  return (
    <div className="space-y-4 p-6">
      <div>
        <h1 className="text-xl font-semibold text-slate-100">Client cleanup</h1>
        <p className="mt-1 max-w-2xl text-sm text-slate-400">
          Clients with nothing in them: no devices, no alerts, no cases and no tool client mapped to them. Archiving hides a client and renames it &quot;(archived)&quot;; nothing is deleted, and Show hidden brings it back.
        </p>
      </div>
      {error && (
        <p role="alert" className="rounded border border-red-500/40 bg-red-500/10 p-3 text-sm text-red-300">
          {error}
        </p>
      )}
      {report === null && !error && <p className="text-sm text-slate-500">Loading...</p>}
      {report !== null && (
        <p data-testid="checked" className="text-sm text-slate-300">
          {report.checked} clients checked, {report.empty.length} empty.
        </p>
      )}
      {report !== null && report.empty.length === 0 && (
        <p data-testid="none" className="text-sm text-slate-400">
          Every client has something in it.
        </p>
      )}
      {report !== null && report.empty.length > 0 && (
        <ul className="divide-y divide-slate-800 rounded border border-slate-800">
          {report.empty.map((c) => (
            <li key={c.id} className="flex items-center justify-between gap-4 px-4 py-3" data-testid="empty-client">
              <span className="text-slate-200">{c.name}</span>
              {confirming === c.id ? (
                <span className="flex items-center gap-2 text-sm">
                  <button type="button" disabled={busy === c.id} onClick={() => void archive(c)} className="rounded border border-red-500/50 bg-red-500/10 px-2 py-1 text-red-300 disabled:opacity-50">
                    {busy === c.id ? "Archiving..." : `Archive ${c.name}`}
                  </button>
                  <button type="button" onClick={() => setConfirming(null)} className="text-slate-400 hover:text-slate-200">
                    Cancel
                  </button>
                </span>
              ) : (
                <button type="button" onClick={() => setConfirming(c.id)} className="rounded border border-slate-600 px-2 py-1 text-sm text-slate-200 hover:bg-slate-800">
                  Archive
                </button>
              )}
            </li>
          ))}
        </ul>
      )}
    </div>
  );
}
