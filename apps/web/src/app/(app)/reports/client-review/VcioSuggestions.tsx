"use client";

import { useCallback, useEffect, useState } from "react";
import { authFetch } from "@/lib/auth-session";

export interface Proposal {
  id: string;
  key: string;
  name: string;
  description: string;
  priority: string;
  evidence: string;
  status: string;
  result_message: string | null;
}

interface Suggestions {
  mapped: boolean;
  proposals: Proposal[];
}

/** What a state means to the person reading the list. */
export const STATUS_TEXT: Record<string, string> = {
  suggested: "Waiting for you",
  approved: "Approved: CORE will add it to vCIO Toolbox",
  sent: "Added to vCIO Toolbox",
  failed: "vCIO Toolbox did not take it",
  rejected: "Rejected",
  cleared: "No longer applies",
};

/** The suggestions a person still has something to do with, then the ones already dealt with. */
export function orderProposals(list: Proposal[]): Proposal[] {
  const rank: Record<string, number> = { suggested: 0, failed: 1, approved: 2, sent: 3, rejected: 4, cleared: 5 };
  return [...list].sort((a, b) => (rank[a.status] ?? 9) - (rank[b.status] ?? 9) || a.name.localeCompare(b.name));
}

async function send(path: string): Promise<Response> {
  return authFetch(path, { method: "POST" });
}

/**
 * What AiSOC suggests adding to this client's vCIO Toolbox, worked out from the checks above. Each one is a recommendation a person approves or rejects; only an approved one is sent, and CORE sends it.
 * Not part of a printed review.
 */
export function VcioSuggestions({ clientId }: { clientId: string }) {
  const base = `/api/v1/client-review/${encodeURIComponent(clientId)}/vcio-proposals`;
  const [data, setData] = useState<Suggestions | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  const load = useCallback(async () => {
    const res = await authFetch(base);
    if (!res.ok) throw new Error(`The API answered ${res.status}`);
    setData((await res.json()) as Suggestions);
  }, [base]);

  useEffect(() => {
    let live = true;
    setData(null);
    setError(null);
    load().catch((e: unknown) => {
      if (live) setError(e instanceof Error ? e.message : "Could not load the suggestions");
    });
    return () => {
      live = false;
    };
  }, [load]);

  async function act(path: string, then: "reload" | "set") {
    setBusy(true);
    setError(null);
    try {
      const res = await send(path);
      if (!res.ok) {
        const body = (await res.json().catch(() => ({}))) as { detail?: unknown };
        throw new Error(typeof body.detail === "string" ? body.detail : `The API answered ${res.status}`);
      }
      if (then === "set") setData((await res.json()) as Suggestions);
      else await load();
    } catch (e) {
      setError(e instanceof Error ? e.message : "That did not work");
    } finally {
      setBusy(false);
    }
  }

  const proposals = orderProposals(data?.proposals ?? []);
  return (
    <section className="rounded-lg border border-slate-800 p-4 print:hidden" data-testid="vcio-suggestions">
      <div className="mb-2 flex flex-wrap items-center justify-between gap-2">
        <h2 className="text-sm font-semibold uppercase tracking-wide text-slate-400">Suggested for vCIO Toolbox</h2>
        <button type="button" disabled={busy} onClick={() => void act(`${base}/refresh`, "set")} className="rounded border border-slate-600 px-2 py-1 text-xs text-slate-200 hover:bg-slate-800 disabled:opacity-40">
          Check again
        </button>
      </div>
      <p className="text-xs text-slate-500">
        Recommendations AiSOC would add to this client in vCIO Toolbox, from the checks in this review. Nothing is sent until you approve it, and CORE does the sending.
      </p>
      {data && !data.mapped && (
        <p className="mt-2 text-sm text-yellow-300" data-testid="vcio-unmapped">
          This client is not mapped to a vCIO Toolbox customer yet. Map it on the Clients page to approve suggestions.
        </p>
      )}
      {error && (
        <p role="alert" className="mt-2 text-sm text-red-300">
          {error}
        </p>
      )}
      {data && proposals.length === 0 && <p className="mt-2 text-sm text-slate-500">No suggestions yet. Press Check again to work them out from the latest data.</p>}
      <ul className="mt-3 space-y-3">
        {proposals.map((p) => (
          <li key={p.id} className="text-sm" data-testid="vcio-suggestion">
            <div className="flex flex-wrap items-baseline justify-between gap-2">
              <p className="text-slate-200">
                {p.name} <span className="text-xs text-slate-500">· {p.priority}</span>
              </p>
              <span className="text-xs text-slate-400" data-testid="vcio-suggestion-status">
                {STATUS_TEXT[p.status] ?? p.status}
              </span>
            </div>
            <p className="text-xs text-slate-500">{p.evidence}</p>
            {p.result_message && <p className="text-xs text-red-300">{p.result_message}</p>}
            {(p.status === "suggested" || p.status === "failed") && (
              <div className="mt-1 flex gap-2">
                <button type="button" disabled={busy || data?.mapped === false} onClick={() => void act(`${base}/${p.id}/approve`, "reload")} className="rounded bg-blue-600 px-2 py-1 text-xs text-white disabled:opacity-40">
                  {p.status === "failed" ? "Approve and try again" : "Approve"}
                </button>
                <button type="button" disabled={busy} onClick={() => void act(`${base}/${p.id}/reject`, "reload")} className="rounded border border-slate-600 px-2 py-1 text-xs text-slate-200 disabled:opacity-40">
                  Reject
                </button>
              </div>
            )}
          </li>
        ))}
      </ul>
    </section>
  );
}
