"use client";

/**
 * Sign-in scores: the sign-ins the behaviour service found most unusual in the last days, across clients. Read-only: nothing alerts on these yet; this is for judging whether the scores are
 * useful before alerting is turned on. Backed by GET /api/v1/signins/top.
 */
import { useCallback, useEffect, useState } from "react";

import { authFetch } from "@/lib/auth-session";

export interface ScoredSignin {
  client_id: string;
  client_name: string | null;
  user: string;
  display_name: string | null;
  occurred_at: string;
  score: number;
  success: boolean;
  country: string | null;
  city: string | null;
  ip_address: string | null;
  app: string | null;
  mfa: boolean | null;
  risk: string | null;
}

const DAYS = [1, 7, 30];

/** "Dallas, US" / "US" / "unknown place". */
export function placeLabel(s: Pick<ScoredSignin, "city" | "country">): string {
  const parts = [s.city, s.country].filter((p): p is string => !!p);
  return parts.length ? parts.join(", ") : "unknown place";
}

export function SigninScores() {
  const [rows, setRows] = useState<ScoredSignin[] | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [days, setDays] = useState(7);

  const load = useCallback(async (d: number) => {
    try {
      const res = await authFetch(`/api/v1/signins/top?days=${d}&limit=100`);
      if (!res.ok) throw new Error(`The API answered ${res.status}`);
      setRows((await res.json()) as ScoredSignin[]);
      setError(null);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Could not load sign-in scores");
    }
  }, []);

  useEffect(() => {
    void load(days);
  }, [load, days]);

  return (
    <div className="space-y-4 p-6">
      <div>
        <h1 className="text-xl font-semibold text-slate-100">Sign-in scores</h1>
        <p className="mt-1 text-sm text-slate-400">
          The sign-ins the behaviour service found most unusual, across clients. Higher is more unusual. Nothing alerts on these yet; this is for judging the scores first.
        </p>
      </div>
      <div className="flex gap-2 text-sm">
        {DAYS.map((d) => (
          <button
            key={d}
            type="button"
            onClick={() => setDays(d)}
            aria-pressed={days === d}
            className={`rounded border px-2 py-1 ${days === d ? "border-sky-500 text-sky-300" : "border-slate-700 text-slate-400"}`}
          >
            {d === 1 ? "Last day" : `Last ${d} days`}
          </button>
        ))}
      </div>
      {error && (
        <p role="alert" className="rounded border border-red-500/40 bg-red-500/10 p-3 text-sm text-red-300">
          {error}
        </p>
      )}
      {rows === null && !error && <p className="text-sm text-slate-500">Loading...</p>}
      {rows !== null && rows.length === 0 && (
        <p data-testid="none" className="text-sm text-slate-400">
          No scored sign-ins in this period. Sign-ins arrive hourly through CORE once CIPP is connected and its tenants are mapped to clients.
        </p>
      )}
      {rows !== null && rows.length > 0 && (
        <table className="w-full text-left text-sm">
          <thead>
            <tr className="border-b border-slate-700 text-slate-500">
              <th className="py-2">Score</th>
              <th>Person</th>
              <th>Client</th>
              <th>When</th>
              <th>Where</th>
              <th>App</th>
              <th>Result</th>
            </tr>
          </thead>
          <tbody>
            {rows.map((r, i) => (
              <tr key={`${r.client_id}-${r.user}-${r.occurred_at}-${i}`} className="border-b border-slate-800" data-testid="signin-row">
                <td className="py-2 font-mono text-slate-200">{r.score.toFixed(2)}</td>
                <td className="text-slate-200">{r.user}</td>
                <td className="text-slate-400">{r.client_name ?? "This organization"}</td>
                <td className="text-slate-400">{new Date(r.occurred_at).toLocaleString()}</td>
                <td className="text-slate-400">
                  {placeLabel(r)}
                  {r.ip_address ? <span className="ml-1 font-mono text-slate-500">{r.ip_address}</span> : null}
                </td>
                <td className="text-slate-400">{r.app ?? "—"}</td>
                <td className={r.success ? "text-slate-400" : "text-red-300"}>
                  {r.success ? "Signed in" : "Failed"}
                  {r.mfa === false ? <span className="ml-1 text-amber-300">no MFA</span> : null}
                  {r.risk && r.risk !== "none" ? <span className="ml-1 text-amber-300">risk: {r.risk}</span> : null}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
    </div>
  );
}
