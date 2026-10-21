"use client";

/**
 * Microsoft Secure Score: per client, the score Microsoft gives the tenant's security setup, how it moved over the last 30 days, how it compares with Microsoft's average, and (opening a row) the
 * controls still missing the most points. Read through CIPP and refreshed daily by CORE. Backed by GET /api/v1/identity/secure-scores and /api/v1/identity/secure-scores/{client}.
 * Read-only: nothing here changes a tenant.
 */
import { useCallback, useEffect, useMemo, useState } from "react";

import { authFetch } from "@/lib/auth-session";

export interface ScorePoint {
  d: string;
  c: number;
  m: number;
}

export interface ScoreClient {
  client_id: string;
  client_name: string | null;
  current: number;
  max: number;
  percent: number;
  average: number | null;
  change_30d: number | null;
  active_users: number | null;
  licensed_users: number | null;
  taken_at: string;
  refreshed_at: string;
  history: ScorePoint[];
  points_available: number;
}

export interface Improvement {
  id: string;
  title: string;
  category?: string;
  service?: string;
  missing: number;
  max: number;
  rank?: number;
  user_impact?: string;
  cost?: string;
  status?: string;
  description?: string;
}

type Sort = "lowest" | "biggest_drop" | "name";

/** The lines drawn for a small trend chart: the points as an SVG path scaled into ``width`` by ``height`` (the lowest point at the bottom). An empty string for fewer than two points. */
export function sparklinePath(points: Pick<ScorePoint, "c">[], width = 96, height = 24): string {
  if (points.length < 2) return "";
  const values = points.map((p) => p.c);
  const lo = Math.min(...values);
  const hi = Math.max(...values);
  const span = hi - lo || 1;
  return values
    .map((v, i) => `${i === 0 ? "M" : "L"}${((i / (values.length - 1)) * width).toFixed(1)},${(height - ((v - lo) / span) * (height - 2) - 1).toFixed(1)}`)
    .join(" ");
}

/** "+15", "-5" or "0" for a 30-day change; a dash when there is no history to compare with. */
export function changeText(change: number | null): string {
  if (change === null) return "—";
  if (change === 0) return "0";
  return `${change > 0 ? "+" : "−"}${Math.abs(change).toLocaleString(undefined, { maximumFractionDigits: 2 })}`;
}

/** Clients filtered by name and ordered: lowest score first, biggest 30-day drop first, or by name (the organization's own entry has no name and goes first). */
export function visibleScores(clients: ScoreClient[], opts: { query?: string; sort: Sort }): ScoreClient[] {
  const needle = (opts.query ?? "").trim().toLowerCase();
  const nameOf = (c: ScoreClient) => c.client_name ?? "";
  const list = clients.filter((c) => !needle || (nameOf(c) || "this organization").toLowerCase().includes(needle));
  const byName = (a: ScoreClient, b: ScoreClient) => nameOf(a).localeCompare(nameOf(b), undefined, { sensitivity: "base", numeric: true });
  if (opts.sort === "name") return list.sort(byName);
  if (opts.sort === "biggest_drop") return list.sort((a, b) => (a.change_30d ?? 0) - (b.change_30d ?? 0) || byName(a, b));
  return list.sort((a, b) => a.percent - b.percent || byName(a, b));
}

async function getJson<T>(path: string): Promise<T> {
  const res = await authFetch(path);
  if (!res.ok) throw new Error(`The API answered ${res.status}`);
  return (await res.json()) as T;
}

function Trend({ history }: { history: ScorePoint[] }) {
  const path = sparklinePath(history);
  if (!path) return <span className="text-slate-600">—</span>;
  return (
    <svg width="96" height="24" viewBox="0 0 96 24" role="img" aria-label={`Score over the last ${history.length} days`} className="text-sky-400">
      <path d={path} fill="none" stroke="currentColor" strokeWidth="1.5" />
    </svg>
  );
}

function Improvements({ clientId }: { clientId: string }) {
  const [items, setItems] = useState<Improvement[] | null>(null);
  const [error, setError] = useState<string | null>(null);
  useEffect(() => {
    let live = true;
    getJson<{ improvements: Improvement[] }>(`/api/v1/identity/secure-scores/${encodeURIComponent(clientId)}`)
      .then((d) => {
        if (live) setItems(d.improvements);
      })
      .catch((e: unknown) => {
        if (live) setError(e instanceof Error ? e.message : "Could not load the improvements");
      });
    return () => {
      live = false;
    };
  }, [clientId]);
  if (error) return <p className="text-sm text-red-300">{error}</p>;
  if (items === null) return <p className="text-sm text-slate-500">Loading...</p>;
  if (items.length === 0) return <p className="text-sm text-slate-500">Every control Microsoft scores is fully met.</p>;
  return (
    <ul className="space-y-2 text-sm" data-testid="improvements">
      {items.map((i) => (
        <li key={i.id} className="rounded border border-slate-800 p-2">
          <div className="flex flex-wrap items-baseline gap-2">
            <span className="rounded bg-sky-500/20 px-1.5 py-0.5 text-[11px] text-sky-300">+{i.missing.toLocaleString(undefined, { maximumFractionDigits: 2 })} points</span>
            <span className="font-medium text-slate-200">{i.title}</span>
            {i.category ? <span className="text-xs text-slate-500">{i.category}</span> : null}
            {i.user_impact && i.user_impact !== "Unknown" ? <span className="text-xs text-slate-500">user impact: {i.user_impact}</span> : null}
            {i.cost && i.cost !== "Unknown" ? <span className="text-xs text-slate-500">cost: {i.cost}</span> : null}
          </div>
          {i.status ? <p className="mt-1 text-xs text-slate-400">{i.status}</p> : null}
          {i.description ? <p className="mt-1 text-xs text-slate-500">{i.description}</p> : null}
        </li>
      ))}
    </ul>
  );
}

export function SecureScore() {
  const [clients, setClients] = useState<ScoreClient[] | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [query, setQuery] = useState("");
  const [sort, setSort] = useState<Sort>("lowest");
  const [open, setOpen] = useState<string | null>(null);

  const load = useCallback(async () => {
    try {
      setClients(await getJson<ScoreClient[]>("/api/v1/identity/secure-scores"));
      setError(null);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Could not load the Secure Scores");
    }
  }, []);

  useEffect(() => {
    void load();
  }, [load]);

  const shown = useMemo(() => visibleScores(clients ? [...clients] : [], { query, sort }), [clients, query, sort]);
  const overall = clients && clients.length > 0 ? Math.round(clients.reduce((t, c) => t + c.percent, 0) / clients.length) : null;
  const falling = (clients ?? []).filter((c) => c.change_30d !== null && c.change_30d < 0).length;

  return (
    <div className="space-y-4 p-6">
      <div>
        <h1 className="text-xl font-semibold text-slate-100">Microsoft Secure Score</h1>
        <p className="mt-1 text-sm text-slate-400">
          How well each client&apos;s Microsoft 365 is set up against Microsoft&apos;s own security checklist, read through CIPP once a day. Open a client to see the controls that would add the most points. Read-only: nothing here
          changes a tenant.
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
          Nothing yet. Once CORE is connected to CIPP and the CIPP tenants are mapped to clients, each client&apos;s Secure Score appears here after the next daily read.
        </p>
      )}
      {clients !== null && clients.length > 0 && (
        <>
          <p data-testid="totals" className="text-sm text-slate-300">
            {clients.length} clients, {overall}% on average; {falling} {falling === 1 ? "has" : "have"} fallen in the last 30 days.
          </p>
          <div className="flex flex-wrap items-center gap-4">
            <input
              type="search"
              aria-label="Search clients"
              placeholder="Search clients"
              value={query}
              onChange={(e) => setQuery(e.target.value)}
              className="w-64 rounded border border-slate-700 bg-slate-900 px-3 py-1.5 text-sm text-slate-200 placeholder:text-slate-500"
            />
            <label className="flex items-center gap-2 text-sm text-slate-300">
              Order by
              <select aria-label="Order by" value={sort} onChange={(e) => setSort(e.target.value as Sort)} className="rounded border border-slate-700 bg-slate-900 px-2 py-1 text-sm text-slate-200">
                <option value="lowest">Lowest score first</option>
                <option value="biggest_drop">Biggest 30-day drop first</option>
                <option value="name">Client name</option>
              </select>
            </label>
          </div>
          <table className="w-full text-left text-sm">
            <thead className="text-xs uppercase text-slate-500">
              <tr className="border-b border-slate-700">
                <th className="py-2">Client</th>
                <th>Score</th>
                <th>30 days</th>
                <th>Trend</th>
                <th>Microsoft average</th>
                <th>People</th>
                <th>Read</th>
              </tr>
            </thead>
            <tbody>
              {shown.map((c) => (
                <ScoreRow key={c.client_id} c={c} open={open === c.client_id} toggle={() => setOpen(open === c.client_id ? null : c.client_id)} />
              ))}
            </tbody>
          </table>
        </>
      )}
    </div>
  );
}

function ScoreRow({ c, open, toggle }: { c: ScoreClient; open: boolean; toggle: () => void }) {
  const tone = c.percent >= 70 ? "bg-emerald-500" : c.percent >= 45 ? "bg-amber-500" : "bg-red-500";
  const changeTone = c.change_30d === null || c.change_30d === 0 ? "text-slate-500" : c.change_30d > 0 ? "text-emerald-300" : "text-red-300";
  const belowAverage = c.average !== null && c.current < c.average;
  return (
    <>
      <tr className="border-b border-slate-800" data-testid="score-row">
        <td className="py-2">
          <button type="button" onClick={toggle} aria-expanded={open} className="text-left text-slate-200 hover:underline">
            {c.client_name ?? "This organization"}
          </button>
        </td>
        <td>
          <div className="flex items-center gap-2">
            <div className="h-2 w-24 rounded bg-slate-800" aria-hidden="true">
              <div className={`h-2 rounded ${tone}`} style={{ width: `${Math.min(100, Math.max(0, c.percent))}%` }} />
            </div>
            <span className="text-slate-200">{c.percent}%</span>
            <span className="text-xs text-slate-500">
              {c.current.toLocaleString(undefined, { maximumFractionDigits: 2 })} / {c.max.toLocaleString(undefined, { maximumFractionDigits: 2 })}
            </span>
          </div>
        </td>
        <td className={changeTone} data-testid="change">
          {changeText(c.change_30d)}
        </td>
        <td>
          <Trend history={c.history} />
        </td>
        <td className={belowAverage ? "text-amber-300" : "text-slate-400"}>{c.average === null ? "—" : c.average.toLocaleString(undefined, { maximumFractionDigits: 1 })}</td>
        <td className="text-slate-400">{c.active_users ?? "—"}{c.licensed_users !== null ? ` / ${c.licensed_users}` : ""}</td>
        <td className="text-slate-500">{new Date(c.taken_at).toLocaleDateString()}</td>
      </tr>
      {open && (
        <tr className="border-b border-slate-800 bg-slate-900/40">
          <td colSpan={7} className="px-3 py-3">
            <p className="mb-2 text-xs uppercase text-slate-500">
              Controls still missing points{c.points_available > 0 ? ` (the top ones add up to ${c.points_available.toLocaleString(undefined, { maximumFractionDigits: 2 })} points)` : ""}
            </p>
            <Improvements clientId={c.client_id} />
          </td>
        </tr>
      )}
    </>
  );
}
