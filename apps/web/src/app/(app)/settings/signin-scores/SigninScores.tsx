"use client";

/**
 * Sign-in scores: the sign-ins the behaviour service found most unusual in the last days, across clients. Read-only: nothing alerts on these yet; this is for judging whether the scores are
 * useful before alerting is turned on. Backed by GET /api/v1/signins/top.
 */
import { useCallback, useEffect, useState } from "react";

import { authFetch } from "@/lib/auth-session";
import { FilterRow, SortableTh, useTable, type Column } from "@/components/ui/useTable";

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

const when = (iso: string): number | null => Date.parse(iso) || null;

/** The result as one phrase for sorting and filtering: "Signed in", "Signed in, no MFA", "Failed"... */
export function resultLabel(s: Pick<ScoredSignin, "success" | "mfa" | "risk">): string {
  const base = s.success ? "Signed in" : "Failed";
  const parts = [s.mfa === false ? "no MFA" : null, s.risk && s.risk !== "none" ? `risk: ${s.risk}` : null].filter((p): p is string => !!p);
  return parts.length ? `${base}, ${parts.join(", ")}` : base;
}

const SIGNIN_COLUMNS: Column<ScoredSignin>[] = [
  { key: "score", label: "Score", value: (r) => r.score, filter: "min" },
  { key: "person", label: "Person", value: (r) => r.user, filter: "text" },
  { key: "client", label: "Client", value: (r) => r.client_name ?? "This organization", filter: "text" },
  { key: "when", label: "When", value: (r) => new Date(r.occurred_at).toLocaleString(), sortValue: (r) => when(r.occurred_at), filter: "text" },
  { key: "where", label: "Where", value: (r) => [placeLabel(r), r.ip_address].filter(Boolean).join(" "), filter: "text" },
  { key: "app", label: "App", value: (r) => r.app ?? null, filter: "choice" },
  { key: "result", label: "Result", value: (r) => resultLabel(r), filter: "choice" },
];

const CHANGE_COLUMNS: Column<ScoredChange>[] = [
  { key: "score", label: "Score", value: (r) => r.score, filter: "min" },
  { key: "by", label: "Done by", value: (r) => r.actor, filter: "text" },
  { key: "what", label: "What", value: (r) => `${r.activity}${r.success ? "" : " (failed)"}`, filter: "text" },
  { key: "to", label: "To", value: (r) => r.target ?? null, filter: "text" },
  { key: "client", label: "Client", value: (r) => r.client_name ?? "This organization", filter: "text" },
  { key: "when", label: "When", value: (r) => new Date(r.occurred_at).toLocaleString(), sortValue: (r) => when(r.occurred_at), filter: "text" },
];

function ClearFilters({ active, shown, total, onClear }: { active: boolean; shown: number; total: number; onClear: () => void }) {
  if (!active) return null;
  return (
    <button type="button" onClick={onClear} className="text-xs text-sky-300 hover:underline">
      Clear filters ({shown} of {total} shown)
    </button>
  );
}

/** "Dallas, US" / "US" / "unknown place". */
export function placeLabel(s: Pick<ScoredSignin, "city" | "country">): string {
  const parts = [s.city, s.country].filter((p): p is string => !!p);
  return parts.length ? parts.join(", ") : "unknown place";
}

export interface ScoredChange {
  client_id: string;
  client_name: string | null;
  actor: string;
  actor_is_app: boolean;
  activity: string;
  category: string;
  target: string | null;
  success: boolean;
  sensitivity: number;
  occurred_at: string;
  score: number;
}

function ChangesTable({ rows }: { rows: ScoredChange[] }) {
  const t = useTable(rows, CHANGE_COLUMNS, { key: "score", dir: "desc" });
  return (
    <div className="space-y-2">
      <ClearFilters active={t.active} shown={t.shown.length} total={rows.length} onClear={t.clear} />
      <table className="w-full text-left text-sm">
        <thead className="text-xs text-slate-500">
          <tr className="border-b border-slate-700">
            {CHANGE_COLUMNS.map((c) => (
              <SortableTh key={c.key} col={c} sort={t.sort} onSort={t.toggleSort} />
            ))}
          </tr>
          <FilterRow columns={CHANGE_COLUMNS} filters={t.filters} setFilter={t.setFilter} choices={t.choices} />
        </thead>
        <tbody>
          {t.shown.length === 0 && (
            <tr>
              <td colSpan={CHANGE_COLUMNS.length} className="px-3 py-4 text-slate-500">
                Nothing matches these filters.
              </td>
            </tr>
          )}
          {t.shown.map((r, i) => (
            <tr key={`${r.client_id}-${r.actor}-${r.occurred_at}-${i}`} className="border-b border-slate-800" data-testid="change-row">
              <td className="px-3 py-2 font-mono text-slate-200">{r.score.toFixed(2)}</td>
              <td className="px-3 text-slate-200">
                {r.actor}
                {r.actor_is_app ? <span className="ml-1 text-slate-500">(app)</span> : null}
              </td>
              <td className={`px-3 ${r.success ? "text-slate-300" : "text-red-300"}`}>
                {r.activity}
                {r.success ? "" : " (failed)"}
              </td>
              <td className="px-3 text-slate-400">{r.target ?? "—"}</td>
              <td className="px-3 text-slate-400">{r.client_name ?? "This organization"}</td>
              <td className="px-3 text-slate-400">{new Date(r.occurred_at).toLocaleString()}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

/** The most unusual identity changes (a role added, a password reset, a security method registered...). Backed by GET /api/v1/identity/top. */
function IdentityChanges({ days }: { days: number }) {
  const [rows, setRows] = useState<ScoredChange[] | null>(null);
  const [error, setError] = useState<string | null>(null);
  useEffect(() => {
    let live = true;
    authFetch(`/api/v1/identity/top?days=${days}&limit=50`)
      .then(async (res) => {
        if (!res.ok) throw new Error(`The API answered ${res.status}`);
        const body = (await res.json()) as ScoredChange[];
        if (live) setRows(body);
      })
      .catch((e: unknown) => {
        if (live) setError(e instanceof Error ? e.message : "Could not load identity changes");
      });
    return () => {
      live = false;
    };
  }, [days]);
  return (
    <section className="space-y-2" data-testid="identity-changes">
      <h2 className="text-lg font-semibold text-slate-100">Identity changes</h2>
      <p className="text-sm text-slate-400">Role, group, password and security-method changes in Microsoft 365 that were flagged as unusual for whoever made them. Higher is more unusual.</p>
      {error && <p className="text-sm text-red-300">{error}</p>}
      {rows === null && !error && <p className="text-sm text-slate-500">Loading...</p>}
      {rows !== null && rows.length === 0 && <p className="text-sm text-slate-400">No identity changes were flagged as unusual in this period.</p>}
      {rows !== null && rows.length > 0 && <ChangesTable rows={rows} />}
    </section>
  );
}

function SigninsTable({ rows }: { rows: ScoredSignin[] }) {
  const t = useTable(rows, SIGNIN_COLUMNS, { key: "score", dir: "desc" });
  return (
    <div className="space-y-2">
      <ClearFilters active={t.active} shown={t.shown.length} total={rows.length} onClear={t.clear} />
      <table className="w-full text-left text-sm">
        <thead className="text-xs text-slate-500">
          <tr className="border-b border-slate-700">
            {SIGNIN_COLUMNS.map((c) => (
              <SortableTh key={c.key} col={c} sort={t.sort} onSort={t.toggleSort} />
            ))}
          </tr>
          <FilterRow columns={SIGNIN_COLUMNS} filters={t.filters} setFilter={t.setFilter} choices={t.choices} />
        </thead>
        <tbody>
          {t.shown.length === 0 && (
            <tr>
              <td colSpan={SIGNIN_COLUMNS.length} className="px-3 py-4 text-slate-500">
                Nothing matches these filters.
              </td>
            </tr>
          )}
          {t.shown.map((r, i) => (
            <tr key={`${r.client_id}-${r.user}-${r.occurred_at}-${i}`} className="border-b border-slate-800" data-testid="signin-row">
              <td className="px-3 py-2 font-mono text-slate-200">{r.score.toFixed(2)}</td>
              <td className="px-3 text-slate-200">{r.user}</td>
              <td className="px-3 text-slate-400">{r.client_name ?? "This organization"}</td>
              <td className="px-3 text-slate-400">{new Date(r.occurred_at).toLocaleString()}</td>
              <td className="px-3 text-slate-400">
                {placeLabel(r)}
                {r.ip_address ? <span className="ml-1 font-mono text-slate-500">{r.ip_address}</span> : null}
              </td>
              <td className="px-3 text-slate-400">{r.app ?? "—"}</td>
              <td className={`px-3 ${r.success ? "text-slate-400" : "text-red-300"}`}>
                {r.success ? "Signed in" : "Failed"}
                {r.mfa === false ? <span className="ml-1 text-amber-300">no MFA</span> : null}
                {r.risk && r.risk !== "none" ? <span className="ml-1 text-amber-300">risk: {r.risk}</span> : null}
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
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
          The sign-ins the behaviour service flagged as unusual for that person, across clients (it keeps a score only for the ones it flags). Higher is more unusual. Nothing alerts on these yet; this is for judging them first.
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
          No sign-ins were flagged as unusual in this period. That is normal while the service is still learning each person&apos;s usual pattern. Sign-ins arrive hourly through CORE once CIPP is connected and its tenants are mapped to clients.
        </p>
      )}
      {rows !== null && rows.length > 0 && <SigninsTable rows={rows} />}
      <IdentityChanges days={days} />
    </div>
  );
}
