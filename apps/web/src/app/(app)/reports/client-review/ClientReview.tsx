"use client";

/**
 * Client review: one client's tool coverage, Multi-Factor, Microsoft Secure Score, the last 30 days of alerts and cases, and a cyber-insurance readiness checklist, on one printable page.
 * Backed by GET /api/v1/client-review/{client}. Every answer is evidence from the connected tools; what AiSOC does not hold is shown as "Not known", never guessed.
 */
import { useEffect, useMemo, useState } from "react";
import { useSearchParams } from "next/navigation";

import { authFetch } from "@/lib/auth-session";

export interface Coverage {
  tool: string;
  have: number;
  of: number;
  percent: number | null;
}

export interface ReadinessItem {
  key: string;
  question: string;
  status: "met" | "partly" | "not_met" | "unknown";
  evidence: string;
}

export interface VcioRecommendation {
  name: string;
  priority: string | null;
  adoption: string;
  due: string | null;
  on_roadmap: boolean;
}

export interface VcioRisk {
  name: string;
  category: string | null;
  priority: string | null;
  impact: number | null;
  likelihood: number | null;
  score: number | null;
  inherent: string | null;
}

export interface Review {
  client_id: string;
  client_name: string | null;
  generated_at: string;
  window_days: number;
  devices: { endpoints: number; coverage: Coverage[]; stale_agents: number; offline: number; with_known_exploited: number | null; with_ransomware_exploit: number | null };
  mfa: { people: number; with_mfa: number; not_required: number; without_mfa: number; admins_without_mfa: number } | null;
  secure_score: { percent: number; current: number; max: number; average: number | null; taken_at: string } | null;
  alerts: { open: number; critical_open: number; high_open: number; opened_30d: number; closed_30d: number };
  cases: { open: number; opened_30d: number; resolved_30d: number };
  readiness: { met: number; partly: number; not_met: number; unknown: number; items: ReadinessItem[] };
  vcio?: { recommendations: { total: number; pending: number; adopted: number; declined: number; top: VcioRecommendation[] }; risks: VcioRisk[]; refreshed_at: string } | null;
}

interface ClientChoice {
  id: string;
  name: string;
}

export const TOOL_NAMES: Record<string, string> = {
  huntress: "Huntress (endpoint detection)",
  ninjaone: "NinjaOne (management)",
  dnsfilter: "DNSFilter (web filtering)",
  threatmate: "ThreatMate (vulnerability scanning)",
  fieldeffect: "Field Effect (monitoring)",
  autoelevate: "AutoElevate (privilege control)",
  screenconnect: "ScreenConnect (remote support)",
  addigy: "Addigy (Mac management)",
};

const STATUS: Record<ReadinessItem["status"], { label: string; className: string }> = {
  met: { label: "Met", className: "bg-emerald-500/20 text-emerald-300" },
  partly: { label: "Partly", className: "bg-amber-500/20 text-amber-300" },
  not_met: { label: "Not met", className: "bg-red-500/20 text-red-300" },
  unknown: { label: "Not known", className: "bg-slate-600/30 text-slate-300" },
};

/** One plain sentence for the top of the review: how many answers are met, and what needs a person. */
export function readinessHeadline(r: Review["readiness"]): string {
  const total = r.items.length;
  const gaps = r.not_met + r.partly;
  const parts = [`${r.met} of ${total} answers are met`];
  if (gaps > 0) parts.push(`${gaps} ${gaps === 1 ? "needs" : "need"} work`);
  if (r.unknown > 0) parts.push(`${r.unknown} ${r.unknown === 1 ? "is" : "are"} not known to AiSOC`);
  return `${parts.join(", ")}.`;
}

/** "Due 12 Jun 2026" or an empty string, from the ISO date vCIO Toolbox's summary carries. */
export function dueText(iso: string | null): string {
  const m = iso ? /^(\d{4})-(\d{2})-(\d{2})$/.exec(iso) : null;
  if (!m) return "";
  const months = ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"];
  const month = months[Number(m[2]) - 1];
  return month ? `due ${Number(m[3])} ${month} ${m[1]}` : "";
}

/** Tools worth showing: the ones some of this client's machines should be running, in the order given by the API. */
export function visibleCoverage(coverage: Coverage[]): Coverage[] {
  return coverage.filter((c) => c.of > 0);
}

async function getJson<T>(path: string): Promise<T> {
  const res = await authFetch(path);
  if (!res.ok) throw new Error(res.status === 404 ? "That client was not found." : `The API answered ${res.status}`);
  return (await res.json()) as T;
}

function Card({ title, children }: { title: string; children: React.ReactNode }) {
  return (
    <section className="rounded-lg border border-slate-800 p-4">
      <h2 className="mb-2 text-sm font-semibold uppercase tracking-wide text-slate-400">{title}</h2>
      {children}
    </section>
  );
}

export function ClientReview() {
  const params = useSearchParams();
  const [clients, setClients] = useState<ClientChoice[] | null>(null);
  const [clientId, setClientId] = useState(params?.get("client") ?? "");
  const [review, setReview] = useState<Review | null>(null);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    let live = true;
    getJson<{ id: string; name: string }[]>("/api/v1/mssp/children")
      .then((list) => {
        if (live) setClients(list.map((c) => ({ id: c.id, name: c.name })).sort((a, b) => a.name.localeCompare(b.name)));
      })
      .catch(() => {
        if (live) setClients([]);
      });
    return () => {
      live = false;
    };
  }, []);

  useEffect(() => {
    if (!clientId) {
      setReview(null);
      return;
    }
    let live = true;
    setReview(null);
    setError(null);
    getJson<Review>(`/api/v1/client-review/${encodeURIComponent(clientId)}`)
      .then((r) => {
        if (live) setReview(r);
      })
      .catch((e: unknown) => {
        if (live) setError(e instanceof Error ? e.message : "Could not load the review");
      });
    return () => {
      live = false;
    };
  }, [clientId]);

  const coverage = useMemo(() => (review ? visibleCoverage(review.devices.coverage) : []), [review]);

  return (
    <div className="space-y-4 p-6">
      <div className="flex flex-wrap items-end justify-between gap-3">
        <div>
          <h1 className="text-xl font-semibold text-slate-100">Client review</h1>
          <p className="mt-1 text-sm text-slate-400">
            Coverage, identity, alerts and a cyber-insurance readiness checklist for one client, from the tools AiSOC is connected to. Evidence, not a certification: what AiSOC cannot see is marked Not known.
          </p>
        </div>
        <div className="flex items-center gap-2 print:hidden">
          <select
            aria-label="Client"
            value={clientId}
            onChange={(e) => setClientId(e.target.value)}
            className="rounded border border-slate-700 bg-slate-900 px-3 py-1.5 text-sm text-slate-200"
          >
            <option value="">Choose a client...</option>
            {(clients ?? []).map((c) => (
              <option key={c.id} value={c.id}>
                {c.name}
              </option>
            ))}
          </select>
          <button type="button" disabled={!review} onClick={() => window.print()} className="rounded border border-slate-600 px-3 py-1.5 text-sm text-slate-200 hover:bg-slate-800 disabled:opacity-40">
            Print or save as PDF
          </button>
        </div>
      </div>

      {error && (
        <p role="alert" className="rounded border border-red-500/40 bg-red-500/10 p-3 text-sm text-red-300">
          {error}
        </p>
      )}
      {!clientId && !error && <p className="text-sm text-slate-500">Choose a client to see its review.</p>}
      {clientId && !review && !error && <p className="text-sm text-slate-500">Loading...</p>}

      {review && (
        <>
          <div>
            <h2 className="text-lg font-semibold text-slate-100" data-testid="review-title">
              {review.client_name ?? "This organization"}
            </h2>
            <p className="text-sm text-slate-300" data-testid="review-headline">
              {readinessHeadline(review.readiness)}
            </p>
            <p className="text-xs text-slate-500">Read {new Date(review.generated_at).toLocaleString()}. Alerts and cases cover the last {review.window_days} days.</p>
          </div>

          <Card title="Cyber-insurance readiness">
            <ul className="space-y-2" data-testid="readiness">
              {review.readiness.items.map((i) => (
                <li key={i.key} className="flex items-start gap-3 text-sm">
                  <span className={`mt-0.5 w-20 shrink-0 rounded px-2 py-0.5 text-center text-[11px] font-medium ${STATUS[i.status].className}`}>{STATUS[i.status].label}</span>
                  <span>
                    <span className="text-slate-200">{i.question}</span>
                    <span className="block text-xs text-slate-500">{i.evidence}</span>
                  </span>
                </li>
              ))}
            </ul>
          </Card>

          <div className="grid gap-4 md:grid-cols-2">
            <Card title="Tool coverage">
              {coverage.length === 0 ? (
                <p className="text-sm text-slate-500">No computers are listed for this client.</p>
              ) : (
                <ul className="space-y-2 text-sm" data-testid="coverage">
                  {coverage.map((c) => (
                    <li key={c.tool}>
                      <div className="flex justify-between text-slate-300">
                        <span>{TOOL_NAMES[c.tool] ?? c.tool}</span>
                        <span>
                          {c.have} of {c.of}
                          {c.percent !== null ? ` (${Math.round(c.percent)}%)` : ""}
                        </span>
                      </div>
                      <div className="mt-1 h-1.5 rounded bg-slate-800" aria-hidden="true">
                        <div className={`h-1.5 rounded ${(c.percent ?? 0) >= 90 ? "bg-emerald-500" : (c.percent ?? 0) >= 60 ? "bg-amber-500" : "bg-red-500"}`} style={{ width: `${Math.min(100, c.percent ?? 0)}%` }} />
                      </div>
                    </li>
                  ))}
                </ul>
              )}
              <p className="mt-3 text-xs text-slate-500">
                {review.devices.endpoints} computers. {review.devices.stale_agents} with an agent that has not checked in for two weeks, {review.devices.offline} offline for a week or more.
                {review.devices.with_known_exploited !== null ? ` ${review.devices.with_known_exploited} with a known-exploited vulnerability.` : ""}
              </p>
            </Card>

            <Card title="Identity">
              {review.mfa ? (
                <p className="text-sm text-slate-300" data-testid="mfa-line">
                  {review.mfa.with_mfa} of {review.mfa.people} people have a required second factor; {review.mfa.without_mfa} have none, {review.mfa.admins_without_mfa} of them administrators.
                </p>
              ) : (
                <p className="text-sm text-slate-500">No multi-factor data for this client yet.</p>
              )}
              {review.secure_score ? (
                <p className="mt-2 text-sm text-slate-300" data-testid="score-line">
                  Microsoft Secure Score {review.secure_score.percent}% ({review.secure_score.current} of {review.secure_score.max})
                  {review.secure_score.average !== null ? `, Microsoft's average is ${review.secure_score.average}` : ""}.
                </p>
              ) : (
                <p className="mt-2 text-sm text-slate-500">No Microsoft Secure Score read for this client yet.</p>
              )}
            </Card>

            {review.vcio ? (
              <Card title="From vCIO Toolbox">
                <p className="text-sm text-slate-300" data-testid="vcio-line">
                  {review.vcio.recommendations.total} recommendations: {review.vcio.recommendations.pending} pending, {review.vcio.recommendations.adopted} adopted, {review.vcio.recommendations.declined} declined.
                </p>
                {review.vcio.recommendations.top.length > 0 && (
                  <ul className="mt-2 space-y-1 text-sm" data-testid="vcio-top">
                    {review.vcio.recommendations.top.map((r) => (
                      <li key={r.name} className="text-slate-300">
                        {r.name}
                        <span className="text-xs text-slate-500">
                          {r.priority ? ` · ${r.priority}` : ""}
                          {dueText(r.due) ? ` · ${dueText(r.due)}` : ""}
                        </span>
                      </li>
                    ))}
                  </ul>
                )}
                {review.vcio.risks.length > 0 && (
                  <>
                    <p className="mb-1 mt-3 text-xs uppercase text-slate-500">Risks</p>
                    <ul className="space-y-1 text-sm" data-testid="vcio-risks">
                      {review.vcio.risks.map((k) => (
                        <li key={k.name} className="text-slate-300">
                          {k.name}
                          <span className="text-xs text-slate-500">
                            {k.score !== null ? ` · score ${k.score}` : ""}
                            {k.impact !== null && k.likelihood !== null ? ` (impact ${k.impact}, likelihood ${k.likelihood})` : ""}
                            {k.category ? ` · ${k.category}` : ""}
                          </span>
                        </li>
                      ))}
                    </ul>
                  </>
                )}
                <p className="mt-2 text-xs text-slate-500">Read from vCIO Toolbox on {new Date(review.vcio.refreshed_at).toLocaleDateString()}. The IT review answers themselves are not available through its API.</p>
              </Card>
            ) : null}

            <Card title="Alerts">
              <p className="text-sm text-slate-300" data-testid="alerts-line">
                {review.alerts.open} open ({review.alerts.critical_open} critical, {review.alerts.high_open} high). {review.alerts.opened_30d} raised and {review.alerts.closed_30d} closed in the last {review.window_days} days.
              </p>
            </Card>

            <Card title="Cases">
              <p className="text-sm text-slate-300" data-testid="cases-line">
                {review.cases.open} open. {review.cases.opened_30d} opened and {review.cases.resolved_30d} resolved in the last {review.window_days} days.
              </p>
            </Card>
          </div>
        </>
      )}
    </div>
  );
}
