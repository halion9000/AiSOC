"use client";

/**
 * The e-mail and DNS posture of the domains a client's people use: SPF, DMARC, DKIM and where mail goes. Looked up in public DNS when the page opens (nothing is stored).
 * Backed by GET /api/v1/client-posture/{client_id}/domains. An older API without the route shows nothing.
 */
import { useEffect, useState } from "react";

import { authFetch } from "@/lib/auth-session";

type Status = "good" | "needs_work" | "missing";
interface Finding {
  status: Status;
  summary: string;
  record?: string | null;
}
export interface DomainPosture {
  domain: string;
  status: Status;
  mx: string[];
  mail_provider: string | null;
  spf: Finding;
  dmarc: Finding;
  dkim: Finding;
  /** What the domain's website shows; absent when no website answered (normal for a mail-only domain) or from an older API. */
  web?: { certificate: Finding; https_redirect: Finding; headers: Finding } | null;
}

const LABEL: Record<Status, { text: string; className: string }> = {
  good: { text: "Good", className: "text-emerald-300" },
  needs_work: { text: "Needs work", className: "text-amber-300" },
  missing: { text: "Missing", className: "text-red-300" },
};

function Check({ name, f }: { name: string; f: Finding }) {
  const l = LABEL[f.status];
  return (
    <div className="rounded border border-slate-800 p-2" data-testid={`check-${name}`}>
      <div className="text-xs uppercase text-slate-500">{name}</div>
      <div className={`text-sm font-medium ${l.className}`}>{l.text}</div>
      <div className="mt-1 text-xs text-slate-400">{f.summary}</div>
      {f.record && <code className="mt-1 block break-all text-[11px] text-slate-500">{f.record}</code>}
    </div>
  );
}

export function DomainChecks({ clientId }: { clientId: string }) {
  const [domains, setDomains] = useState<DomainPosture[] | null>(null);

  useEffect(() => {
    let live = true;
    setDomains(null);
    authFetch(`/api/v1/client-posture/${encodeURIComponent(clientId)}/domains`)
      .then(async (res) => (res.ok ? ((await res.json()) as { domains?: unknown }) : null))
      .then((body) => {
        if (live) setDomains(Array.isArray(body?.domains) ? (body.domains as DomainPosture[]) : []);
      })
      .catch(() => {
        if (live) setDomains([]);
      });
    return () => {
      live = false;
    };
  }, [clientId]);

  if (domains === null) return <p className="text-sm text-slate-500">Checking the client&apos;s domains…</p>;
  return (
    <section data-testid="domain-checks">
      <h3 className="mb-2 text-sm uppercase text-slate-500">E-mail and website checks for the client&apos;s domains</h3>
      {domains.length === 0 ? (
        <p className="text-sm text-slate-400" data-testid="no-domains">
          No domains to check yet. They come from the e-mail addresses of this client&apos;s people (the Identities page), so they appear once those are loaded.
        </p>
      ) : (
        <div className="space-y-3">
          {domains.map((d) => (
            <div key={d.domain} className="rounded border border-slate-800 p-3">
              <div className="mb-2 flex flex-wrap items-baseline gap-x-3">
                <span className="font-medium text-slate-100">{d.domain}</span>
                <span className={`text-sm ${LABEL[d.status].className}`}>{LABEL[d.status].text}</span>
                <span className="text-xs text-slate-500">{d.mail_provider ? `Mail: ${d.mail_provider}` : d.mx.length > 0 ? `Mail: ${d.mx[0]}` : "No mail server (MX) published"}</span>
              </div>
              <div className="grid gap-2 md:grid-cols-3">
                <Check name="SPF" f={d.spf} />
                <Check name="DMARC" f={d.dmarc} />
                <Check name="DKIM" f={d.dkim} />
              </div>
              {d.web && (
                <div className="mt-2 grid gap-2 md:grid-cols-3" data-testid={`web-${d.domain}`}>
                  <Check name="Certificate" f={d.web.certificate} />
                  <Check name="HTTP to HTTPS" f={d.web.https_redirect} />
                  <Check name="Security headers" f={d.web.headers} />
                </div>
              )}
            </div>
          ))}
        </div>
      )}
    </section>
  );
}
