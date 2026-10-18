'use client';

/**
 * One compliance framework: which controls have accepted evidence, which are waiting for a review, and which have none.
 *
 * Backed by /api/v1/compliance/{frameworks/<key>/controls, report, evidence, evidence/collect}. "Collect platform evidence" records what the platform's own
 * data can show (accounts, monitoring coverage, incident handling) as PENDING items; a person reviews each one here. Controls that need a document or an
 * attestation stay "No evidence" until someone adds one: nothing is filled in on anyone's behalf.
 */
import { useCallback, useEffect, useState } from 'react';

import { authFetch } from '@/lib/auth-session';

interface Props {
  framework: string;
}

/** The URL ids on the Compliance page, and the framework keys the API knows them by. */
const API_KEYS: Record<string, string> = {
  soc2: 'SOC2',
  iso27001: 'ISO27001',
  nist_csf: 'NIST-CSF',
  pci_dss: 'PCI-DSS',
  hipaa: 'HIPAA',
  dora: 'DORA',
};

interface Control {
  control_id: string;
  title: string;
}
interface Posture {
  total_evidence: number;
  accepted: number;
  pending: number;
  rejected: number;
  coverage_pct: number;
  controls_covered: string[];
  controls_missing: string[];
}
interface Evidence {
  id: string;
  control_id: string;
  summary: string;
  status: 'pending' | 'accepted' | 'rejected';
  collected_at: string;
  reviewed_by: string | null;
}

const STATUS_TEXT: Record<string, string> = { accepted: 'text-emerald-400', pending: 'text-yellow-400', rejected: 'text-red-400' };

async function getJson<T>(path: string): Promise<T> {
  const res = await authFetch(path);
  if (!res.ok) throw new Error(`The API answered ${res.status}`);
  return (await res.json()) as T;
}

export function FrameworkView({ framework }: Props) {
  const key = API_KEYS[framework];
  const [controls, setControls] = useState<Control[]>([]);
  const [posture, setPosture] = useState<Posture | null>(null);
  const [evidence, setEvidence] = useState<Evidence[]>([]);
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const [note, setNote] = useState<string | null>(null);

  const load = useCallback(async () => {
    if (!key) return;
    try {
      const [c, r, e] = await Promise.all([
        getJson<{ controls: Control[] }>(`/api/v1/compliance/frameworks/${encodeURIComponent(key)}/controls`),
        getJson<Posture[]>(`/api/v1/compliance/report?framework=${encodeURIComponent(key)}`),
        getJson<Evidence[]>(`/api/v1/compliance/evidence?framework=${encodeURIComponent(key)}&limit=200`),
      ]);
      setControls(c.controls);
      setPosture(r[0] ?? null);
      setEvidence(e);
      setError(null);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Could not load this framework');
    }
  }, [key]);

  useEffect(() => {
    void load();
  }, [load]);

  if (!key) {
    return (
      <div className="p-8 text-center space-y-2">
        <h2 className="text-lg font-semibold text-gray-200">{framework.toUpperCase()} Compliance</h2>
        <p className="text-sm text-gray-400 max-w-xl mx-auto">This framework has no control list in this AiSOC build, so there is nothing to collect evidence against yet.</p>
      </div>
    );
  }

  async function collect() {
    setBusy(true);
    setNote(null);
    try {
      const res = await authFetch('/api/v1/compliance/evidence/collect', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ framework: key, scope: 'full' }),
      });
      if (!res.ok) throw new Error(`The API answered ${res.status}`);
      const out = (await res.json()) as { collected: number };
      setNote(out.collected > 0 ? `Recorded ${out.collected} item(s) for review.` : 'The platform has no data of its own to evidence for this framework; add evidence for each control yourself.');
      await load();
    } catch (err) {
      setNote(err instanceof Error ? err.message : 'Collection failed');
    } finally {
      setBusy(false);
    }
  }

  async function review(id: string, decision: 'accepted' | 'rejected') {
    try {
      const res = await authFetch(`/api/v1/compliance/evidence/${encodeURIComponent(id)}/review`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ decision }),
      });
      if (!res.ok) throw new Error(`The API answered ${res.status}`);
      await load();
    } catch (err) {
      setNote(err instanceof Error ? err.message : 'Review failed');
    }
  }

  const evidenceFor = (id: string) => evidence.filter((e) => e.control_id === id);
  const controlState = (id: string): 'accepted' | 'pending' | 'rejected' | 'none' => {
    const items = evidenceFor(id);
    if (items.some((e) => e.status === 'accepted')) return 'accepted';
    if (items.some((e) => e.status === 'pending')) return 'pending';
    if (items.some((e) => e.status === 'rejected')) return 'rejected';
    return 'none';
  };

  return (
    <div className="space-y-6">
      <div className="flex items-start justify-between gap-4">
        <div>
          <h2 className="text-xl font-semibold text-gray-100">{key} compliance</h2>
          {posture && (
            <p className="text-sm text-gray-400 mt-1" data-testid="coverage">
              {posture.coverage_pct.toFixed(0)}% of controls have accepted evidence ({posture.accepted} accepted, {posture.pending} waiting for review, {posture.rejected} rejected)
            </p>
          )}
        </div>
        <button
          type="button"
          onClick={() => void collect()}
          disabled={busy}
          className="px-3 py-2 rounded bg-blue-600 text-white text-sm disabled:opacity-50"
        >
          {busy ? 'Collecting...' : 'Collect platform evidence'}
        </button>
      </div>

      {note && <p className="text-sm text-gray-300">{note}</p>}
      {error && (
        <p role="alert" className="rounded border border-red-500/40 bg-red-500/10 p-3 text-sm text-red-300">
          {error}
        </p>
      )}

      <div className="space-y-3">
        {controls.map((c) => {
          const state = controlState(c.control_id);
          return (
            <div key={c.control_id} className="rounded-lg border border-gray-700 bg-gray-800/60 p-4">
              <div className="flex items-baseline justify-between gap-3">
                <div>
                  <span className="font-mono text-sm text-gray-200">{c.control_id}</span>
                  <span className="ml-2 text-sm text-gray-400">{c.title}</span>
                </div>
                <span className={`text-xs ${STATUS_TEXT[state] ?? 'text-gray-500'}`}>{state === 'none' ? 'No evidence' : state}</span>
              </div>
              {evidenceFor(c.control_id).map((e) => (
                <div key={e.id} className="mt-3 flex items-start justify-between gap-3 border-t border-gray-700/60 pt-3">
                  <p className="text-sm text-gray-300">
                    {e.summary}
                    <span className="block text-xs text-gray-500 mt-1">
                      {new Date(e.collected_at).toLocaleString()} · <span className={STATUS_TEXT[e.status]}>{e.status}</span>
                      {e.reviewed_by ? ` by ${e.reviewed_by}` : ''}
                    </span>
                  </p>
                  {e.status === 'pending' && (
                    <span className="flex shrink-0 gap-2">
                      <button type="button" onClick={() => void review(e.id, 'accepted')} className="px-2 py-1 rounded bg-emerald-700 text-white text-xs">
                        Accept
                      </button>
                      <button type="button" onClick={() => void review(e.id, 'rejected')} className="px-2 py-1 rounded bg-red-800 text-white text-xs">
                        Reject
                      </button>
                    </span>
                  )}
                </div>
              ))}
            </div>
          );
        })}
      </div>
    </div>
  );
}
