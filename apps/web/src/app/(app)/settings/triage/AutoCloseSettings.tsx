"use client";

/**
 * How sure AI triage must be before it closes an alert by itself.
 *
 * Only benign and false-positive verdicts can close on their own (a true positive or "needs review" always goes to a person), and only at or above this confidence.
 * Backed by /api/v1/tenant-settings/auto-close: a tenant's own value, or none, in which case the platform's value applies.
 */
import { useCallback, useEffect, useState } from "react";

import { apiErrorDetail } from "@/lib/api";
import { authFetch } from "@/lib/auth-session";

interface Setting {
  threshold: number | null;
  minimum: number;
  maximum: number;
}

const URL = "/api/v1/tenant-settings/auto-close";

export function AutoCloseSettings() {
  const [setting, setSetting] = useState<Setting | null>(null);
  const [draft, setDraft] = useState("");
  const [message, setMessage] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  const load = useCallback(async () => {
    try {
      const res = await authFetch(URL);
      if (!res.ok) throw new Error(`The API answered ${res.status}`);
      const s = (await res.json()) as Setting;
      setSetting(s);
      setDraft(s.threshold === null ? "" : String(s.threshold));
      setError(null);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Could not load the setting");
    }
  }, []);

  useEffect(() => {
    void load();
  }, [load]);

  async function call(method: "PUT" | "DELETE", body?: unknown, done?: string) {
    setBusy(true);
    setMessage(null);
    setError(null);
    try {
      const res = await authFetch(URL, { method, headers: { "Content-Type": "application/json" }, ...(body !== undefined ? { body: JSON.stringify(body) } : {}) });
      if (!res.ok) {
        const text = await res.text().catch(() => "");
        throw new Error(apiErrorDetail(Object.assign(new Error("refused"), { body: text }) as never) ?? `The API answered ${res.status}`);
      }
      const s = (await res.json()) as Setting;
      setSetting((prev) => (prev ? { ...prev, threshold: s.threshold } : prev));
      setDraft(s.threshold === null ? "" : String(s.threshold));
      setMessage(done ?? "Saved.");
    } catch (err) {
      setError(err instanceof Error ? err.message : "Could not save");
    } finally {
      setBusy(false);
    }
  }

  const min = setting?.minimum ?? 0.5;
  const max = setting?.maximum ?? 1;
  const value = Number(draft);
  const valid = draft.trim() !== "" && Number.isFinite(value) && value >= min && value <= max;

  return (
    <div className="mx-auto max-w-2xl space-y-4 p-6">
      <h1 className="text-xl font-semibold">Auto-close</h1>
      <p className="text-sm text-gray-400">
        AI triage closes an alert on its own only when it judges it benign or a false positive <em>and</em> its confidence is at or above this number. A true positive or an alert needing review always goes to a person. A higher number closes fewer alerts
        on its own.
      </p>

      {error && (
        <p role="alert" className="rounded border border-red-500/40 bg-red-500/10 p-3 text-sm text-red-300">
          {error}
        </p>
      )}

      {setting && (
        <>
          <p data-testid="current" className="text-sm text-gray-300">
            {setting.threshold === null ? "This tenant follows the platform value." : `This tenant closes at confidence ${setting.threshold} or above.`}
          </p>
          <div className="flex items-end gap-3">
            <label className="text-sm">
              <span className="block text-gray-400 mb-1">
                Confidence ({min} to {max})
              </span>
              <input
                aria-label="Auto-close confidence"
                type="number"
                step="0.01"
                min={min}
                max={max}
                value={draft}
                onChange={(e) => setDraft(e.target.value)}
                className="w-28 rounded border border-gray-700 bg-gray-900 px-2 py-1.5 text-gray-100"
              />
            </label>
            <button
              type="button"
              disabled={busy || !valid}
              onClick={() => void call("PUT", { threshold: value }, "Saved. It applies to this tenant's alerts within a minute.")}
              className="rounded bg-blue-600 px-3 py-2 text-sm text-white disabled:opacity-50"
            >
              Save
            </button>
            <button
              type="button"
              disabled={busy || setting.threshold === null}
              onClick={() => void call("DELETE", undefined, "Back to the platform value.")}
              className="rounded border border-gray-700 px-3 py-2 text-sm text-gray-300 disabled:opacity-50"
            >
              Use the platform value
            </button>
          </div>
          {draft.trim() !== "" && !valid && (
            <p role="note" className="text-xs text-yellow-300">
              Enter a number from {min} to {max}.
            </p>
          )}
          {message && <p className="text-sm text-emerald-400">{message}</p>}
        </>
      )}
    </div>
  );
}
