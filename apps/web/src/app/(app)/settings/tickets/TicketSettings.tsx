"use client";

/**
 * Which HaloPSA ticket status a resolved incident moves its ticket to.
 *
 * Resolving a Huntress incident from an alert makes CORE leave a note on the incident's ticket and set the ticket to this status. The name must match a status in HaloPSA exactly (capitals do not
 * matter); if HaloPSA has no such status CORE says so and leaves the ticket alone. Backed by /api/v1/tenant-settings/tickets.
 */
import { useCallback, useEffect, useState } from "react";

import { apiErrorDetail } from "@/lib/api";
import { authFetch } from "@/lib/auth-session";

interface Setting {
  close_status: string;
  is_default: boolean;
  default: string;
}

const URL = "/api/v1/tenant-settings/tickets";

export function TicketSettings() {
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
      setDraft(s.close_status);
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
      setSetting(s);
      setDraft(s.close_status);
      setMessage(done ?? "Saved.");
    } catch (err) {
      setError(err instanceof Error ? err.message : "Could not save");
    } finally {
      setBusy(false);
    }
  }

  const valid = draft.trim() !== "" && draft.trim().length <= 60;

  return (
    <div className="mx-auto max-w-2xl space-y-4 p-6">
      <h1 className="text-xl font-semibold">Tickets</h1>
      <p className="text-sm text-gray-400">
        When you resolve a Huntress incident from an alert, CORE adds a private note to the HaloPSA ticket Huntress opened and moves the ticket to the status below. Approving or rejecting a remediation only adds a note.
      </p>

      {error && (
        <p role="alert" className="rounded border border-red-500/40 bg-red-500/10 p-3 text-sm text-red-300">
          {error}
        </p>
      )}

      {setting && (
        <>
          <p data-testid="current" className="text-sm text-gray-300">
            {setting.is_default ? `Resolved incidents move their ticket to "${setting.close_status}" (the default).` : `Resolved incidents move their ticket to "${setting.close_status}".`}
          </p>
          <div className="flex items-end gap-3">
            <label className="text-sm">
              <span className="mb-1 block text-gray-400">Ticket status in HaloPSA</span>
              <input
                aria-label="Ticket status"
                type="text"
                maxLength={60}
                value={draft}
                onChange={(e) => setDraft(e.target.value)}
                className="w-64 rounded border border-gray-700 bg-gray-900 px-2 py-1.5 text-gray-100"
              />
            </label>
            <button
              type="button"
              disabled={busy || !valid}
              onClick={() => void call("PUT", { close_status: draft.trim() }, "Saved. It applies to the next incident you resolve.")}
              className="rounded bg-blue-600 px-3 py-1.5 text-sm text-white disabled:opacity-50"
            >
              Save
            </button>
            {!setting.is_default && (
              <button type="button" disabled={busy} onClick={() => void call("DELETE", undefined, `Back to the default, "${setting.default}".`)} className="rounded border border-gray-700 px-3 py-1.5 text-sm text-gray-300 disabled:opacity-50">
                Use the default
              </button>
            )}
          </div>
          {message && (
            <p role="status" className="text-sm text-emerald-300">
              {message}
            </p>
          )}
        </>
      )}
    </div>
  );
}
