"use client";

/**
 * Type an answer or a note into one question of the client review. A status (and, for the technology questions, an answer) replaces what A.C.O.R.N worked out, which stays visible as "Suggested";
 * a note alone changes no answer; "Back to automatic" removes both. Backed by PUT /api/v1/client-review/{client}/answers. Hidden when printing.
 */
import { useState } from "react";

import { authFetch } from "@/lib/auth-session";

export type Section = "readiness" | "tech" | "m365";

const OPTIONS: Record<Section, { value: string; label: string }[]> = {
  readiness: [
    { value: "met", label: "Met" },
    { value: "partly", label: "Partly" },
    { value: "not_met", label: "Not met" },
    { value: "unknown", label: "Not known" },
  ],
  tech: [
    { value: "seen", label: "In use (answer below)" },
    { value: "not_seen", label: "None in use" },
    { value: "unknown", label: "Ask the client" },
  ],
  m365: [
    { value: "met", label: "Met" },
    { value: "partly", label: "Partly" },
    { value: "not_met", label: "Not met" },
    { value: "needs_person", label: "Needs a person" },
  ],
};

export interface Typed {
  manual?: boolean;
  note?: string | null;
}

interface Props {
  clientId: string;
  section: Section;
  /** The question's key (the question text for the Microsoft 365 list). */
  questionKey: string;
  /** The status now shown, and the answer now shown (technology questions). */
  status: string;
  answer?: string | null;
  note?: string | null;
  manual?: boolean;
  onSaved: () => void;
}

export async function saveAnswer(clientId: string, body: { section: Section; key: string; status?: string | null; answer?: string | null; note?: string | null }): Promise<void> {
  const res = await authFetch(`/api/v1/client-review/${encodeURIComponent(clientId)}/answers`, {
    method: "PUT",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(body),
  });
  if (!res.ok) {
    let detail = "";
    try {
      detail = ((await res.json()) as { detail?: string }).detail ?? "";
    } catch {
      /* no body */
    }
    throw new Error(detail || `The API answered ${res.status}`);
  }
}

export function AnswerEditor({ clientId, section, questionKey, status, answer, note, manual, onSaved }: Props) {
  const [open, setOpen] = useState(false);
  const [state, setState] = useState(manual ? status : "");
  const [text, setText] = useState(manual ? (answer ?? "") : "");
  const [memo, setMemo] = useState(note ?? "");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const run = async (body: { status: string | null; answer: string | null; note: string | null }) => {
    setBusy(true);
    setError(null);
    try {
      await saveAnswer(clientId, { section, key: questionKey, ...body });
      setOpen(false);
      onSaved();
    } catch (e) {
      setError(e instanceof Error ? e.message : "Could not save");
    } finally {
      setBusy(false);
    }
  };

  if (!open) {
    return (
      <button
        type="button"
        onClick={() => {
          setState(manual ? status : "");
          setText(manual ? (answer ?? "") : "");
          setMemo(note ?? "");
          setOpen(true);
        }}
        className="rounded border border-slate-700 px-2 py-0.5 text-[11px] text-slate-300 hover:bg-slate-800 print:hidden"
        aria-label={`Edit the answer to: ${questionKey}`}
      >
        {note || manual ? "Edit" : "Answer / note"}
      </button>
    );
  }

  return (
    <div className="mt-2 space-y-2 rounded border border-slate-700 bg-slate-900/60 p-3 print:hidden" role="group" aria-label="Edit this answer">
      <label className="block text-xs text-slate-400">
        Answer
        <select value={state} onChange={(e) => setState(e.target.value)} className="mt-1 block w-full rounded border border-slate-700 bg-slate-950 px-2 py-1 text-sm text-slate-100">
          <option value="">Leave as A.C.O.R.N worked it out</option>
          {OPTIONS[section].map((o) => (
            <option key={o.value} value={o.value}>
              {o.label}
            </option>
          ))}
        </select>
      </label>
      {section === "tech" && (
        <label className="block text-xs text-slate-400">
          What is in use
          <input
            value={text}
            maxLength={300}
            onChange={(e) => setText(e.target.value)}
            placeholder="e.g. Fortinet 60F"
            className="mt-1 block w-full rounded border border-slate-700 bg-slate-950 px-2 py-1 text-sm text-slate-100 placeholder:text-slate-500"
          />
        </label>
      )}
      <label className="block text-xs text-slate-400">
        Note
        <textarea
          value={memo}
          maxLength={4000}
          rows={3}
          onChange={(e) => setMemo(e.target.value)}
          placeholder="Where this came from, or anything the reader should know"
          className="mt-1 block w-full rounded border border-slate-700 bg-slate-950 px-2 py-1 text-sm text-slate-100 placeholder:text-slate-500"
        />
      </label>
      {error && (
        <p role="alert" className="text-xs text-red-300">
          {error}
        </p>
      )}
      <div className="flex flex-wrap gap-2">
        <button
          type="button"
          disabled={busy}
          onClick={() => void run({ status: state || null, answer: section === "tech" && text.trim() ? text.trim() : null, note: memo.trim() || null })}
          className="rounded bg-blue-600 px-3 py-1 text-xs font-medium text-white hover:bg-blue-500 disabled:opacity-50"
        >
          Save
        </button>
        <button type="button" disabled={busy} onClick={() => void run({ status: null, answer: null, note: null })} className="rounded border border-slate-600 px-3 py-1 text-xs text-slate-200 hover:bg-slate-800 disabled:opacity-50">
          Back to automatic (clears the note too)
        </button>
        <button type="button" disabled={busy} onClick={() => setOpen(false)} className="rounded px-3 py-1 text-xs text-slate-400 hover:bg-slate-800">
          Cancel
        </button>
      </div>
    </div>
  );
}

/** The marks under a question: that its answer was typed (and what A.C.O.R.N had worked out), and the note. These print. */
export function AnswerMarks({ manual, note, suggested }: { manual?: boolean; note?: string | null; suggested?: string | null }) {
  if (!manual && !note) return null;
  return (
    <span className="mt-1 block text-xs">
      {manual && (
        <span className="mr-2 rounded bg-sky-500/15 px-1.5 py-0.5 text-[11px] text-sky-300" data-testid="typed-mark">
          Typed{suggested ? ` (A.C.O.R.N suggested: ${suggested})` : ""}
        </span>
      )}
      {note && (
        <span className="whitespace-pre-wrap italic text-slate-300" data-testid="answer-note">
          Note: {note}
        </span>
      )}
    </span>
  );
}
