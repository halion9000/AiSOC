'use client';

/**
 * AI Copilot — full-page experience.
 *
 * Two-column layout:
 *   left  — recent conversations + suggested prompts
 *   right — active conversation thread + composer
 *
 * Talks to `copilotApi`. If the request genuinely fails (not the backend's
 * own honest degraded-but-200 responses, which carry real content already)
 * this shows a plain, honest error - never fabricated analysis. Streaming
 * is preferred when available.
 */

import { useEffect, useRef, useState } from 'react';
import useSWR from 'swr';
import { clsx } from 'clsx';
import { motion, AnimatePresence } from 'framer-motion';
import {
  copilotApi,
  type CopilotConversation,
  type CopilotMessage,
} from '@/lib/api';
import { Skeleton } from '@/components/ui/Skeleton';

// ─── Suggested prompts ───────────────────────────────────────────────────────

const SUGGESTED_PROMPTS: Array<{ label: string; prompt: string }> = [
  {
    label: 'Top critical alerts',
    prompt: 'Summarize the top 5 critical alerts in the last 24 hours.',
  },
  {
    label: 'Investigate an entity',
    prompt:
      'Investigate host WIN-FIN-DB01: show recent alerts, related users, and ATT&CK techniques observed.',
  },
  {
    label: 'Explain an ATT&CK technique',
    prompt: 'Explain MITRE ATT&CK T1078 (Valid Accounts) and how we detect it.',
  },
  {
    label: 'Tune a noisy rule',
    prompt:
      'Show me the noisiest detection rules this week and recommend exceptions to reduce false positives.',
  },
  {
    label: 'MTTR by severity',
    prompt: 'What is our MTTR by severity over the last 30 days, and what is trending?',
  },
  {
    label: 'Threat intel match',
    prompt:
      'Has any indicator from the latest threat intel feed matched our telemetry in the last 7 days?',
  },
];

// ─── Offline fallback reply ──────────────────────────────────────────────────
//
// Hal, 2026-09-22, live: "the chat in aisoc still responds with random demo
// data" - traced to this function (formerly buildDemoReply), which the
// copilot.py rewrite and CopilotDock.tsx's own real-API wiring both missed
// entirely, since neither commit's message mentioned this file. It returned
// three keyword-matched, fully fabricated replies (a fake MTTR table, a fake
// T1078 coverage report, a fake host investigation naming a nonexistent user
// `j.harlow@aisoc.example`) - exactly the pattern removed everywhere else in
// the app tonight, just missed here. It fired on ANY error from the real
// copilotApi.chat() call, including one this component - unlike
// CopilotDock.tsx - never even checked for: a real, successful 200 response
// with `degraded: true` inside it (the backend's own honest "LLM unreachable"
// path) still went through `try` successfully and was never miscategorized,
// but a genuine failure (an auth error, a network drop) triggered fabricated
// security analysis instead of a plain, honest error. Replaced with the same
// pattern CopilotDock.tsx already uses: state what's actually true.
function offlineReply(prompt: string): CopilotMessage {
  return {
    id: `offline-${Date.now()}`,
    role: 'assistant',
    createdAt: new Date().toISOString(),
    content:
      'The AI backend is currently unreachable. Check that the AiSOC stack ' +
      'is running and that CORE\'s provider config is synced (rebuild AISOC ' +
      `from the HUD or run \`syncAisocProviderConfig()\`).\n\nYour query was: "${prompt}"`,
    suggestions: ['Retry', 'Open AISOC status'],
  };
}

// ─── Markdown-ish renderer (lightweight) ─────────────────────────────────────

function renderRichText(content: string): React.ReactNode {
  // Very small subset: **bold**, `code`, # headings, > blockquote, - lists,
  // and pipe tables. Good enough for assistant replies without pulling in
  // a full markdown library.
  const lines = content.split('\n');
  const blocks: React.ReactNode[] = [];
  let i = 0;

  const inline = (text: string): React.ReactNode => {
    const parts: React.ReactNode[] = [];
    const re = /(\*\*[^*]+\*\*|`[^`]+`)/g;
    let lastIndex = 0;
    let m: RegExpExecArray | null;
    while ((m = re.exec(text)) !== null) {
      if (m.index > lastIndex) parts.push(text.slice(lastIndex, m.index));
      const token = m[0];
      if (token.startsWith('**')) {
        parts.push(
          <strong key={`b-${m.index}`} className="font-semibold text-white">
            {token.slice(2, -2)}
          </strong>,
        );
      } else if (token.startsWith('`')) {
        parts.push(
          <code
            key={`c-${m.index}`}
            className="rounded bg-slate-800/80 px-1.5 py-0.5 font-mono text-[12px] text-emerald-300"
          >
            {token.slice(1, -1)}
          </code>,
        );
      }
      lastIndex = m.index + token.length;
    }
    if (lastIndex < text.length) parts.push(text.slice(lastIndex));
    return parts;
  };

  while (i < lines.length) {
    const line = lines[i];

    // Table: header | --- | rows
    if (line.includes('|') && lines[i + 1]?.match(/^\s*\|?\s*-/)) {
      const headerCells = line
        .split('|')
        .map((c) => c.trim())
        .filter(Boolean);
      i += 2;
      const rows: string[][] = [];
      while (i < lines.length && lines[i].includes('|')) {
        rows.push(
          lines[i]
            .split('|')
            .map((c) => c.trim())
            .filter(Boolean),
        );
        i++;
      }
      blocks.push(
        <div key={`tbl-${blocks.length}`} className="my-3 overflow-x-auto">
          <table className="w-full text-sm">
            <thead>
              <tr className="border-b border-slate-700/60">
                {headerCells.map((h, idx) => (
                  <th
                    key={idx}
                    className="px-3 py-2 text-left font-medium text-slate-300"
                  >
                    {inline(h)}
                  </th>
                ))}
              </tr>
            </thead>
            <tbody>
              {rows.map((r, rIdx) => (
                <tr key={rIdx} className="border-b border-slate-800/60 last:border-0">
                  {r.map((c, cIdx) => (
                    <td key={cIdx} className="px-3 py-2 text-slate-300">
                      {inline(c)}
                    </td>
                  ))}
                </tr>
              ))}
            </tbody>
          </table>
        </div>,
      );
      continue;
    }

    if (line.startsWith('# ')) {
      blocks.push(
        <h2 key={i} className="mt-3 text-lg font-semibold text-white">
          {inline(line.slice(2))}
        </h2>,
      );
      i++;
      continue;
    }

    if (line.startsWith('> ')) {
      blocks.push(
        <blockquote
          key={i}
          className="my-2 border-l-2 border-slate-600 pl-3 text-sm italic text-slate-400"
        >
          {inline(line.slice(2))}
        </blockquote>,
      );
      i++;
      continue;
    }

    if (line.match(/^\s*[-*]\s+/)) {
      const items: string[] = [];
      while (i < lines.length && lines[i].match(/^\s*[-*]\s+/)) {
        items.push(lines[i].replace(/^\s*[-*]\s+/, ''));
        i++;
      }
      blocks.push(
        <ul
          key={`ul-${blocks.length}`}
          className="my-2 list-disc space-y-1 pl-5 text-sm text-slate-300"
        >
          {items.map((it, idx) => (
            <li key={idx}>{inline(it)}</li>
          ))}
        </ul>,
      );
      continue;
    }

    if (line.match(/^\s*\d+\.\s+/)) {
      const items: string[] = [];
      while (i < lines.length && lines[i].match(/^\s*\d+\.\s+/)) {
        items.push(lines[i].replace(/^\s*\d+\.\s+/, ''));
        i++;
      }
      blocks.push(
        <ol
          key={`ol-${blocks.length}`}
          className="my-2 list-decimal space-y-1 pl-5 text-sm text-slate-300"
        >
          {items.map((it, idx) => (
            <li key={idx}>{inline(it)}</li>
          ))}
        </ol>,
      );
      continue;
    }

    if (line.trim() === '') {
      blocks.push(<div key={`sp-${i}`} className="h-2" />);
      i++;
      continue;
    }

    blocks.push(
      <p key={i} className="my-1 text-sm leading-relaxed text-slate-200">
        {inline(line)}
      </p>,
    );
    i++;
  }

  return <>{blocks}</>;
}

// ─── Component ───────────────────────────────────────────────────────────────

export function CopilotView() {
  const [messages, setMessages] = useState<CopilotMessage[]>([]);
  const [conversationId, setConversationId] = useState<string | undefined>();
  const [input, setInput] = useState('');
  const [sending, setSending] = useState(false);
  const [error, setError] = useState<unknown>(null);
  const scrollerRef = useRef<HTMLDivElement>(null);

  const conversationsState = useSWR(
    'copilot.conversations',
    () => copilotApi.listConversations(),
    { revalidateOnFocus: false, shouldRetryOnError: false },
  );
  const conversations: CopilotConversation[] =
    conversationsState.data?.conversations ?? [];

  // Auto-scroll thread to bottom on new messages.
  useEffect(() => {
    const el = scrollerRef.current;
    if (el) el.scrollTop = el.scrollHeight;
  }, [messages.length, sending]);

  const send = async (prompt: string) => {
    const trimmed = prompt.trim();
    if (!trimmed || sending) return;

    const userMsg: CopilotMessage = {
      id: `u-${Date.now()}`,
      role: 'user',
      content: trimmed,
      createdAt: new Date().toISOString(),
    };
    setMessages((prev) => [...prev, userMsg]);
    setInput('');
    setSending(true);
    setError(null);

    try {
      const res = await copilotApi.chat({
        conversationId,
        message: trimmed,
        context: { page: 'copilot' },
      });
      setConversationId(res.conversationId);
      setMessages((prev) => [...prev, res.reply]);
    } catch (err) {
      // Genuine failure only - the backend's own honest "LLM unreachable"
      // path already returns 200 with degraded:true and real content, so
      // this only fires for something actually wrong (auth, network).
      const fallback = offlineReply(trimmed);
      setMessages((prev) => [...prev, fallback]);
      setError(err);
    } finally {
      setSending(false);
    }
  };

  const onKeyDown = (e: React.KeyboardEvent<HTMLTextAreaElement>) => {
    if (e.key === 'Enter' && !e.shiftKey) {
      e.preventDefault();
      void send(input);
    }
  };

  const startNew = () => {
    setMessages([]);
    setConversationId(undefined);
    setError(null);
  };

  const empty = messages.length === 0;

  return (
    <div className="grid h-[calc(100vh-7rem)] grid-cols-1 gap-4 lg:grid-cols-[18rem_1fr]">
      {/* Sidebar */}
      <aside className="hidden flex-col gap-3 rounded-xl border border-slate-800/80 bg-slate-900/40 p-3 lg:flex">
        <button
          onClick={startNew}
          className="flex items-center justify-center gap-2 rounded-lg bg-emerald-500 px-3 py-2 text-sm font-semibold text-emerald-950 shadow-sm transition-colors hover:bg-emerald-400"
        >
          New chat
        </button>

        <div>
          <h3 className="mb-2 px-1 text-[11px] font-semibold uppercase tracking-wider text-slate-500">
            Suggested
          </h3>
          <ul className="space-y-1">
            {SUGGESTED_PROMPTS.slice(0, 4).map((p) => (
              <li key={p.label}>
                <button
                  onClick={() => void send(p.prompt)}
                  className="group flex w-full items-start gap-2 rounded-md px-2 py-2 text-left text-sm text-slate-300 transition-colors hover:bg-slate-800/60 hover:text-white"
                >
                  <span className="leading-tight">{p.label}</span>
                </button>
              </li>
            ))}
          </ul>
        </div>

        <div className="mt-2 flex-1 overflow-y-auto">
          <h3 className="mb-2 px-1 text-[11px] font-semibold uppercase tracking-wider text-slate-500">
            Recent
          </h3>
          {conversationsState.isLoading ? (
            <div className="space-y-2 px-1">
              <Skeleton className="h-8" />
              <Skeleton className="h-8" />
              <Skeleton className="h-8" />
            </div>
          ) : conversations.length === 0 ? (
            <p className="px-2 text-xs text-slate-500">
              Past conversations will appear here.
            </p>
          ) : (
            <ul className="space-y-1">
              {conversations.slice(0, 8).map((c) => (
                <li key={c.id}>
                  <button
                    className={clsx(
                      'block w-full truncate rounded-md px-2 py-1.5 text-left text-sm transition-colors',
                      c.id === conversationId
                        ? 'bg-slate-800 text-white'
                        : 'text-slate-300 hover:bg-slate-800/60',
                    )}
                    onClick={() => setConversationId(c.id)}
                    title={c.title}
                  >
                    {c.title}
                  </button>
                </li>
              ))}
            </ul>
          )}
        </div>
      </aside>

      {/* Chat panel */}
      <section className="flex min-h-0 flex-col rounded-xl border border-slate-800/80 bg-slate-900/40">
        {/* Header */}
        <div className="flex items-center justify-between border-b border-slate-800/80 px-4 py-3">
          <div>
            <h1 className="text-base font-semibold text-white">AI Copilot</h1>
            <p className="text-xs text-slate-400">
              Ask about alerts, hosts, MITRE techniques, or your detection
              coverage.
            </p>
          </div>
          <div className="flex items-center gap-2 text-xs text-slate-400">
            <span
              className={clsx(
                'inline-block h-2 w-2 rounded-full',
                error ? 'bg-amber-400' : 'bg-emerald-400',
              )}
            />
            {error ? 'Offline' : 'Connected'}
          </div>
        </div>

        {/* Thread */}
        <div ref={scrollerRef} className="min-h-0 flex-1 overflow-y-auto p-4">
          {empty ? (
            <div className="mx-auto flex h-full max-w-2xl flex-col items-center justify-center text-center">
              <h2 className="text-lg font-semibold text-white">
                Copilot
              </h2>
              <p className="mt-1 max-w-md text-sm text-slate-400">
                Ask about alerts, hosts, MITRE techniques, or detection
                coverage. Cite an alert ID, hostname, or technique to scope
                the answer.
              </p>
              <div className="mt-6 grid w-full max-w-2xl grid-cols-1 gap-2 sm:grid-cols-2">
                {SUGGESTED_PROMPTS.map((p) => (
                  <button
                    key={p.label}
                    onClick={() => void send(p.prompt)}
                    className="flex items-start gap-3 rounded-lg border border-slate-800/80 bg-slate-900/60 p-3 text-left transition-colors hover:border-emerald-500/40 hover:bg-slate-800/60"
                  >
                    <span>
                      <span className="block text-sm font-medium text-white">
                        {p.label}
                      </span>
                      <span className="block text-xs text-slate-400">
                        {p.prompt}
                      </span>
                    </span>
                  </button>
                ))}
              </div>
            </div>
          ) : (
            <ul className="mx-auto max-w-3xl space-y-4">
              <AnimatePresence initial={false}>
                {messages.map((m) => (
                  <motion.li
                    key={m.id}
                    initial={{ opacity: 0, y: 8 }}
                    animate={{ opacity: 1, y: 0 }}
                    exit={{ opacity: 0 }}
                    className={clsx(
                      'flex gap-3',
                      m.role === 'user' ? 'justify-end' : 'justify-start',
                    )}
                  >
                    {m.role === 'assistant' && (
                      <div className="flex h-8 w-8 flex-none items-center justify-center rounded-full bg-emerald-500/15 text-[10px] font-semibold uppercase tracking-wider text-emerald-300">
                        ai
                      </div>
                    )}
                    <div
                      className={clsx(
                        'max-w-[85%] rounded-2xl px-4 py-3 shadow-sm',
                        m.role === 'user'
                          ? 'bg-emerald-500/15 text-white ring-1 ring-emerald-500/30'
                          : 'bg-slate-800/70 text-slate-100 ring-1 ring-slate-700/60',
                      )}
                    >
                      {m.role === 'assistant' ? (
                        renderRichText(m.content)
                      ) : (
                        <p className="whitespace-pre-wrap text-sm text-slate-100">
                          {m.content}
                        </p>
                      )}

                      {m.citations && m.citations.length > 0 && (
                        <div className="mt-3 flex flex-wrap gap-1.5">
                          {m.citations.map((c, idx) => (
                            <span
                              key={idx}
                              className="inline-flex items-center gap-1 rounded-full border border-slate-700/70 bg-slate-900/60 px-2 py-0.5 text-[11px] text-slate-300"
                            >
                              <span className="text-slate-500">
                                {c.kind ?? 'ref'}:
                              </span>
                              {c.label}
                            </span>
                          ))}
                        </div>
                      )}

                      {m.suggestions && m.suggestions.length > 0 && (
                        <div className="mt-3 flex flex-wrap gap-2">
                          {m.suggestions.map((s, idx) => (
                            <button
                              key={idx}
                              onClick={() => void send(s)}
                              className="rounded-full border border-emerald-500/30 bg-emerald-500/10 px-3 py-1 text-xs text-emerald-200 transition-colors hover:bg-emerald-500/20"
                            >
                              {s}
                            </button>
                          ))}
                        </div>
                      )}
                    </div>
                    {m.role === 'user' && (
                      <div className="flex h-8 w-8 flex-none items-center justify-center rounded-full bg-slate-700 text-xs font-semibold text-slate-200">
                        You
                      </div>
                    )}
                  </motion.li>
                ))}
              </AnimatePresence>
              {sending && (
                <li className="flex justify-start gap-3">
                  <div className="flex h-8 w-8 flex-none items-center justify-center rounded-full bg-emerald-500/15 text-[10px] font-semibold uppercase tracking-wider text-emerald-300">
                    ai
                  </div>
                  <div className="rounded-2xl bg-slate-800/70 px-4 py-3 ring-1 ring-slate-700/60">
                    <TypingDots />
                  </div>
                </li>
              )}
            </ul>
          )}
        </div>

        {/* Composer */}
        <div className="border-t border-slate-800/80 p-3">
          <div className="mx-auto flex max-w-3xl items-end gap-2 rounded-xl border border-slate-700/70 bg-slate-950/40 p-2 focus-within:border-emerald-500/50">
            <textarea
              value={input}
              onChange={(e) => setInput(e.target.value)}
              onKeyDown={onKeyDown}
              rows={1}
              placeholder="Ask anything — try 'investigate WIN-FIN-DB01'…"
              className="flex-1 resize-none bg-transparent px-2 py-2 text-sm text-slate-100 placeholder-slate-500 outline-none"
            />
            <button
              onClick={() => void send(input)}
              disabled={!input.trim() || sending}
              className={clsx(
                'flex-none rounded-lg px-3 py-2 text-sm font-semibold transition-colors',
                input.trim() && !sending
                  ? 'bg-emerald-500 text-emerald-950 hover:bg-emerald-400'
                  : 'bg-slate-800 text-slate-500',
              )}
            >
              {sending ? '…' : 'Send'}
            </button>
          </div>
          <p className="mx-auto mt-1.5 max-w-3xl px-1 text-[11px] text-slate-500">
            Press <kbd className="rounded bg-slate-800 px-1">Enter</kbd> to
            send,{' '}
            <kbd className="rounded bg-slate-800 px-1">Shift</kbd>+
            <kbd className="rounded bg-slate-800 px-1">Enter</kbd> for newline.
            Responses can include actions you can run from inside the chat.
          </p>
        </div>
      </section>
    </div>
  );
}

function TypingDots() {
  return (
    <span className="inline-flex items-center gap-1" aria-label="Assistant is typing">
      {[0, 1, 2].map((i) => (
        <motion.span
          key={i}
          className="block h-1.5 w-1.5 rounded-full bg-slate-400"
          animate={{ opacity: [0.2, 1, 0.2] }}
          transition={{ duration: 1.1, repeat: Infinity, delay: i * 0.18 }}
        />
      ))}
    </span>
  );
}
