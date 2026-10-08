'use client';

/**
 * LiveFeedPanel
 *
 * Subscribes to the realtime `alerts` channel and renders the most recent
 * fused alerts as a live-streaming list. It only ever shows events that really
 * arrived: if the realtime service is unreachable, or nothing has happened yet,
 * the list is empty and the pill says which of those it is. (It used to label
 * an empty list "Demo" with a tooltip claiming it was "showing demo data", which
 * was never true.)
 *
 * The status pill reflects the actual WebSocket state:
 *   - "Live"          → connected and receiving
 *   - "Waiting"       → connected, no event has arrived yet
 *   - "Connecting…"   → opening the connection
 *   - "Reconnecting…" → the connection dropped after events were received
 *   - "Offline"       → the realtime service is unreachable
 */

import { useEffect, useRef, useState } from 'react';
import clsx from 'clsx';
import { useRealtimeChannel, type RealtimeStatus } from '@/lib/realtime';

type Severity = 'critical' | 'high' | 'medium' | 'low' | 'info';

interface LiveEvent {
  id: string;
  severity: Severity;
  text: string;
  source: string;
  receivedAt: number; // epoch ms
}

/**
 * Loose shape of the message broadcast by `services/realtime`. The realtime
 * service forwards Kafka messages from `aisoc.alerts.fused` so the inner
 * `payload` may carry either the full envelope or the unwrapped alert.
 */
interface RealtimeAlertMessage {
  type?: string;
  timestamp?: string;
  payload?: {
    alert?: AlertLike;
    tenant_id?: string;
    severity?: string;
    title?: string;
    description?: string;
    source?: string;
    source_system?: string;
  } & AlertLike;
}

interface AlertLike {
  id?: string;
  severity?: string;
  title?: string;
  description?: string;
  source?: string;
  source_system?: string;
}

const SEVERITY_COLORS: Record<Severity, string> = {
  critical: 'bg-red-500/20 text-red-300 border border-red-500/30',
  high: 'bg-orange-500/20 text-orange-300 border border-orange-500/30',
  medium: 'bg-yellow-500/20 text-yellow-300 border border-yellow-500/30',
  low: 'bg-blue-500/20 text-blue-300 border border-blue-500/30',
  info: 'bg-gray-500/20 text-gray-300 border border-gray-500/30',
};


const MAX_VISIBLE = 12;

function normalizeSeverity(value: unknown): Severity {
  const v = String(value ?? '').toLowerCase();
  if (v === 'critical' || v === 'high' || v === 'medium' || v === 'low' || v === 'info') {
    return v;
  }
  return 'info';
}

function relativeTime(receivedAt: number, now: number): string {
  const diff = Math.max(0, Math.floor((now - receivedAt) / 1000));
  if (diff < 1) return 'just now';
  if (diff < 60) return `${diff}s ago`;
  const minutes = Math.floor(diff / 60);
  if (minutes < 60) return `${minutes}m ago`;
  const hours = Math.floor(minutes / 60);
  if (hours < 24) return `${hours}h ago`;
  const days = Math.floor(hours / 24);
  return `${days}d ago`;
}

export type PillTone = 'live' | 'waiting' | 'reconnect' | 'offline';

export function statusToLabel(status: RealtimeStatus, hasReal: boolean): { label: string; tone: PillTone; hint: string } {
  if (status === 'open' && hasReal) return { label: 'Live', tone: 'live', hint: 'Connected and receiving events.' };
  if (status === 'open') return { label: 'Waiting', tone: 'waiting', hint: 'Connected. No events have arrived yet.' };
  if (status === 'connecting') return { label: 'Connecting…', tone: 'reconnect', hint: 'Connecting to the realtime service.' };
  if (hasReal) return { label: 'Reconnecting…', tone: 'reconnect', hint: 'The connection dropped. Reconnecting.' };
  return { label: 'Offline', tone: 'offline', hint: 'The realtime service is unreachable.' };
}

function eventFromMessage(msg: RealtimeAlertMessage, fallbackId: number): LiveEvent | null {
  if (!msg) return null;
  // The realtime service wraps payloads as { type: 'alert.fused', payload, timestamp }
  // but tests / older producers may send the alert directly.
  const payload = msg.payload ?? (msg as unknown as RealtimeAlertMessage['payload']);
  if (!payload) return null;

  const inner: AlertLike = (payload as { alert?: AlertLike }).alert ?? (payload as AlertLike);
  const title =
    inner.title ??
    inner.description ??
    (payload as { title?: string }).title ??
    (payload as { description?: string }).description ??
    'Security event received';
  const source =
    inner.source ??
    inner.source_system ??
    (payload as { source?: string }).source ??
    (payload as { source_system?: string }).source_system ??
    'AiSOC';

  const tsRaw = msg.timestamp ? Date.parse(msg.timestamp) : Date.now();
  const receivedAt = Number.isFinite(tsRaw) ? tsRaw : Date.now();

  return {
    id: inner.id ?? `live-${receivedAt}-${fallbackId}`,
    severity: normalizeSeverity(inner.severity ?? (payload as { severity?: string }).severity),
    text: title,
    source,
    receivedAt,
  };
}

export function LiveFeedPanel() {
  const { last, status } = useRealtimeChannel<RealtimeAlertMessage>('alerts');

  const [events, setEvents] = useState<LiveEvent[]>([]);
  const [now, setNow] = useState(() => Date.now());
  const counterRef = useRef(0);

  // Append new realtime events to the top of the list, dedup by id.
  useEffect(() => {
    if (!last) return;
    counterRef.current += 1;
    const next = eventFromMessage(last, counterRef.current);
    if (!next) return;
    setEvents((prev) => {
      if (prev.some((e) => e.id === next.id)) return prev;
      return [next, ...prev].slice(0, MAX_VISIBLE);
    });
  }, [last]);

  // Tick the clock every second so relative timestamps stay current.
  useEffect(() => {
    const id = window.setInterval(() => setNow(Date.now()), 1_000);
    return () => window.clearInterval(id);
  }, []);

  const hasReal = events.length > 0;
  const visible = events;

  const pill = statusToLabel(status, hasReal);

  return (
    <div className="bg-[#111620] border border-gray-800/60 rounded-lg p-4">
      <div className="flex items-center justify-between mb-3">
        <h3 className="text-sm font-medium text-gray-200 flex items-center gap-2">
          <span
            className={clsx(
              'w-2 h-2 rounded-full',
              pill.tone === 'live' && 'bg-emerald-400 animate-pulse',
              pill.tone === 'reconnect' && 'bg-amber-400 animate-pulse',
              pill.tone === 'waiting' && 'bg-gray-500',
              pill.tone === 'offline' && 'bg-red-400',
            )}
          />
          Live Feed
        </h3>
        <span
          className={clsx(
            'text-[10px] uppercase tracking-wide px-2 py-0.5 rounded-full border',
            pill.tone === 'live' && 'bg-emerald-500/10 text-emerald-300 border-emerald-500/30',
            pill.tone === 'reconnect' && 'bg-amber-500/10 text-amber-300 border-amber-500/30',
            pill.tone === 'waiting' && 'bg-gray-500/10 text-gray-400 border-gray-700',
            pill.tone === 'offline' && 'bg-red-500/10 text-red-300 border-red-500/30',
          )}
          title={`${pill.hint} (WebSocket: ${status})`}
        >
          {pill.label}
        </span>
      </div>

      <div className="space-y-2.5 overflow-y-auto max-h-52 pr-1">
        {visible.length === 0 ? (
          <p className="text-xs text-gray-500">{pill.tone === 'offline' ? 'The realtime service is unreachable.' : 'No events yet.'}</p>
        ) : null}
        {visible.map((event) => (
          <div key={event.id} className="flex items-start gap-2">
            <span
              className={clsx(
                'text-xs px-1.5 py-0.5 rounded font-medium shrink-0 mt-0.5',
                SEVERITY_COLORS[event.severity],
              )}
            >
              {event.severity.toUpperCase().slice(0, 4)}
            </span>
            <div className="min-w-0 flex-1">
              <p className="text-xs text-gray-300 leading-tight truncate">{event.text}</p>
              <p className="text-[11px] text-gray-600 mt-0.5">
                {event.source} · {relativeTime(event.receivedAt, now)}
              </p>
            </div>
          </div>
        ))}
      </div>
    </div>
  );
}
