import { beforeEach, describe, expect, it, vi } from 'vitest';
import { render, screen } from '@testing-library/react';
import type { RealtimeStatus } from '@/lib/realtime';

const channel = vi.hoisted(() => ({ current: { last: null as unknown, status: 'closed' as string } }));
vi.mock('@/lib/realtime', () => ({ useRealtimeChannel: () => channel.current }));

import { LiveFeedPanel, statusToLabel } from './LiveFeedPanel';

// An empty feed used to be labelled "Demo" with a tooltip saying "Realtime service unreachable or no events received yet — showing demo data". No demo events
// were ever shown (that code had been removed), so the claim was false, and "Demo" hid the difference between "connected, nothing yet" and "service down".
function alert(id: string, over: Record<string, unknown> = {}) {
  return { type: 'alert', timestamp: new Date().toISOString(), payload: { alert: { id, title: `Alert ${id}`, severity: 'high', source: 'edr', ...over } } };
}

function setChannel(status: RealtimeStatus, last: unknown = null) {
  channel.current = { last, status };
}

beforeEach(() => setChannel('closed'));

describe('statusToLabel', () => {
  const cases: [RealtimeStatus, boolean, string, string][] = [
    ['open', true, 'Live', 'live'],
    ['open', false, 'Waiting', 'waiting'],
    ['connecting', false, 'Connecting…', 'reconnect'],
    ['connecting', true, 'Connecting…', 'reconnect'],
    ['closing', true, 'Reconnecting…', 'reconnect'],
    ['closed', true, 'Reconnecting…', 'reconnect'],
    ['error', true, 'Reconnecting…', 'reconnect'],
    ['closing', false, 'Offline', 'offline'],
    ['closed', false, 'Offline', 'offline'],
    ['error', false, 'Offline', 'offline'],
  ];
  it.each(cases)('%s, events received: %s -> %s', (status, hasReal, label, tone) => {
    const pill = statusToLabel(status, hasReal);
    expect(pill.label).toBe(label);
    expect(pill.tone).toBe(tone);
    expect(pill.hint.length).toBeGreaterThan(5);
  });

  it('never calls anything "Demo", and says nothing about demo data', () => {
    for (const status of ['connecting', 'open', 'closing', 'closed', 'error'] as RealtimeStatus[]) {
      for (const hasReal of [true, false]) {
        const pill = statusToLabel(status, hasReal);
        expect(`${pill.label} ${pill.hint}`).not.toMatch(/demo|seeded|sample/i);
      }
    }
  });
});

describe('LiveFeedPanel', () => {
  it('says the service is unreachable, and shows no events and no demo claim, when it is down', () => {
    setChannel('closed');
    const { container } = render(<LiveFeedPanel />);
    expect(screen.getByText('Offline')).toBeInTheDocument();
    expect(screen.getByText('The realtime service is unreachable.')).toBeInTheDocument();
    expect(container.textContent).not.toMatch(/demo|seeded|sample/i);
    expect(container.querySelectorAll('.truncate').length).toBe(0);
    expect(screen.getByText('Offline').getAttribute('title')).toBe('The realtime service is unreachable. (WebSocket: closed)');
  });

  it('says it is connected and waiting, which is different from being down', () => {
    setChannel('open');
    const { container } = render(<LiveFeedPanel />);
    expect(screen.getByText('Waiting')).toBeInTheDocument();
    expect(screen.getByText('No events yet.')).toBeInTheDocument();
    expect(screen.queryByText('The realtime service is unreachable.')).not.toBeInTheDocument();
    expect(container.textContent).not.toMatch(/demo/i);
  });

  it('shows a real event with its severity and source, and goes Live', () => {
    setChannel('open', alert('a1', { title: 'Impossible travel for jdoe', severity: 'critical', source: 'entra-id' }));
    render(<LiveFeedPanel />);
    expect(screen.getByText('Live')).toBeInTheDocument();
    expect(screen.getByText('Impossible travel for jdoe')).toBeInTheDocument();
    expect(screen.getByText('CRIT')).toBeInTheDocument();
    expect(screen.getByText(/entra-id/)).toBeInTheDocument();
    expect(screen.queryByText('No events yet.')).not.toBeInTheDocument();
  });

  it('keeps the events it has, and says it is reconnecting, if the connection drops after events arrived', () => {
    setChannel('open', alert('a1', { title: 'First real event' }));
    const { rerender } = render(<LiveFeedPanel />);
    setChannel('closed', alert('a1', { title: 'First real event' }));
    rerender(<LiveFeedPanel />);
    expect(screen.getByText('Reconnecting…')).toBeInTheDocument();
    expect(screen.getByText('First real event')).toBeInTheDocument();
  });

  it('does not show the same alert twice, and keeps only the 12 most recent', () => {
    setChannel('open', alert('dup', { title: 'Same alert' }));
    const { rerender, container } = render(<LiveFeedPanel />);
    setChannel('open', alert('dup', { title: 'Same alert' }));
    rerender(<LiveFeedPanel />);
    expect(screen.getAllByText('Same alert').length).toBe(1);
    for (let i = 0; i < 15; i += 1) {
      setChannel('open', alert(`e${i}`, { title: `Event ${i}` }));
      rerender(<LiveFeedPanel />);
    }
    expect(container.querySelectorAll('.truncate').length).toBe(12);
    expect(screen.getByText('Event 14')).toBeInTheDocument();
    expect(screen.queryByText('Same alert')).not.toBeInTheDocument();
  });
});
