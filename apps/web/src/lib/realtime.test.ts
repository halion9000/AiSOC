import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { act, renderHook } from '@testing-library/react';

const api = vi.hoisted(() => ({ channelUrl: vi.fn() }));
vi.mock('./api', () => ({ realtimeApi: api }));

import { useRealtimeChannel } from './realtime';

class FakeSocket {
  static CONNECTING = 0;
  static OPEN = 1;
  static CLOSING = 2;
  static CLOSED = 3;
  static all: FakeSocket[] = [];
  readyState = FakeSocket.CONNECTING;
  sent: string[] = [];
  closed = false;
  onopen: (() => void) | null = null;
  onmessage: ((e: { data: string }) => void) | null = null;
  onerror: (() => void) | null = null;
  onclose: (() => void) | null = null;
  constructor(public url: string) {
    FakeSocket.all.push(this);
  }
  send(text: string) {
    this.sent.push(text);
  }
  close() {
    this.closed = true;
    this.readyState = FakeSocket.CLOSED;
  }
  open() {
    this.readyState = FakeSocket.OPEN;
    this.onopen?.();
  }
  say(data: unknown) {
    this.onmessage?.({ data: typeof data === 'string' ? data : JSON.stringify(data) });
  }
  drop() {
    this.readyState = FakeSocket.CLOSED;
    this.onclose?.();
  }
}

const flush = async () => {
  await act(async () => {
    await Promise.resolve();
    await Promise.resolve();
  });
};

beforeEach(() => {
  vi.useFakeTimers();
  FakeSocket.all = [];
  api.channelUrl.mockReset().mockImplementation(async (c: string) => `ws://rt/${c}?token=t`);
  vi.stubGlobal('WebSocket', FakeSocket);
});
afterEach(() => {
  vi.useRealTimers();
  vi.unstubAllGlobals();
});

describe('useRealtimeChannel', () => {
  it('connects to the channel with a fresh ticket, and says open once the socket is', async () => {
    const { result } = renderHook(() => useRealtimeChannel('alerts'));
    expect(result.current.status).toBe('connecting');
    await flush();
    expect(api.channelUrl).toHaveBeenCalledWith('alerts');
    expect(FakeSocket.all[0].url).toBe('ws://rt/alerts?token=t');
    act(() => FakeSocket.all[0].open());
    expect(result.current.status).toBe('open');
  });

  it('does nothing when disabled', async () => {
    renderHook(() => useRealtimeChannel('alerts', { enabled: false }));
    await flush();
    expect(FakeSocket.all).toHaveLength(0);
    expect(api.channelUrl).not.toHaveBeenCalled();
  });

  it('a test-supplied address skips the ticket', async () => {
    renderHook(() => useRealtimeChannel('alerts', { url: 'ws://test/x' }));
    await flush();
    expect(api.channelUrl).not.toHaveBeenCalled();
    expect(FakeSocket.all[0].url).toBe('ws://test/x');
  });

  it('keeps the latest message and the newest fifty, newest first, and ignores frames that are not JSON', async () => {
    const { result } = renderHook(() => useRealtimeChannel<{ n: number }>('alerts'));
    await flush();
    const ws = FakeSocket.all[0];
    act(() => ws.open());
    act(() => ws.say('not json at all'));
    expect(result.current.last).toBeNull();
    for (let n = 1; n <= 60; n += 1) act(() => ws.say({ n }));
    expect(result.current.last).toEqual({ n: 60 });
    expect(result.current.history).toHaveLength(50);
    expect(result.current.history[0]).toEqual({ n: 60 });
    expect(result.current.history[49]).toEqual({ n: 11 });
  });

  it('reset clears what was received', async () => {
    const { result } = renderHook(() => useRealtimeChannel('alerts'));
    await flush();
    act(() => FakeSocket.all[0].open());
    act(() => FakeSocket.all[0].say({ a: 1 }));
    act(() => result.current.reset());
    expect(result.current.last).toBeNull();
    expect(result.current.history).toEqual([]);
  });

  it('send writes text as it is and anything else as JSON, but only while open', async () => {
    const { result } = renderHook(() => useRealtimeChannel('alerts'));
    await flush();
    const ws = FakeSocket.all[0];
    act(() => result.current.send({ early: true }));
    expect(ws.sent).toEqual([]);
    act(() => ws.open());
    act(() => result.current.send({ type: 'ping' }));
    act(() => result.current.send('raw text'));
    expect(ws.sent).toEqual(['{"type":"ping"}', 'raw text']);
  });

  it('after a drop it reconnects with a new ticket, waiting longer each time up to the cap', async () => {
    renderHook(() => useRealtimeChannel('alerts', { maxBackoffMs: 5000 }));
    await flush();
    const gaps: number[] = [];
    for (let i = 0; i < 4; i += 1) {
      const before = FakeSocket.all.length;
      act(() => FakeSocket.all[before - 1].drop());
      // Find the wait by stepping time until a new socket appears.
      let waited = 0;
      while (FakeSocket.all.length === before && waited < 20_000) {
        await act(async () => { await vi.advanceTimersByTimeAsync(250); });
        waited += 250;
      }
      gaps.push(waited);
    }
    expect(gaps).toEqual([2000, 4000, 5000, 5000]);
    expect(api.channelUrl.mock.calls.length).toBe(5);
  });

  it('a successful open resets the wait', async () => {
    renderHook(() => useRealtimeChannel('alerts'));
    await flush();
    act(() => FakeSocket.all[0].drop());
    await act(async () => { await vi.advanceTimersByTimeAsync(2000); });
    expect(FakeSocket.all).toHaveLength(2);
    act(() => FakeSocket.all[1].open());
    act(() => FakeSocket.all[1].drop());
    await act(async () => { await vi.advanceTimersByTimeAsync(1999); });
    expect(FakeSocket.all).toHaveLength(2);
    await act(async () => { await vi.advanceTimersByTimeAsync(1); });
    expect(FakeSocket.all).toHaveLength(3);
  });

  it('when a ticket cannot be had it says error, opens no socket, and tries again later', async () => {
    api.channelUrl.mockRejectedValueOnce(new Error('503'));
    const { result } = renderHook(() => useRealtimeChannel('alerts'));
    await flush();
    expect(result.current.status).toBe('error');
    expect(FakeSocket.all).toHaveLength(0);
    await act(async () => { await vi.advanceTimersByTimeAsync(2000); });
    expect(FakeSocket.all).toHaveLength(1);
  });

  it('closing the page closes an open socket and does not reconnect', async () => {
    const { unmount } = renderHook(() => useRealtimeChannel('alerts'));
    await flush();
    const ws = FakeSocket.all[0];
    act(() => ws.open());
    unmount();
    expect(ws.closed).toBe(true);
    ws.onclose?.();
    await act(async () => { await vi.advanceTimersByTimeAsync(60_000); });
    expect(FakeSocket.all).toHaveLength(1);
  });

  it('a socket that is still connecting when the page goes away is closed too, not left to open unseen', async () => {
    const { unmount } = renderHook(() => useRealtimeChannel('alerts'));
    await flush();
    const ws = FakeSocket.all[0];
    expect(ws.readyState).toBe(FakeSocket.CONNECTING);
    unmount();
    expect(ws.closed).toBe(true);
  });

  it('changing channel while a reconnect is waiting does not leave a second connection loop running for the old channel', async () => {
    const { rerender } = renderHook(({ c }) => useRealtimeChannel(c), { initialProps: { c: 'alerts' as 'alerts' | 'cases' } });
    await flush();
    act(() => FakeSocket.all[0].drop());
    rerender({ c: 'cases' });
    await flush();
    await act(async () => { await vi.advanceTimersByTimeAsync(10_000); });
    const channels = FakeSocket.all.map((s) => s.url.split('/')[3].split('?')[0]);
    expect(channels.filter((c) => c === 'alerts')).toHaveLength(1);
    expect(channels).toContain('cases');
  });
});
