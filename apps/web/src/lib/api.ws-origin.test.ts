import { describe, expect, it } from 'vitest';
import { resolveWsBase } from './api';

describe('resolveWsBase', () => {
  it('keeps localhost when the page is on localhost', () => {
    expect(resolveWsBase('ws://localhost:8086', 'localhost')).toBe('ws://localhost:8086');
    expect(resolveWsBase('ws://localhost:8086', '127.0.0.1')).toBe('ws://localhost:8086');
  });

  it('swaps in the LAN IP the page was loaded from, keeping the port', () => {
    expect(resolveWsBase('ws://localhost:8086', '192.168.1.50')).toBe('ws://192.168.1.50:8086');
  });

  it('swaps in a name like aisoc.local', () => {
    expect(resolveWsBase('ws://localhost:8086', 'aisoc.local')).toBe('ws://aisoc.local:8086');
  });

  it('leaves a non-loopback base alone', () => {
    expect(resolveWsBase('wss://soc.example.com', 'aisoc.local')).toBe('wss://soc.example.com');
  });

  it('leaves a non-URL value alone', () => {
    expect(resolveWsBase('/ws', 'aisoc.local')).toBe('/ws');
  });
});
