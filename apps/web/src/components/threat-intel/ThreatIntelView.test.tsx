import { cleanup, render, screen, waitFor } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

const list = vi.fn();
const lookup = vi.fn();
const getAlert = vi.fn();

vi.mock('@/lib/api', () => ({
  __esModule: true,
  threatIntelApi: { list: (...a: unknown[]) => list(...a), lookup: (...a: unknown[]) => lookup(...a) },
  alertsApi: { get: (...a: unknown[]) => getAlert(...a) },
}));
vi.mock('next/link', () => ({ __esModule: true, default: ({ href, children, ...rest }: { href: string; children: React.ReactNode }) => <a href={href} {...rest}>{children}</a> }));
vi.mock('swr', async () => {
  // A tiny SWR: runs the fetcher once per key and re-renders with the result.
  const React = await import('react');
  return {
    __esModule: true,
    default: function useFakeSwr(key: unknown, fetcher: () => Promise<unknown>) {
      const [data, setData] = React.useState<unknown>(undefined);
      React.useEffect(() => {
        if (key === null) return;
        let live = true;
        void fetcher().then((d) => live && setData(d));
        return () => {
          live = false;
        };
        // eslint-disable-next-line react-hooks/exhaustive-deps
      }, [JSON.stringify(key)]);
      return { data };
    },
  };
});

import { ThreatIntelView, externalCheckUrl } from './ThreatIntelView';

const HASH = '84ed030762b11dc4d29e7cf02812b7d4a3a578f25ac1a8a3ae51002627644c07';

const indicator = (over: Record<string, unknown> = {}) => ({
  id: 'i1',
  type: 'hash',
  value: HASH,
  confidence: 30,
  severity: 'info',
  malicious: false,
  tags: ['from-alert', 'fieldeffect'],
  sources: ['alerts'],
  firstSeen: '2026-10-18T08:31:00Z',
  lastSeen: '2026-10-18T08:31:00Z',
  description: 'observed on an alert; not a confirmed malicious indicator',
  storedType: 'file_hash_sha256',
  linkedAlerts: ['8477e050-7e5f-581d-a959-5209593c65ef', '9c81e12a-8e9f-53bc-8e15-44aae8df5710'],
  ...over,
});

beforeEach(() => {
  list.mockReset();
  lookup.mockReset();
  getAlert.mockReset();
  getAlert.mockRejectedValue(new Error('alert not available')); // the links still show, with the alert id
  list.mockResolvedValue({ indicators: [indicator()], total: 1 });
});
afterEach(() => cleanup());

describe('the indicator list', () => {
  it('opens an indicator on click and shows what is known about it, instead of a dead row', async () => {
    getAlert.mockImplementation(async (id: string) => ({ id, title: `Alert for ${id.slice(0, 4)}`, severity: 'medium' }));
    render(<ThreatIntelView />);
    const row = await screen.findByRole('button', { name: new RegExp(`Show details for ${HASH}`) });
    expect(screen.queryByTestId('ioc-details')).toBeNull();

    await userEvent.setup().click(row);
    const details = await screen.findByTestId('ioc-details');
    expect(details.textContent).toContain('Hash (SHA256)');
    expect(details.textContent).toContain('not a confirmed malicious indicator');
    expect(details.textContent).toContain('Seen on 2 alerts');
    expect(details.textContent).toContain('fieldeffect');
    expect(await screen.findByRole('link', { name: 'Alert for 8477' })).toHaveAttribute('href', '/alerts/8477e050-7e5f-581d-a959-5209593c65ef');
  });

  it('works from the keyboard', async () => {
    render(<ThreatIntelView />);
    const row = await screen.findByRole('button', { name: /Show details for/ });
    row.focus();
    await userEvent.setup().keyboard('{Enter}');
    expect(await screen.findByTestId('ioc-details')).toBeInTheDocument();
    await userEvent.setup().keyboard('{Enter}');
    await waitFor(() => expect(screen.queryByTestId('ioc-details')).toBeNull());
  });

  it('asks the providers only when the button is pressed, and says what they answered', async () => {
    lookup.mockResolvedValue({ ...indicator(), malicious: true, confidence: 91, sources: ['virustotal'] });
    render(<ThreatIntelView />);
    await userEvent.setup().click(await screen.findByRole('button', { name: /Show details for/ }));
    expect(lookup).not.toHaveBeenCalled();
    await userEvent.setup().click(await screen.findByRole('button', { name: /Look up with threat intel providers/ }));
    expect(await screen.findByText(/Providers report a malicious indicator at 91% confidence \(virustotal\)/)).toBeInTheDocument();
    expect(lookup).toHaveBeenCalledWith(HASH);
  });

  it('says "nothing known" for a 404 and "failed" for any other error', async () => {
    lookup.mockRejectedValueOnce(Object.assign(new Error('nf'), { status: 404 }));
    render(<ThreatIntelView />);
    const user = userEvent.setup();
    await user.click(await screen.findByRole('button', { name: /Show details for/ }));
    await user.click(await screen.findByRole('button', { name: /Look up with threat intel providers/ }));
    expect(await screen.findByText(/know nothing about this indicator/)).toBeInTheDocument();
    lookup.mockRejectedValueOnce(Object.assign(new Error('boom'), { status: 502 }));
    await user.click(screen.getByRole('button', { name: /Look up with threat intel providers/ }));
    expect(await screen.findByText(/The lookup failed/)).toBeInTheDocument();
  });

  it('the Added Today tile counts real indicators, not a fixed number', async () => {
    const today = new Date().toISOString();
    list.mockResolvedValue({ indicators: [indicator({ id: 'a', firstSeen: today }), indicator({ id: 'b', firstSeen: '2020-01-01T00:00:00Z' })], total: 2 });
    render(<ThreatIntelView />);
    const tile = (await screen.findByText('Added Today')).parentElement!;
    expect(tile.textContent).toContain('1');
    expect(tile.textContent).not.toContain('3');
  });
});

describe('externalCheckUrl', () => {
  it('links a hash, an IP and a domain to VirusTotal with the value encoded, and a URL or email to nothing', () => {
    expect(externalCheckUrl({ type: 'hash', value: HASH })?.url).toBe(`https://www.virustotal.com/gui/file/${HASH}`);
    expect(externalCheckUrl({ type: 'ip', value: '8.8.8.8' })?.url).toBe('https://www.virustotal.com/gui/ip-address/8.8.8.8');
    expect(externalCheckUrl({ type: 'domain', value: 'a b.example' })?.url).toBe('https://www.virustotal.com/gui/domain/a%20b.example');
    expect(externalCheckUrl({ type: 'url', value: 'http://x' })).toBeNull();
    expect(externalCheckUrl({ type: 'email', value: 'a@b.c' })).toBeNull();
  });
});

describe('iocIdentifiers', () => {
  it('lists family, actor, campaign, at most three tags (no repeats) and the alert count', async () => {
    const { iocIdentifiers } = await import('./ThreatIntelView');
    const out = iocIdentifiers({ malwareFamily: 'Emotet', threatActor: 'TA542', campaign: null, tags: ['emotet', 'botnet', 'loader', 'x', 'y'], linkedAlerts: ['a', 'b'] } as never);
    expect(out.map((o) => o.text)).toEqual(['Emotet', 'TA542', 'botnet', 'loader', 'x', '2 alerts']);
  });
  it('is empty when nothing is known', async () => {
    const { iocIdentifiers } = await import('./ThreatIntelView');
    expect(iocIdentifiers({ tags: [], linkedAlerts: [] } as never)).toEqual([]);
  });
});

describe('what the list row says an indicator is', () => {
  it('shows the family, actor, campaign, tags and alert count on the row itself, without opening it', async () => {
    list.mockResolvedValue({ indicators: [indicator({ malwareFamily: 'Emotet', threatActor: 'TA542', campaign: 'Spring', tags: ['botnet', 'loader'], linkedAlerts: ['a', 'b', 'c'] })], total: 1 });
    render(<ThreatIntelView />);
    const chips = await screen.findByTestId('ioc-identifiers');
    for (const text of ['Emotet', 'TA542', 'Spring', 'botnet', 'loader', '3 alerts']) expect(chips.textContent).toContain(text);
    expect(screen.getByTitle('malware family').textContent).toBe('Emotet');
  });

  it('shows no chip line for an indicator nothing is known about', async () => {
    list.mockResolvedValue({ indicators: [indicator({ tags: [], linkedAlerts: [] })], total: 1 });
    render(<ThreatIntelView />);
    await screen.findByRole('button', { name: new RegExp(`Show details for ${HASH}`) });
    expect(screen.queryByTestId('ioc-identifiers')).toBeNull();
  });
});

describe('filtering the list', () => {
  const rows = [
    indicator({ id: 'h1', type: 'hash', value: 'a'.repeat(64), malwareFamily: 'Emotet', tags: ['botnet'], linkedAlerts: ['x'] }),
    indicator({ id: 'i1', type: 'ip', value: '203.0.113.9', malwareFamily: 'Qakbot', tags: ['c2'], linkedAlerts: [] }),
  ];

  it('searching by an indicator value keeps the chips on the rows that remain', async () => {
    list.mockResolvedValue({ indicators: rows, total: 2 });
    render(<ThreatIntelView />);
    const box = await screen.findByPlaceholderText(/search/i);
    await userEvent.type(box, '203.0.113');
    const chips = await screen.findAllByTestId('ioc-identifiers');
    expect(chips).toHaveLength(1);
    expect(chips[0].textContent).toContain('Qakbot');
    expect(chips[0].textContent).not.toContain('Emotet');
  });
});
