import { beforeEach, describe, expect, it, vi } from 'vitest';
import { render, screen } from '@testing-library/react';
import { SWRConfig } from 'swr';

const api = vi.hoisted(() => ({ getFunnel: vi.fn() }));
vi.mock('@/lib/api', () => ({ metricsApi: api }));

import { EfficiencyReport } from './EfficiencyReport';

const funnel = (over: Record<string, unknown> = {}) => ({ correlation_efficiency: 0.25, alert_yield: 0.6, mitre_coverage: { covered: 21, total: 40 }, ...over });

function renderIt(props: Record<string, unknown> = {}) {
  return render(
    <SWRConfig value={{ provider: () => new Map(), dedupingInterval: 0, shouldRetryOnError: false }}>
      <EfficiencyReport {...props} />
    </SWRConfig>,
  );
}
const rowOf = (label: string) => screen.getByText(label).closest('div.min-w-0')?.parentElement?.parentElement as HTMLElement;
const barOf = (label: string) => rowOf(label).querySelector('div.h-full') as HTMLElement;

beforeEach(() => {
  api.getFunnel.mockReset();
});

describe('EfficiencyReport', () => {
  it('shows the three labels while loading', () => {
    let release: (v: unknown) => void = () => {};
    api.getFunnel.mockReturnValue(new Promise((r) => { release = r; }));
    renderIt();
    for (const l of ['Correlation efficiency', 'Alert yield', 'MITRE coverage']) expect(screen.getByText(l)).toBeInTheDocument();
    release(funnel());
  });

  it('asks for the 24 hour window by default and for another when told, and says which', async () => {
    api.getFunnel.mockResolvedValue(funnel());
    const first = renderIt();
    expect(await screen.findByText('Last 24h')).toBeInTheDocument();
    expect(api.getFunnel).toHaveBeenCalledWith('24h');
    first.unmount();
    renderIt({ period: '7d' });
    expect(await screen.findByText('Last 7d')).toBeInTheDocument();
    expect(api.getFunnel).toHaveBeenCalledWith('7d');
  });

  it('shows the two ratios as percentages and MITRE coverage as covered of total with a percentage', async () => {
    api.getFunnel.mockResolvedValue(funnel());
    renderIt();
    expect(await screen.findByText('25%')).toBeInTheDocument();
    expect(screen.getByText('60%')).toBeInTheDocument();
    expect(screen.getByText('21/40 • 52.5%')).toBeInTheDocument();
  });

  it('colours a bar red under 20%, amber under 50% and green from 50%', async () => {
    for (const [value, colour] of [[0.1, 'bg-red-500/70'], [0.3, 'bg-amber-500/70'], [0.5, 'bg-green-500/70']] as const) {
      api.getFunnel.mockResolvedValue(funnel({ correlation_efficiency: value }));
      const view = renderIt();
      await screen.findByText(`${(value * 100).toFixed(0)}%`);
      expect(barOf('Correlation efficiency').className).toContain(colour);
      view.unmount();
    }
  });

  it('keeps the bar between 0 and 100% whatever the server sends', async () => {
    api.getFunnel.mockResolvedValue(funnel({ correlation_efficiency: 7, alert_yield: -3 }));
    renderIt();
    await screen.findByText('Alert yield');
    expect(barOf('Correlation efficiency').style.width).toBe('100%');
    expect(barOf('Alert yield').style.width).toBe('0%');
    expect(screen.getByText('100%')).toBeInTheDocument();
    expect(screen.getByText('0%')).toBeInTheDocument();
  });

  it('a total of zero gives a dash for coverage and an empty bar, not a divide-by-zero', async () => {
    api.getFunnel.mockResolvedValue(funnel({ mitre_coverage: { covered: 0, total: 0 } }));
    renderIt();
    await screen.findByText('MITRE coverage');
    expect(screen.getByText('—')).toBeInTheDocument();
    expect(barOf('MITRE coverage').style.width).toBe('0%');
    expect(screen.queryByText(/NaN|Infinity/)).toBeNull();
  });

  it('says unavailable when the funnel cannot be read', async () => {
    api.getFunnel.mockImplementation(() => new Promise((_, reject) => setTimeout(() => reject(new Error('down')), 0)));
    renderIt();
    expect(await screen.findByText('Efficiency metrics unavailable.')).toBeInTheDocument();
  });
});
