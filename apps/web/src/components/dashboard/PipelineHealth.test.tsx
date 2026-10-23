import { beforeEach, describe, expect, it, vi } from 'vitest';
import { render, screen, within } from '@testing-library/react';
import { SWRConfig } from 'swr';

const api = vi.hoisted(() => ({ getPipelineHealth: vi.fn() }));
vi.mock('@/lib/api', () => ({ metricsApi: api }));

import { PipelineHealth } from './PipelineHealth';

const stage = (name: string, over: Record<string, unknown> = {}) => ({ stage: name, status: 'green', backlog: 12, p95_latency_ms: 340, error_rate: 0, ...over });
const ALL = ['ingest', 'normalize', 'fuse', 'correlate', 'alert'];

function renderIt() {
  return render(
    <SWRConfig value={{ provider: () => new Map(), dedupingInterval: 0, shouldRetryOnError: false }}>
      <PipelineHealth />
    </SWRConfig>,
  );
}
const card = (label: string) => screen.getByText(label, { selector: 'p.font-semibold' }).closest('div.rounded-xl') as HTMLElement;
const row = (c: HTMLElement, label: string) => (within(c).getByText(label).parentElement as HTMLElement).querySelector('dd')?.textContent;
const three = (label: string) => [row(card(label), 'Backlog'), row(card(label), 'p95'), row(card(label), 'Errors')];

beforeEach(() => {
  api.getPipelineHealth.mockReset();
});

describe('PipelineHealth', () => {
  it('shows all five stages as loading placeholders first', () => {
    let release: (v: unknown) => void = () => {};
    api.getPipelineHealth.mockReturnValue(new Promise((r) => { release = r; }));
    renderIt();
    for (const l of ['Ingest', 'Normalize', 'Fuse', 'Correlate', 'Alert']) expect(screen.getByText(l)).toBeInTheDocument();
    expect(screen.queryByText('Backlog')).toBeNull();
    release({ stages: [] });
  });

  it('shows the stages in pipeline order whatever order the API sent', async () => {
    api.getPipelineHealth.mockResolvedValue({ stages: [...ALL].reverse().map((n) => stage(n)) });
    renderIt();
    await screen.findAllByText('Backlog');
    const names = screen.getAllByText(/^(Ingest|Normalize|Fuse|Correlate|Alert)$/, { selector: 'p.font-semibold' }).map((e) => e.textContent);
    expect(names).toEqual(['Ingest', 'Normalize', 'Fuse', 'Correlate', 'Alert']);
  });

  it('a stage the API did not send stays a placeholder instead of vanishing', async () => {
    api.getPipelineHealth.mockResolvedValue({ stages: ALL.filter((n) => n !== 'fuse').map((n) => stage(n)) });
    renderIt();
    await screen.findAllByText('Backlog');
    expect(screen.getAllByText('Backlog')).toHaveLength(4);
    expect(screen.getByText('Fuse')).toBeInTheDocument();
  });

  it('writes backlog, latency and error rate in a short readable form', async () => {
    api.getPipelineHealth.mockResolvedValue({
      stages: [
        stage('ingest', { backlog: 999, p95_latency_ms: 0.4, error_rate: 0 }),
        stage('normalize', { backlog: 1500, p95_latency_ms: 340.4, error_rate: 0.0004 }),
        stage('fuse', { backlog: 12_000, p95_latency_ms: 1500, error_rate: 0.01 }),
        stage('correlate', { backlog: 2_500_000, p95_latency_ms: 90_000, error_rate: 0.125 }),
        stage('alert', { backlog: 1_000_000, p95_latency_ms: 2000, error_rate: 1 }),
      ],
    });
    renderIt();
    await screen.findAllByText('Backlog');
    expect(three('Ingest')).toEqual(['999', '< 1 ms', '0%']);
    expect(three('Normalize')).toEqual(['1.5k', '340 ms', '< 0.1%']);
    expect(three('Fuse')).toEqual(['12k', '1.5 s', '1%']);
    expect(three('Correlate')).toEqual(['2.5M', '1.5 m', '12.5%']);
    expect(three('Alert')).toEqual(['1M', '2 s', '100%']);
  });

  it('shows a dash for numbers that are negative or not numbers', async () => {
    api.getPipelineHealth.mockResolvedValue({ stages: [stage('ingest', { backlog: -1, p95_latency_ms: Number.NaN, error_rate: -0.5 }), ...ALL.slice(1).map((n) => stage(n))] });
    renderIt();
    await screen.findAllByText('Backlog');
    expect(three('Ingest')).toEqual(['—', '—', '—']);
  });

  it('marks each stage green, amber, red or grey and says so for assistive technology', async () => {
    api.getPipelineHealth.mockResolvedValue({ stages: [stage('ingest', { status: 'green' }), stage('normalize', { status: 'yellow' }), stage('fuse', { status: 'red' }), stage('correlate', { status: 'unknown' }), stage('alert', { status: 'green' })] });
    renderIt();
    await screen.findAllByText('Backlog');
    const dot = (l: string) => within(card(l)).getByLabelText(/^status /);
    expect(dot('Ingest')).toHaveAttribute('aria-label', 'status green');
    expect(dot('Ingest').className).toContain('bg-green-500');
    expect(dot('Normalize').className).toContain('bg-amber-500');
    expect(dot('Fuse').className).toContain('bg-red-500');
    expect(dot('Correlate').className).toContain('bg-gray-600');
  });

  it('says unavailable when the health call fails, and Live when it works', async () => {
    api.getPipelineHealth.mockRejectedValue(new Error('down'));
    const first = renderIt();
    expect(await screen.findByText('unavailable')).toBeInTheDocument();
    first.unmount();
    api.getPipelineHealth.mockResolvedValue({ stages: ALL.map((n) => stage(n)) });
    renderIt();
    expect(await screen.findByText('Live')).toBeInTheDocument();
  });
});
