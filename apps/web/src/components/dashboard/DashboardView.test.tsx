import { beforeEach, describe, expect, it, vi } from 'vitest';
import { fireEvent, render, screen, waitFor, within } from '@testing-library/react';
import { SWRConfig } from 'swr';

const api = vi.hoisted(() => ({ getDashboard: vi.fn() }));
vi.mock('@/lib/api', () => ({ metricsApi: api }));
vi.mock('next/dynamic', () => ({ default: () => () => null }));
vi.mock('./LiveFeedPanel', () => ({ LiveFeedPanel: () => <div>live-feed</div> }));
vi.mock('./SOCMetricsDashboard', () => ({ SOCMetricsDashboard: () => <div>soc-metrics</div> }));
vi.mock('./DashboardWelcome', () => ({ DashboardWelcome: () => <div>welcome</div> }));
vi.mock('./FunnelKpiBar', () => ({ FunnelKpiBar: () => <div>funnel</div> }));
vi.mock('./EfficiencyReport', () => ({ EfficiencyReport: () => <div>efficiency</div> }));
vi.mock('./PipelineHealth', () => ({ PipelineHealth: () => <div>pipeline</div> }));

import { DashboardView } from './DashboardView';

const metrics = (over: Record<string, unknown> = {}) => ({
  alerts: { total: 321, new: 12, critical: 4, high: 20, medium: 100, low: 150, info: 47, resolvedToday: 9, mttr: 38 },
  cases: { open: 7, inProgress: 3, resolvedThisWeek: 11 },
  sources: [
    { name: 'CrowdStrike', status: 'healthy', count: 200 },
    { name: 'Okta', status: 'degraded', count: 100 },
    { name: 'Blumira', status: 'error', count: 50 },
  ],
  topMitre: [],
  alertsTrend: [],
  threatsBySource: [],
  ...over,
});

function renderView() {
  return render(
    <SWRConfig value={{ provider: () => new Map(), dedupingInterval: 0, shouldRetryOnError: false }}>
      <DashboardView />
    </SWRConfig>,
  );
}

const ORDER_KEY = 'aisoc:dashboard:widget-order';

beforeEach(() => {
  api.getDashboard.mockReset();
  localStorage.clear();
});

const widgetIds = () => screen.getAllByLabelText(/^Dashboard widget:/).map((e) => e.getAttribute('aria-label')?.replace('Dashboard widget: ', ''));

describe('DashboardView', () => {
  it('shows a loading note first', () => {
    api.getDashboard.mockReturnValue(new Promise(() => {}));
    renderView();
    expect(screen.getByText('Loading dashboard metrics…')).toBeInTheDocument();
  });

  it('shows the numbers the API sent', async () => {
    api.getDashboard.mockResolvedValue(metrics());
    renderView();
    const card = async (label: string) => (await screen.findAllByText(label))[0].parentElement as HTMLElement;
    expect(within(await card('Active Alerts')).getByText('321')).toBeInTheDocument();
    expect(within(await card('Active Alerts')).getByText('12 new today')).toBeInTheDocument();
    expect(within(await card('Critical')).getByText('4')).toBeInTheDocument();
    expect(within(await card('Open Cases')).getByText('7')).toBeInTheDocument();
    expect(within(await card('Open Cases')).getByText('3 in progress')).toBeInTheDocument();
    expect(within(await card('MTTR')).getByText('38m')).toBeInTheDocument();
  });

  it('counts a source as connected when it works, even with a warning, and not when it is failing', async () => {
    api.getDashboard.mockResolvedValue(metrics());
    renderView();
    const card = (await screen.findAllByText('Connected Sources'))[0].closest('div') as HTMLElement;
    expect(within((await screen.findAllByText('Connected Sources'))[0].parentElement as HTMLElement).getByText('2')).toBeInTheDocument();
    expect(card).toBeTruthy();
    expect(screen.getByText(/2 connected sources/)).toBeInTheDocument();
  });

  it('lists each source with its event count, coloured by its health', async () => {
    api.getDashboard.mockResolvedValue(metrics());
    renderView();
    const dot = async (name: string) => (await screen.findByText(name)).previousElementSibling as HTMLElement;
    expect((await dot('CrowdStrike')).className).toContain('bg-green-500');
    expect((await dot('Okta')).className).toContain('bg-amber-500');
    expect((await dot('Blumira')).className).toContain('bg-red-500');
    expect(screen.getByText('200')).toBeInTheDocument();
  });

  it('shows the severity breakdown including Info', async () => {
    api.getDashboard.mockResolvedValue(metrics());
    renderView();
    await screen.findByText('Severity Breakdown');
    const box = screen.getByText('Severity Breakdown').parentElement as HTMLElement;
    for (const [name, value] of [['Critical', '4'], ['High', '20'], ['Medium', '100'], ['Low', '150'], ['Info', '47']]) {
      expect(within(box).getByText(name).parentElement?.parentElement).toHaveTextContent(value);
    }
  });

  it('with an empty instance shows honest zeros, no source rows and no crash', async () => {
    api.getDashboard.mockResolvedValue({});
    renderView();
    expect(await screen.findByText('Active Alerts')).toBeInTheDocument();
    expect(within(screen.getByText('Active Alerts').parentElement as HTMLElement).getByText('0')).toBeInTheDocument();
    expect(screen.getByText(/0 connected sources/)).toBeInTheDocument();
  });

  it('does not show percentage changes the API never sent', async () => {
    api.getDashboard.mockResolvedValue(metrics());
    renderView();
    await screen.findByText('Active Alerts');
    expect(screen.queryAllByText(/vs yesterday/)).toHaveLength(0);
    expect(screen.queryAllByText(/vs last week/)).toHaveLength(0);
  });

  it('shows the error and zero values when the metrics cannot be loaded', async () => {
    api.getDashboard.mockRejectedValue(new Error('metrics down'));
    renderView();
    expect(await screen.findByText('Dashboard metrics unavailable')).toBeInTheDocument();
    expect(screen.getByText('metrics down')).toBeInTheDocument();
    expect(screen.getByText('Active Alerts')).toBeInTheDocument();
  });

  it('shows every section in the default order', async () => {
    api.getDashboard.mockResolvedValue(metrics());
    renderView();
    await screen.findByText('Active Alerts');
    expect(widgetIds()).toEqual(['welcome', 'funnel-kpis', 'efficiency-and-pipeline', 'top-metrics', 'charts-row', 'bottom-row', 'soc-performance']);
  });

  it('uses a saved order, and ignores a saved order that is missing a section', async () => {
    const saved = ['soc-performance', 'bottom-row', 'charts-row', 'top-metrics', 'efficiency-and-pipeline', 'funnel-kpis', 'welcome'];
    localStorage.setItem(ORDER_KEY, JSON.stringify(saved));
    api.getDashboard.mockResolvedValue(metrics());
    const first = renderView();
    await waitFor(() => expect(widgetIds()).toEqual(saved));
    first.unmount();

    localStorage.setItem(ORDER_KEY, JSON.stringify(['welcome', 'funnel-kpis']));
    renderView();
    await screen.findByText('Active Alerts');
    expect(widgetIds()).toHaveLength(7);
    expect(widgetIds()[0]).toBe('welcome');
    expect(widgetIds()[6]).toBe('soc-performance');
  });

  it('dragging one section onto another reorders them and remembers the order', async () => {
    api.getDashboard.mockResolvedValue(metrics());
    renderView();
    await screen.findByText('Active Alerts');
    const widget = (id: string) => screen.getByLabelText(`Dashboard widget: ${id}`);
    fireEvent.dragStart(widget('soc-performance'));
    fireEvent.dragOver(widget('welcome'));
    fireEvent.drop(widget('welcome'));
    await waitFor(() => expect(widgetIds()[0]).toBe('soc-performance'));
    expect(widgetIds()[1]).toBe('welcome');
    expect(JSON.parse(localStorage.getItem(ORDER_KEY) as string)).toEqual(widgetIds());
  });

  it('dropping a section on itself changes nothing', async () => {
    api.getDashboard.mockResolvedValue(metrics());
    renderView();
    await screen.findByText('Active Alerts');
    const w = screen.getByLabelText('Dashboard widget: welcome');
    fireEvent.dragStart(w);
    fireEvent.dragOver(w);
    fireEvent.drop(w);
    expect(widgetIds()[0]).toBe('welcome');
    expect(localStorage.getItem(ORDER_KEY)).toBeNull();
  });
});
