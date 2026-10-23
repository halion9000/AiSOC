import { beforeEach, describe, expect, it, vi } from 'vitest';
import { render, screen, waitFor, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { SWRConfig } from 'swr';

const metrics = vi.hoisted(() => ({ getSOC: vi.fn() }));
const investigations = vi.hoisted(() => ({ getCostAggregate: vi.fn() }));
vi.mock('@/lib/api', () => ({ metricsApi: metrics, investigationsApi: investigations }));

import { SOCMetricsDashboard } from './SOCMetricsDashboard';

const soc = (over: Record<string, unknown> = {}) => ({
  kpis: { mttd_hours: 1.5, mttr_hours: 6.25, mttc_hours: 30, escalation_rate: 0.3, false_positive_rate: 0.1, alert_volume_7d: 1234, cases_opened_7d: 40, cases_closed_7d: 35, analyst_overrides_7d: 3 },
  attack_heatmap: [{ tactic: 'Execution', technique: 'T1059', count: 10 }, { tactic: 'Execution', technique: 'T1047', count: 2 }, { tactic: 'Impact', technique: 'T1486', count: 5 }],
  calibration_curve: [{ predicted_lower: 0.5, predicted_upper: 0.6, actual_tp_rate: 0.55, sample_count: 40 }, { predicted_lower: 0.9, predicted_upper: 1, actual_tp_rate: 0.5, sample_count: 10 }],
  ...over,
});
const cost = (over: Record<string, unknown> = {}) => ({
  window_days: 30,
  totals: { runs: 12, calls: 80, total_cost_usd: 31.5, avg_cost_per_run: 2.625, avg_latency_per_call_ms: 6200 },
  by_model: [{ model: 'sonnet', runs: 10, calls: 60, total_prompt_tokens: 2_500_000, total_completion_tokens: 12_000, total_cost_usd: 30 }, { model: 'haiku', runs: 2, calls: 20, total_prompt_tokens: 900, total_completion_tokens: 40, total_cost_usd: 1.5 }],
  ...over,
});

function renderIt() {
  return render(
    <SWRConfig value={{ provider: () => new Map(), dedupingInterval: 0, shouldRetryOnError: false }}>
      <SOCMetricsDashboard />
    </SWRConfig>,
  );
}
const kpi = (label: string) => screen.getByText(label, { selector: 'span.uppercase' }).parentElement as HTMLElement;

beforeEach(() => {
  metrics.getSOC.mockReset().mockResolvedValue(soc());
  investigations.getCostAggregate.mockReset().mockResolvedValue(cost());
});

describe('SOCMetricsDashboard: the headline numbers', () => {
  it('shows dashes until the numbers arrive', () => {
    metrics.getSOC.mockReturnValue(new Promise(() => {}));
    renderIt();
    expect(within(kpi('MTTD')).getByText('—')).toBeInTheDocument();
    expect(within(kpi('Alert Volume (7d)')).getByText('—')).toBeInTheDocument();
  });

  it('shows the times in hours, the rates as percentages and the counts as they are', async () => {
    renderIt();
    await waitFor(() => expect(kpi('MTTD')).toHaveTextContent('1.5hrs'));
    expect(kpi('MTTR')).toHaveTextContent('6.3hrs');
    expect(kpi('MTTC')).toHaveTextContent('30.0hrs');
    expect(kpi('Escalation Rate')).toHaveTextContent('30.0%');
    expect(kpi('False Positive Rate')).toHaveTextContent('10.0%');
    expect(kpi('Alert Volume (7d)')).toHaveTextContent('1234');
    expect(kpi('Cases Opened (7d)')).toHaveTextContent('40');
    expect(kpi('Cases Closed (7d)')).toHaveTextContent('35');
    expect(kpi('Analyst Overrides (7d)')).toHaveTextContent('3');
  });

  it('colours a time green, amber or red at its limits: MTTD 2 and 4 hours, MTTR and MTTC 8 and 24', async () => {
    const colour = async (kpis: Record<string, number>, label: string) => {
      metrics.getSOC.mockResolvedValue(soc({ kpis: { ...soc().kpis, ...kpis } }));
      const { unmount } = renderIt();
      await waitFor(() => expect(within(kpi(label)).queryByText('—')).toBeNull());
      const cls = (kpi(label).querySelectorAll('span')[1] as HTMLElement).className;
      unmount();
      return cls;
    };
    expect(await colour({ mttd_hours: 2 }, 'MTTD')).toContain('text-green-400');
    expect(await colour({ mttd_hours: 2.1 }, 'MTTD')).toContain('text-yellow-400');
    expect(await colour({ mttd_hours: 4.1 }, 'MTTD')).toContain('text-red-400');
    expect(await colour({ mttr_hours: 8 }, 'MTTR')).toContain('text-green-400');
    expect(await colour({ mttr_hours: 24.5 }, 'MTTR')).toContain('text-red-400');
    expect(await colour({ escalation_rate: 0.6 }, 'Escalation Rate')).toContain('text-red-400');
    expect(await colour({ false_positive_rate: 0.2 }, 'False Positive Rate')).toContain('text-yellow-400');
  });

  it('a reply that is not the expected shape is treated as no data, not shown as zeros', async () => {
    metrics.getSOC.mockResolvedValue({ unexpected: true });
    renderIt();
    await screen.findByText('SOC Performance Metrics');
    await waitFor(() => expect(investigations.getCostAggregate).toHaveBeenCalled());
    expect(within(kpi('MTTD')).getByText('—')).toBeInTheDocument();
  });

  it('says plainly when the numbers cannot be loaded, and does not claim to be showing mock data', async () => {
    metrics.getSOC.mockRejectedValue(new Error('metrics down'));
    renderIt();
    const note = await screen.findByText(/SOC metrics unavailable:/);
    expect(note.parentElement).toHaveTextContent('metrics down');
    expect(note.parentElement?.textContent ?? '').not.toMatch(/mock|baseline/i);
    expect(within(kpi('MTTD')).getByText('—')).toBeInTheDocument();
  });

  it('Refresh asks again', async () => {
    renderIt();
    await waitFor(() => expect(kpi('MTTD')).toHaveTextContent('1.5'));
    await userEvent.click(screen.getByRole('button', { name: 'Refresh' }));
    await waitFor(() => expect(metrics.getSOC).toHaveBeenCalledTimes(2));
  });
});

describe('SOCMetricsDashboard: confidence calibration', () => {
  it('says there is not enough data when there are no buckets', async () => {
    metrics.getSOC.mockResolvedValue(soc({ calibration_curve: [] }));
    renderIt();
    expect(await screen.findByText(/Not enough labeled investigations/)).toBeInTheDocument();
  });

  it('shows each confidence bin with the real true-positive rate and sample count, coloured by how far off the middle of the bin it is', async () => {
    renderIt();
    const bin = async (range: string) => (await screen.findByText(range)).parentElement as HTMLElement;
    const good = await bin('50-60%');
    expect(good).toHaveTextContent('55.0%');
    expect(good).toHaveTextContent('40');
    expect(within(good).getByText('55.0%').className).toContain('text-green-400');
    const bad = await bin('90-100%');
    expect(within(bad).getByText('50.0%').className).toContain('text-red-400');
    expect(bad.getAttribute('title')).toBe('Predicted 90-100%; actual TP rate 50.0%; 10 samples');
  });
});

describe('SOCMetricsDashboard: ATT&CK heatmap', () => {
  it('groups techniques under their tactic with counts', async () => {
    renderIt();
    const t = await screen.findByText('T1059', { exact: false });
    expect(t).toHaveTextContent('T1059(10)');
    expect(screen.getByText('Execution')).toBeInTheDocument();
    expect(screen.getByText('Impact')).toBeInTheDocument();
    expect(screen.getByText('T1486', { exact: false }).getAttribute('title')).toBe('T1486: 5 alerts');
  });

  it('fades the rarer techniques but never to nothing', async () => {
    metrics.getSOC.mockResolvedValue(soc({ attack_heatmap: [{ tactic: 'Execution', technique: 'T1059', count: 1000 }, { tactic: 'Execution', technique: 'T1047', count: 1 }] }));
    renderIt();
    const rare = await screen.findByText('T1047', { exact: false });
    expect(Number(rare.style.opacity)).toBeGreaterThanOrEqual(0.15);
    expect(Number((screen.getByText('T1059', { exact: false })).style.opacity)).toBe(1);
  });

  it('says there is no ATT&CK data when there are no cells', async () => {
    metrics.getSOC.mockResolvedValue(soc({ attack_heatmap: [] }));
    renderIt();
    expect(await screen.findByText(/No ATT&CK data in the selected period/)).toBeInTheDocument();
  });
});

describe('SOCMetricsDashboard: investigation cost', () => {
  it('shows the totals with spend formatted to its size and coloured by amount', async () => {
    renderIt();
    expect(await screen.findByText('Total Spend')).toBeInTheDocument();
    expect(kpi('Total Spend')).toHaveTextContent('$31.50');
    expect(kpi('Total Spend').querySelectorAll('span')[1].className).toContain('text-yellow-400');
    expect(kpi('Runs')).toHaveTextContent('12');
    expect(kpi('LLM Calls')).toHaveTextContent('80');
    expect(kpi('Avg $/Run')).toHaveTextContent('$2.63');
    expect(kpi('Avg Latency/Call')).toHaveTextContent('6.20s');
    expect(kpi('Avg Latency/Call').querySelectorAll('span')[1].className).toContain('text-yellow-400');
  });

  it('formats small and large amounts differently: cents of a cent, dollars, whole dollars', async () => {
    investigations.getCostAggregate.mockResolvedValue(cost({ totals: { runs: 1, calls: 1, total_cost_usd: 150, avg_cost_per_run: 0.0123, avg_latency_per_call_ms: 12_000 } }));
    renderIt();
    await screen.findByText('Total Spend');
    expect(kpi('Total Spend')).toHaveTextContent('$150');
    expect(kpi('Total Spend').querySelectorAll('span')[1].className).toContain('text-red-400');
    expect(kpi('Avg $/Run')).toHaveTextContent('$0.0123');
    expect(kpi('Avg Latency/Call').querySelectorAll('span')[1].className).toContain('text-red-400');
  });

  it('lists each model with its token counts shortened, its spend and a share bar relative to the biggest', async () => {
    renderIt();
    const row = async (model: string) => (await screen.findByText(model)).closest('tr') as HTMLElement;
    const big = await row('sonnet');
    expect(big).toHaveTextContent('2.5M');
    expect(big).toHaveTextContent('12.0K');
    expect(big).toHaveTextContent('$30.00');
    expect((big.querySelector('div.bg-blue-700') as HTMLElement).style.width).toBe('100%');
    const small = await row('haiku');
    expect(small).toHaveTextContent('900');
    expect(small).toHaveTextContent('$1.50');
    expect(Number.parseFloat((small.querySelector('div.bg-blue-700') as HTMLElement).style.width)).toBeCloseTo(5, 5);
  });

  it('says there were no runs when there were none', async () => {
    investigations.getCostAggregate.mockResolvedValue(cost({ totals: { runs: 0, calls: 0, total_cost_usd: 0, avg_cost_per_run: 0, avg_latency_per_call_ms: 0 }, by_model: [] }));
    renderIt();
    expect(await screen.findByText(/No investigation runs with cost telemetry/)).toBeInTheDocument();
  });

  it('shows a placeholder while loading, and says plainly when the cost cannot be loaded, without claiming projections', async () => {
    let release: (v: unknown) => void = () => {};
    investigations.getCostAggregate.mockReturnValueOnce(new Promise((r) => { release = r; }));
    const first = renderIt();
    expect(first.container.querySelector('.animate-pulse')).not.toBeNull();
    release(cost());
    first.unmount();
    investigations.getCostAggregate.mockRejectedValue(new Error('cost down'));
    renderIt();
    const note = await screen.findByText(/Cost telemetry unavailable:/);
    expect(note.parentElement).toHaveTextContent('cost down');
    expect(note.parentElement?.textContent ?? '').not.toMatch(/projection|baseline/i);
  });
});
