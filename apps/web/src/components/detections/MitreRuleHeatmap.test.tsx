import { beforeEach, describe, expect, it, vi } from 'vitest';
import { render, screen, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { SWRConfig } from 'swr';

const api = vi.hoisted(() => ({ coverage: vi.fn() }));
vi.mock('@/lib/api', () => ({ detectionApi: api }));

import { MitreRuleHeatmap } from './MitreRuleHeatmap';

const cell = (techniqueId: string, tactic: string | null, active: number, inactive = 0) => ({ techniqueId, tactic, totalRules: active + inactive, activeRules: active, inactiveRules: inactive });
const coverage = (cells: ReturnType<typeof cell>[], tactics: string[], summary: Record<string, number> = {}) => ({
  tactics,
  cells,
  summary: { totalRules: 20, activeRules: 15, inactiveRules: 5, techniques: cells.length, coveredTechniques: cells.filter((c) => c.activeRules > 0).length, ...summary },
  generatedAt: '2026-10-23T00:00:00Z',
});

function renderIt() {
  return render(
    <SWRConfig value={{ provider: () => new Map(), dedupingInterval: 0, shouldRetryOnError: false }}>
      <MitreRuleHeatmap />
    </SWRConfig>,
  );
}

beforeEach(() => {
  api.coverage.mockReset();
});

describe('MitreRuleHeatmap', () => {
  it('says there is nothing when no rule carries a MITRE tag', async () => {
    api.coverage.mockResolvedValue(coverage([], []));
    renderIt();
    expect(await screen.findByText('No MITRE-mapped rules yet')).toBeInTheDocument();
  });

  it('shows the error with a Retry that asks again', async () => {
    api.coverage.mockRejectedValueOnce(new Error('detection down')).mockResolvedValueOnce(coverage([cell('T1110', 'credential-access', 2)], ['credential-access']));
    renderIt();
    expect(await screen.findByText("Couldn't load detection coverage")).toBeInTheDocument();
    await userEvent.click(screen.getByRole('button', { name: /retry|try again/i }));
    expect(await screen.findByText('T1110')).toBeInTheDocument();
  });

  it('shows the totals, with how many techniques are covered of how many', async () => {
    api.coverage.mockResolvedValue(coverage([cell('T1110', 'credential-access', 2), cell('T1059', 'execution', 0, 1)], ['credential-access', 'execution'], { totalRules: 20, activeRules: 15, inactiveRules: 5 }));
    renderIt();
    await screen.findByText('Total rules');
    const value = (label: string) => (screen.getByText(label).parentElement as HTMLElement).textContent;
    expect(value('Total rules')).toContain('20');
    expect(value('Enabled rules')).toContain('15');
    expect(value('Disabled rules')).toContain('5');
    expect(value('Techniques covered')).toContain('1 / 2');
  });

  it('draws one column per tactic with a readable name and a technique count, most-covered technique first', async () => {
    api.coverage.mockResolvedValue(coverage([cell('T1003', 'credential-access', 1), cell('T1110', 'credential-access', 4), cell('T1059', 'execution', 2)], ['credential-access', 'execution', 'lateral_movement']));
    renderIt();
    const col = (await screen.findByTestId('tactic-column-credential-access')) as HTMLElement;
    expect(within(col).getByText('Credential Access')).toBeInTheDocument();
    expect(within(col).getByText('2 techniques')).toBeInTheDocument();
    expect(within(col).getAllByText(/^T1\d+$/).map((e) => e.textContent)).toEqual(['T1110', 'T1003']);
    expect(within(screen.getByTestId('tactic-column-execution')).getByText('1 technique')).toBeInTheDocument();
    const empty = screen.getByTestId('tactic-column-lateral_movement');
    expect(within(empty).getByText('Lateral Movement')).toBeInTheDocument();
    expect(within(empty).getByText('No rules')).toBeInTheDocument();
  });

  it('shades by how many rules are on, marks "rules exist but none are on" as a tuning gap, and leaves no-rule cells plain', async () => {
    api.coverage.mockResolvedValue(coverage([cell('T0005', 't', 5), cell('T0003', 't', 3), cell('T0002', 't', 2), cell('T0001', 't', 1), cell('T0000', 't', 0, 2), cell('T0099', 't', 0, 0)], ['t']));
    renderIt();
    await screen.findByText('T0005');
    const cls = (id: string) => (screen.getByText(id).closest('div[title]') as HTMLElement).className;
    expect(cls('T0005')).toContain('bg-emerald-500/70');
    expect(cls('T0003')).toContain('bg-emerald-500/45');
    expect(cls('T0002')).toContain('bg-emerald-500/30');
    expect(cls('T0001')).toContain('bg-emerald-500/15');
    expect(cls('T0000')).toContain('bg-amber-500/15');
    expect(cls('T0099')).toContain('bg-gray-800/40');
  });

  it('each technique says how many rules are on, off and in total when you point at it', async () => {
    api.coverage.mockResolvedValue(coverage([cell('T1110', 'credential-access', 2, 1), cell('T1059', 'credential-access', 3)], ['credential-access']));
    renderIt();
    expect((await screen.findByText('T1110')).closest('div[title]')).toHaveAttribute('title', 'T1110 • 2 enabled / 3 total • 1 disabled');
    expect(screen.getByText('T1059').closest('div[title]')).toHaveAttribute('title', 'T1059 • 3 enabled / 3 total');
  });

  it('shows techniques whose rules name no tactic under Unmapped, so they are not counted and then lost', async () => {
    api.coverage.mockResolvedValue(coverage([cell('T1110', 'credential-access', 1), cell('T1999', null, 2)], ['credential-access']));
    renderIt();
    await screen.findByText('T1110');
    expect(screen.getByText('T1999')).toBeInTheDocument();
    expect(within(screen.getByTestId('tactic-column-unmapped')).getByText('Unmapped')).toBeInTheDocument();
  });

  it('shows a technique whose tactic the list left out, rather than dropping it', async () => {
    api.coverage.mockResolvedValue(coverage([cell('T1110', 'credential-access', 1), cell('T1486', 'impact', 1)], ['credential-access']));
    renderIt();
    await screen.findByText('T1110');
    expect(screen.getByText('T1486')).toBeInTheDocument();
    expect(screen.getByTestId('tactic-column-impact')).toBeInTheDocument();
  });

  it('adds no Unmapped column when every technique has a tactic', async () => {
    api.coverage.mockResolvedValue(coverage([cell('T1110', 'credential-access', 1)], ['credential-access']));
    renderIt();
    await screen.findByText('T1110');
    expect(screen.queryByTestId('tactic-column-unmapped')).toBeNull();
  });

  it('explains the colours', async () => {
    api.coverage.mockResolvedValue(coverage([cell('T1110', 'credential-access', 1)], ['credential-access']));
    renderIt();
    expect(await screen.findByText('Active rules:')).toBeInTheDocument();
    expect(screen.getByText('tuning gap (rules disabled)')).toBeInTheDocument();
    for (const label of ['1', '2', '3–4', '5+']) expect(screen.getAllByText(label).length).toBeGreaterThan(0);
  });
});
