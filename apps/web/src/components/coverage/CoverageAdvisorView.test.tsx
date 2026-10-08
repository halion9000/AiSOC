import { beforeEach, describe, expect, it, vi } from 'vitest';
import { render, screen, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { SWRConfig } from 'swr';
import type { DetectionCoverage, DetectionCoverageCell } from '@/lib/api';

const coverage = vi.hoisted(() => vi.fn());
vi.mock('@/lib/api', () => ({ detectionApi: { coverage } }));

import CoverageAdvisorView, { assessTechnique, REFERENCE_TECHNIQUES } from './CoverageAdvisorView';

// This page hard-coded a coverage STATUS for 15 techniques (covered / partial / gap), a priority for each, and recommendations such as "Ransomware canary files active" and "Rate-limit rules deployed
// across tenants", then computed its summary cards from them: an assessment no one had made, with false claims about deployed rules, shown identically to every workspace. Its "Generate Detection"
// button toasted "Detection rule draft created for T1053" and created nothing.
const OLD_CLAIMS = [
  'Existing PowerShell & Bash rules active',
  'ScriptBlock logging rule deployed',
  'Ransomware canary files active',
  'Rate-limit rules deployed across tenants',
  'Service creation audit rule active',
];
const cell = (techniqueId: string, active: number, inactive = 0): DetectionCoverageCell => ({ techniqueId, tactic: null, totalRules: active + inactive, activeRules: active, inactiveRules: inactive });
const coverageOf = (cells: DetectionCoverageCell[]): DetectionCoverage => ({
  tactics: [],
  cells,
  summary: {
    totalRules: cells.reduce((s, c) => s + c.totalRules, 0),
    activeRules: cells.reduce((s, c) => s + c.activeRules, 0),
    inactiveRules: cells.reduce((s, c) => s + c.inactiveRules, 0),
    techniques: cells.length,
    coveredTechniques: cells.filter((c) => c.activeRules > 0).length,
  },
  generatedAt: '2026-10-08T00:00:00Z',
});

function renderView() {
  return render(
    <SWRConfig value={{ provider: () => new Map(), dedupingInterval: 0 }}>
      <CoverageAdvisorView />
    </SWRConfig>,
  );
}
const card = (label: string) => screen.getByText(label).nextElementSibling!.textContent;
const rowFor = (id: string) => within(screen.getByRole('table')).getByText(id).closest('tr')!;

beforeEach(() => {
  coverage.mockReset();
});

describe('assessTechnique', () => {
  const t = REFERENCE_TECHNIQUES.find((x) => x.id === 'T1059')!;

  it('is a gap with no rule mapped at all', () => {
    expect(assessTechnique(t, [])).toMatchObject({ status: 'gap', activeRules: 0, totalRules: 0 });
  });
  it('is partial when rules are mapped but none is active', () => {
    expect(assessTechnique(t, [cell('T1059', 0, 2)])).toMatchObject({ status: 'partial', activeRules: 0, totalRules: 2 });
  });
  it('is covered with at least one active rule', () => {
    expect(assessTechnique(t, [cell('T1059', 1, 1)])).toMatchObject({ status: 'covered', activeRules: 1, totalRules: 2 });
  });
  it('counts a sub-technique (T1059.001 covers T1059), summing its rules', () => {
    expect(assessTechnique(t, [cell('T1059', 1), cell('T1059.001', 2), cell('T1059.003', 0, 1)])).toMatchObject({ status: 'covered', activeRules: 3, totalRules: 4 });
  });
  it('does not confuse similarly numbered techniques', () => {
    expect(assessTechnique(t, [cell('T10590', 5), cell('T1059X', 5), cell('T105', 5), cell('T1053', 5)]).status).toBe('gap');
  });
  it('does not credit a parent technique to its sub-technique', () => {
    const sub = REFERENCE_TECHNIQUES.find((x) => x.id === 'T1059.001')!;
    expect(assessTechnique(sub, [cell('T1059', 3)]).status).toBe('gap');
  });
});

describe('a workspace with no detection rules', () => {
  it('shows EVERY reference technique as a gap, and claims nothing is deployed or covered', async () => {
    coverage.mockResolvedValue(coverageOf([]));
    const { container } = renderView();
    await screen.findByRole('table');
    const table = within(screen.getByRole('table'));
    expect(table.getAllByRole('row')).toHaveLength(REFERENCE_TECHNIQUES.length + 1);
    expect(table.getAllByText('Gap')).toHaveLength(REFERENCE_TECHNIQUES.length);
    expect(table.queryByText('Covered')).not.toBeInTheDocument();
    expect(table.queryByText('Partial')).not.toBeInTheDocument();
    expect(card('Techniques Covered')).toBe('0');
    expect(card('Coverage %')).toBe('0%');
    expect(card('Critical Gaps')).toBe(String(REFERENCE_TECHNIQUES.length));
    for (const claim of OLD_CLAIMS) expect(container.textContent).not.toContain(claim);
    expect(screen.getByText(/using the 0 active of 0 detection rules in this workspace/)).toBeInTheDocument();
  });
});

describe('a workspace with some rules', () => {
  beforeEach(() => {
    coverage.mockResolvedValue(coverageOf([cell('T1059.001', 2), cell('T1053', 0, 1), cell('T1486', 1)]));
  });

  it('computes each status and the summary from the real rules', async () => {
    renderView();
    await screen.findByRole('table');
    expect(within(rowFor('T1059')).getByText('Covered')).toBeInTheDocument(); // through its sub-technique
    expect(within(rowFor('T1059.001')).getByText('Covered')).toBeInTheDocument();
    expect(within(rowFor('T1486')).getByText('Covered')).toBeInTheDocument();
    expect(within(rowFor('T1053')).getByText('Partial')).toBeInTheDocument();
    expect(within(rowFor('T1021')).getByText('Gap')).toBeInTheDocument();
    expect(card('Techniques Covered')).toBe('3');
    expect(card('Coverage %')).toBe('20%'); // 3 of 15
    expect(card('Critical Gaps')).toBe('11');
    expect(card('Recommended Detections')).toBe('12');
    expect(screen.getByText(/using the 3 active of 4 detection rules/)).toBeInTheDocument();
  });

  it('reports the real rule counts and what they mean, not a claim about deployments', async () => {
    renderView();
    await screen.findByRole('table');
    expect(within(rowFor('T1059.001')).getByText('2 / 2')).toBeInTheDocument();
    expect(within(rowFor('T1059.001')).getByText('Covered by 2 active rules')).toBeInTheDocument();
    expect(within(rowFor('T1486')).getByText('Covered by 1 active rule')).toBeInTheDocument();
    expect(within(rowFor('T1053')).getByText(/1 mapped rule, none active\. Enable or tune one\./)).toBeInTheDocument();
    expect(within(rowFor('T1021')).getByText('Monitor RDP/SSH lateral pivots')).toBeInTheDocument();
  });

  it('derives priority from the status', async () => {
    renderView();
    await screen.findByRole('table');
    expect(within(rowFor('T1021')).getByText('High')).toBeInTheDocument();
    expect(within(rowFor('T1053')).getByText('Medium')).toBeInTheDocument();
    expect(within(rowFor('T1486')).getByText('Low')).toBeInTheDocument();
  });

  it('links to the real rule editor for what is not covered, and offers nothing for what is', async () => {
    const { container } = renderView();
    await screen.findByRole('table');
    expect(within(rowFor('T1021')).getByRole('link', { name: 'Create rule' })).toHaveAttribute('href', '/detection/new');
    expect(within(rowFor('T1053')).getByRole('link', { name: 'Create rule' })).toHaveAttribute('href', '/detection/new');
    expect(within(rowFor('T1486')).queryByRole('link', { name: 'Create rule' })).not.toBeInTheDocument();
    expect(container.textContent).not.toContain('Generate Detection');
    expect(screen.getByRole('link', { name: /See the full ATT&CK matrix/ })).toHaveAttribute('href', '/detection/coverage');
  });

  it('filters by status', async () => {
    renderView();
    await screen.findByRole('table');
    await userEvent.setup().click(screen.getByRole('button', { name: 'Partial' }));
    const rows = within(screen.getByRole('table')).getAllByRole('row');
    expect(rows).toHaveLength(2); // header + T1053
    expect(within(rows[1]).getByText('T1053')).toBeInTheDocument();
  });
});

describe('when coverage cannot be loaded', () => {
  it('says so, with a Retry, and shows no assessment at all', async () => {
    coverage.mockRejectedValueOnce(new Error('HTTP 500'));
    renderView();
    expect(await screen.findByText("Couldn't load detection coverage")).toBeInTheDocument();
    expect(screen.getByText(/HTTP 500/)).toBeInTheDocument();
    expect(screen.queryByRole('table')).not.toBeInTheDocument();
    expect(screen.queryByText('Coverage %')).not.toBeInTheDocument();

    coverage.mockResolvedValue(coverageOf([]));
    await userEvent.setup().click(screen.getByRole('button', { name: /retry|try again/i }));
    expect(await screen.findByRole('table')).toBeInTheDocument();
  });
});
