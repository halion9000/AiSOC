import { afterEach, describe, expect, it, vi } from 'vitest';
import { render, screen, within } from '@testing-library/react';

import { BenchmarkResults, fetchLatestEvalReport, type EvalReport } from './BenchmarkResults';

const suite = (over: Record<string, unknown> = {}) => ({ metric: 'm', value: 0.9, target: 0.8, passed: true, ...over });
const report = (suites: Record<string, unknown>): EvalReport => ({ generated_at: 'x', dataset: 'd', all_passed: true, suites }) as unknown as EvalReport;
const card = (name: string) => screen.getByText(name, { selector: 'h3' }).closest('div.rounded-xl') as HTMLElement;

afterEach(() => vi.unstubAllGlobals());

describe('BenchmarkResults', () => {
  it('shows the four suites in a fixed order, skipping one the report does not have', () => {
    render(<BenchmarkResults report={report({ response_quality: suite(), alert_reduction: suite(), mitre_accuracy: suite() })} />);
    expect(screen.getAllByRole('heading', { level: 3 }).map((h) => h.textContent)).toEqual(['Alert reduction', 'MITRE tactic accuracy', 'Response-plan quality']);
  });

  it('ignores a suite it has no description for', () => {
    render(<BenchmarkResults report={report({ something_new: suite(), alert_reduction: suite() })} />);
    expect(screen.getAllByRole('heading', { level: 3 })).toHaveLength(1);
  });

  it('shows the value and target as percentages and how far above the gate it is', () => {
    render(<BenchmarkResults report={report({ alert_reduction: suite({ value: 0.753, target: 0.7 }) })} />);
    const c = card('Alert reduction');
    expect(within(c).getByText('75.3%')).toBeInTheDocument();
    expect(within(c).getByText('target ≥70%')).toBeInTheDocument();
    expect(within(c).getByText('+5.3 pts above gate')).toBeInTheDocument();
    expect(within(c).getByText('Pass')).toBeInTheDocument();
  });

  it('shows a failing suite as Fail with how far below the gate it is', () => {
    render(<BenchmarkResults report={report({ mitre_accuracy: suite({ value: 0.75, target: 0.8, passed: false }) })} />);
    const c = card('MITRE tactic accuracy');
    expect(within(c).getByText('Fail')).toBeInTheDocument();
    expect(within(c).getByText('-5.0 pts below gate')).toBeInTheDocument();
  });

  it('labels what each number really is: a measurement for alert reduction, self-consistency for the others', () => {
    render(<BenchmarkResults report={report({ alert_reduction: suite(), mitre_accuracy: suite(), investigation_completeness: suite(), response_quality: suite() })} />);
    expect(within(card('Alert reduction')).getByText('Real measurement')).toBeInTheDocument();
    for (const name of ['MITRE tactic accuracy', 'Investigation completeness', 'Response-plan quality']) expect(within(card(name)).getByText('Substrate self-consistency')).toBeInTheDocument();
  });

  it('lists the facts each suite reports, and leaves out one that is not a number', () => {
    render(<BenchmarkResults report={report({ alert_reduction: suite({ details: { alerts_in: 1000, incidents_out: 247, storm_incidents: 'many' } }), mitre_accuracy: suite({ details: { incidents: 200, correct: 194, f1: 0.7712 } }) })} />);
    const a = card('Alert reduction');
    expect(within(a).getByText('Alerts in').nextElementSibling).toHaveTextContent('1000');
    expect(within(a).getByText('Incidents out').nextElementSibling).toHaveTextContent('247');
    expect(within(a).queryByText('Storms')).toBeNull();
    const m = card('MITRE tactic accuracy');
    expect(within(m).getByText('Correct').nextElementSibling).toHaveTextContent('194');
    expect(within(m).getByText('F1 (per-case)').nextElementSibling).toHaveTextContent('0.77');
  });

  it('says how many incidents were fully covered, and that the judge is a keyword one', () => {
    render(<BenchmarkResults report={report({ investigation_completeness: suite({ details: { incidents: 200, fully_covered: 134, fully_covered_pct: 0.67 } }) })} />);
    const c = card('Investigation completeness');
    expect(within(c).getByText('Fully covered').nextElementSibling).toHaveTextContent('134 (67%)');
    expect(within(c).getByText('Judge').nextElementSibling).toHaveTextContent('Offline keyword');
  });

  it('shows the per-template average with the templates that fail, and none when all pass', () => {
    const perTemplate = (failing: string[]) => ({ metric: 'macro', value: 0.9636, target: 0.8, passed: true, template_count: 55, failing_templates: failing });
    const { unmount } = render(<BenchmarkResults report={report({ mitre_accuracy: suite({ per_template: perTemplate(['outlook-auto-forward-rule', 'compromised-ci-runner']) }) })} />);
    const c = card('MITRE tactic accuracy');
    expect(within(c).getByText('96.4%')).toBeInTheDocument();
    expect(within(c).getByText(/across 55 distinct/)).toBeInTheDocument();
    expect(within(c).getByText('outlook-auto-forward-rule, compromised-ci-runner')).toBeInTheDocument();
    unmount();
    render(<BenchmarkResults report={report({ mitre_accuracy: suite({ per_template: perTemplate([]) }) })} />);
    expect(screen.queryByText(/Regressions:/)).toBeNull();
  });

  it('a suite with no details shows no detail row', () => {
    render(<BenchmarkResults report={report({ alert_reduction: suite() })} />);
    expect(within(card('Alert reduction')).queryByText('Alerts in')).toBeNull();
  });
});

describe('fetchLatestEvalReport', () => {
  it('returns the published report and says where it came from', async () => {
    vi.stubGlobal('fetch', vi.fn().mockResolvedValue({ ok: true, json: async () => ({ generated_at: 'now', dataset: 'live', all_passed: true, suites: {} }) }));
    const r = await fetchLatestEvalReport();
    expect(r.dataset).toBe('live');
    expect(r._stale).toBeUndefined();
    expect(r._source).toMatch(/eval-results\/eval\/results\/latest\.json$/);
  });

  it('falls back to the saved snapshot, marked stale, when the branch is missing, the network is down or the answer is not JSON', async () => {
    for (const f of [vi.fn().mockResolvedValue({ ok: false, status: 404 }), vi.fn().mockRejectedValue(new Error('offline')), vi.fn().mockResolvedValue({ ok: true, json: async () => { throw new Error('bad json'); } })]) {
      vi.stubGlobal('fetch', f);
      const r = await fetchLatestEvalReport();
      expect(r._stale).toBe(true);
      expect(Object.keys(r.suites).sort()).toEqual(['alert_reduction', 'investigation_completeness', 'mitre_accuracy', 'response_quality']);
      expect(r._source).toBeTruthy();
    }
  });

  it('the snapshot it falls back to renders in full', async () => {
    vi.stubGlobal('fetch', vi.fn().mockRejectedValue(new Error('offline')));
    render(<BenchmarkResults report={await fetchLatestEvalReport()} />);
    expect(screen.getAllByRole('heading', { level: 3 })).toHaveLength(4);
    expect(screen.getAllByText('Pass')).toHaveLength(4);
  });
});
