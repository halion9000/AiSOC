import { describe, expect, it } from 'vitest';
import { render, screen } from '@testing-library/react';

import { KpiBar } from './KpiBar';
import type { EvalReport } from './BenchmarkResults';

const report = (suites: Record<string, unknown>): EvalReport => ({ suites }) as unknown as EvalReport;
const card = (label: string) => screen.getByText(label).closest('div.rounded-lg') as HTMLElement;

describe('KpiBar', () => {
  it('shows the four published targets', () => {
    render(<KpiBar report={report({})} />);
    expect(card('False-positive rate')).toHaveTextContent('≤ 5%');
    expect(card('Alert-to-incident ratio')).toHaveTextContent('≥ 50:1');
    expect(card('MITRE technique tagging')).toHaveTextContent('≥ 85%');
    expect(card('MITRE sub-technique tagging')).toHaveTextContent('≥ 60%');
  });

  it('marks the targets the open harness cannot measure as measured in the app, with no invented number', () => {
    render(<KpiBar report={report({})} />);
    for (const label of ['False-positive rate', 'MITRE sub-technique tagging', 'Alert-to-incident ratio', 'MITRE technique tagging']) {
      expect(card(label)).toHaveTextContent('in-app');
      expect(card(label)).not.toHaveTextContent('Live:');
    }
  });

  it('works out the alert-to-incident ratio from the reduction suite and marks a pass at 50:1 or better', () => {
    render(<KpiBar report={report({ alert_reduction: { details: { alerts_in: 1000, incidents_out: 20 } } })} />);
    const c = card('Alert-to-incident ratio');
    expect(c).toHaveTextContent('Live: 50.0:1');
    expect(c.querySelector('span.bg-emerald-400')).not.toBeNull();
  });

  it('marks a ratio under 50:1 as a miss', () => {
    render(<KpiBar report={report({ alert_reduction: { details: { alerts_in: 1000, incidents_out: 40 } } })} />);
    const c = card('Alert-to-incident ratio');
    expect(c).toHaveTextContent('Live: 25.0:1');
    expect(c.querySelector('span.bg-rose-400')).not.toBeNull();
  });

  it('assumes 1,000 alerts in when the suite does not say, and shows no ratio when nothing came out', () => {
    const { unmount } = render(<KpiBar report={report({ alert_reduction: { details: { incidents_out: 10 } } })} />);
    expect(card('Alert-to-incident ratio')).toHaveTextContent('Live: 100.0:1');
    unmount();
    render(<KpiBar report={report({ alert_reduction: { details: { alerts_in: 1000, incidents_out: 0 } } })} />);
    expect(card('Alert-to-incident ratio')).not.toHaveTextContent('Live:');
  });

  it('shows MITRE tagging accuracy as a percentage and passes it at 85% exactly', () => {
    const { unmount } = render(<KpiBar report={report({ mitre_accuracy: { per_template: { value: 0.85 } } })} />);
    const pass = card('MITRE technique tagging');
    expect(pass).toHaveTextContent('Live: 85.0%');
    expect(pass.querySelector('span.bg-emerald-400')).not.toBeNull();
    unmount();
    render(<KpiBar report={report({ mitre_accuracy: { per_template: { value: 0.8499 } } })} />);
    expect(card('MITRE technique tagging').querySelector('span.bg-rose-400')).not.toBeNull();
  });

  it('a value that is not a number is shown as not measured', () => {
    render(<KpiBar report={report({ mitre_accuracy: { per_template: { value: 'n/a' } } })} />);
    expect(card('MITRE technique tagging')).not.toHaveTextContent('Live:');
  });

  it('links to where the targets are defined, in a new tab', () => {
    render(<KpiBar report={report({})} />);
    const link = screen.getByRole('link', { name: /sla\.py/ });
    expect(link).toHaveAttribute('target', '_blank');
    expect(link.getAttribute('rel')).toContain('noreferrer');
  });
});
