import { beforeEach, describe, expect, it, vi } from 'vitest';
import { render, screen } from '@testing-library/react';

const authFetch = vi.hoisted(() => vi.fn());
vi.mock('@/lib/auth-session', () => ({ authFetch }));

import InvestigationTimeline from './InvestigationTimeline';

// With no run selected, this showed makeDemoTimeline(): an invented investigation of alice@example.com ("Suspending Okta session for alice@example.com", "Classified as credential-stuffing
// attack; routing to Identity investigation") under a made-up case id, as if it were the analyst's own run.
const INVENTED = ['alice@example.com', 'Okta', 'credential-stuffing', 'CASE-001', 'demo-run'];
const json = (status: number, body: unknown) => new Response(JSON.stringify(body), { status, headers: { 'content-type': 'application/json' } });
const realTimeline = {
  run_id: 'run-77',
  case_id: 'INC-777',
  status: 'completed',
  total_duration_ms: 5000,
  attempt_count: 1,
  nodes: [
    { seq: 1, ts: '2026-10-08T01:00:00Z', kind: 'run_start', agent: 'orchestrator', summary: 'Investigation started for INC-777', duration_ms: 10, decision: null, has_artifact: false, diff_vs_prev_attempt: null },
  ],
};

beforeEach(() => {
  authFetch.mockReset();
});

describe('with no run selected', () => {
  it('shows an honest empty state, calls nothing, and invents nothing', () => {
    const { container } = render(<InvestigationTimeline />);
    expect(screen.getByText('Select an investigation to see its timeline.')).toBeInTheDocument();
    expect(authFetch).not.toHaveBeenCalled();
    for (const invented of INVENTED) expect(container.textContent).not.toContain(invented);
  });
});

describe('with a run', () => {
  it('shows the run the server returned', async () => {
    authFetch.mockResolvedValue(json(200, realTimeline));
    const { container } = render(<InvestigationTimeline runId="run-77" />);
    expect(await screen.findByText('Investigation started for INC-777')).toBeInTheDocument();
    expect(screen.getAllByText(/INC-777/).length).toBeGreaterThanOrEqual(2); // the header's case id and the event's own summary
    expect(authFetch.mock.calls[0][0]).toBe('/api/v1/investigations/run-77/timeline');
    for (const invented of INVENTED) expect(container.textContent).not.toContain(invented);
  });

  it('shows the error, and no invented timeline, when it cannot be loaded', async () => {
    authFetch.mockResolvedValue(json(500, { detail: 'boom' }));
    const { container } = render(<InvestigationTimeline runId="run-77" />);
    expect(await screen.findByText('HTTP 500')).toBeInTheDocument();
    for (const invented of INVENTED) expect(container.textContent).not.toContain(invented);
  });

  it('drops the previous run, and shows the empty state, when the selection is cleared', async () => {
    authFetch.mockResolvedValue(json(200, realTimeline));
    const { rerender } = render(<InvestigationTimeline runId="run-77" />);
    await screen.findByText('Investigation started for INC-777');
    rerender(<InvestigationTimeline />);
    expect(await screen.findByText('Select an investigation to see its timeline.')).toBeInTheDocument();
    expect(screen.queryByText('Investigation started for INC-777')).not.toBeInTheDocument();
  });
});
