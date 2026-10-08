import { beforeEach, describe, expect, it, vi } from 'vitest';
import { render, screen } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { SWRConfig } from 'swr';

// cytoscape needs a real canvas; nothing here draws a graph (the overview endpoint does not exist in this build), so stub it out.
vi.mock('cytoscape', () => ({ __esModule: true, default: Object.assign(vi.fn(), { use: vi.fn() }) }));
vi.mock('cytoscape-fcose', () => ({ __esModule: true, default: vi.fn() }));

const getOverview = vi.hoisted(() => vi.fn());
const getMitreCoverage = vi.hoisted(() => vi.fn());
vi.mock('@/lib/api', () => ({ __esModule: true, graphApi: { getOverview: () => getOverview(), getMitreCoverage: () => getMitreCoverage() } }));

import { AttackGraphView } from './AttackGraphView';

// When the MITRE call failed, this panel swapped in a synthetic heatmap of invented cells ("Technique 3.2" ... 72 of them, detections computed from a formula)
// labelled "Demo data", so a failed call presented made-up coverage as the tenant's own. A failure now reaches the error state, which has a Retry.
function renderView() {
  return render(
    <SWRConfig value={{ provider: () => new Map(), dedupingInterval: 0, shouldRetryOnError: false }}>
      <AttackGraphView />
    </SWRConfig>,
  );
}

const coverage = {
  tactics: ['Execution', 'Persistence'],
  generatedAt: '2026-10-08T12:00:00Z',
  cells: [
    { techniqueId: 'T1059', techniqueName: 'Command and Scripting Interpreter', tactic: 'Execution', detections: 4, alerts: 9, intensity: 0.5 },
    { techniqueId: 'T1053', techniqueName: 'Scheduled Task/Job', tactic: 'Persistence', detections: 2, alerts: 3, intensity: 0.25 },
  ],
};

beforeEach(() => {
  getOverview.mockReset().mockRejectedValue(new Error('not found'));
  getMitreCoverage.mockReset();
});

describe('the MITRE coverage panel', () => {
  it('shows the real coverage it was given', async () => {
    getMitreCoverage.mockResolvedValue(coverage);
    const { container } = renderView();
    expect(await screen.findByText('Command and Scripting Interpreter', { exact: false })).toBeInTheDocument();
    expect(container.textContent).not.toMatch(/Technique \d+\.\d+/);
    expect(container.textContent).not.toMatch(/demo data/i);
  });

  it('shows an error with a Retry, never invented coverage, when the call fails', async () => {
    getMitreCoverage.mockRejectedValueOnce(new Error('503 upstream unavailable')).mockResolvedValue(coverage);
    const { container } = renderView();
    expect(await screen.findByText("Couldn't load MITRE coverage")).toBeInTheDocument();
    expect(container.textContent).not.toMatch(/Technique \d+\.\d+/);
    expect(container.textContent).not.toMatch(/demo data/i);
    expect(container.textContent).not.toContain('Backend MITRE endpoint unavailable');
    await userEvent.setup().click(screen.getByRole('button', { name: /retry|try again/i }));
    expect(await screen.findByText('Command and Scripting Interpreter', { exact: false })).toBeInTheDocument();
  });

  it('says there is no coverage yet, and shows no cells, when the response is empty', async () => {
    getMitreCoverage.mockResolvedValue({ tactics: [], cells: [], generatedAt: '2026-10-08T12:00:00Z' });
    const { container } = renderView();
    expect(await screen.findByText('No coverage data')).toBeInTheDocument();
    expect(container.textContent).not.toMatch(/Technique \d+\.\d+/);
  });
});

describe('the graph panel', () => {
  it('has no developer-only instructions in its empty state', async () => {
    getOverview.mockResolvedValue({ nodes: [], edges: [], generatedAt: '2026-10-08T12:00:00Z' });
    getMitreCoverage.mockResolvedValue(coverage);
    const { container } = renderView();
    expect(await screen.findByText('No graph yet')).toBeInTheDocument();
    expect(container.textContent).not.toContain('pnpm demo:produce');
    expect(screen.getByText(/appear here as events are ingested/)).toBeInTheDocument();
  });

  it('still says plainly that the overview endpoint is unavailable', async () => {
    getMitreCoverage.mockResolvedValue(coverage);
    renderView();
    expect(await screen.findByText('Attack Graph Unavailable')).toBeInTheDocument();
  });
});
