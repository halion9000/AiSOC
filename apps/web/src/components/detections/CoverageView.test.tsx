import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { render, screen, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { SWRConfig } from 'swr';

import { CoverageView } from './CoverageView';

const index = {
  version: '1',
  generated: '2026-10-01',
  stats: { total: 120, detections: 100, detections_by_tier: { stable: 60, imported: 30, community: 10 }, quarantined: 7 },
  mitre_coverage: {
    unique_techniques: 4,
    total_with_mitre: 55,
    techniques: { T1110: 12, T1059: 3, 'T1059.001': 1, T1003: 5 },
    by_tier: { stable: { T1110: 12, T1003: 5 }, imported: { T1059: 3 }, community: { 'T1059.001': 1 } },
  },
};

function mockFetch(body: unknown, ok = true, status = 200) {
  const f = vi.fn().mockResolvedValue({ ok, status, json: async () => body });
  vi.stubGlobal('fetch', f);
  return f;
}

function renderView() {
  return render(
    <SWRConfig value={{ provider: () => new Map(), dedupingInterval: 0, shouldRetryOnError: false }}>
      <CoverageView />
    </SWRConfig>,
  );
}

beforeEach(() => vi.unstubAllGlobals());
afterEach(() => vi.unstubAllGlobals());

describe('CoverageView', () => {
  it('shows a loading message first', () => {
    vi.stubGlobal('fetch', vi.fn(() => new Promise(() => {})));
    renderView();
    expect(screen.getByText('Loading coverage…')).toBeInTheDocument();
  });

  it('tells how to build the file when it cannot be loaded', async () => {
    const f = mockFetch({}, false, 404);
    renderView();
    expect(await screen.findByText(/Could not load/)).toBeInTheDocument();
    expect(screen.getByText('python3 scripts/build_marketplace.py')).toBeInTheDocument();
    expect(f).toHaveBeenCalledWith('/marketplace/index.json', { cache: 'no-store' });
  });

  it('says the same when the file has no MITRE section', async () => {
    mockFetch({ version: '1', generated: 'x' });
    renderView();
    expect(await screen.findByText(/Could not load/)).toBeInTheDocument();
  });

  it('shows the summary numbers and the tier breakdown', async () => {
    mockFetch(index);
    renderView();
    const techniques = (await screen.findByText('Techniques covered')).parentElement as HTMLElement;
    expect(within(techniques).getByText('4')).toBeInTheDocument();
    expect(within(techniques).getByText('across all tiers')).toBeInTheDocument();
    const withMitre = screen.getByText('Rules with MITRE').parentElement as HTMLElement;
    expect(within(withMitre).getByText('55')).toBeInTheDocument();
    expect(within(withMitre).getByText('of 100 detection rules')).toBeInTheDocument();
    const rules = screen.getByText('Detection rules').parentElement as HTMLElement;
    expect(within(rules).getByText('100')).toBeInTheDocument();
    expect(within(rules).getByText('stable').nextElementSibling).toHaveTextContent('60');
    expect(within(rules).getByText('community').nextElementSibling).toHaveTextContent('10');
    expect(within(screen.getByText('Quarantined').parentElement as HTMLElement).getByText('7')).toBeInTheDocument();
  });

  it('groups techniques under their tactic in kill-chain order, most-covered first, sub-techniques under the parent tactic', async () => {
    mockFetch(index);
    renderView();
    await screen.findByText('Techniques covered');
    const columns = ['TA0002', 'TA0006'].map((id) => screen.getByText(id).parentElement?.parentElement as HTMLElement);
    // Execution comes before Credential Access.
    expect(columns[0].compareDocumentPosition(columns[1]) & Node.DOCUMENT_POSITION_FOLLOWING).toBeTruthy();
    expect(within(columns[0]).getByText('2 techniques')).toBeInTheDocument();
    expect(within(columns[0]).getByText('T1059.001')).toBeInTheDocument();
    const cred = within(columns[1]).getAllByRole('link').map((a) => a.textContent);
    expect(cred[0]).toMatch(/^T111012/);
    expect(cred[1]).toMatch(/^T10035/);
    expect(within(columns[1]).getByText('2 techniques')).toBeInTheDocument();
  });

  it('each technique links to MITRE (sub-techniques with a slash) and says how many rules cover it', async () => {
    mockFetch(index);
    renderView();
    await screen.findByText('Techniques covered');
    const sub = screen.getByText('T1059.001').closest('a');
    expect(sub).toHaveAttribute('href', 'https://attack.mitre.org/techniques/T1059/001/');
    expect(sub).toHaveAttribute('target', '_blank');
    expect(sub).toHaveAttribute('rel', 'noopener noreferrer');
    expect(sub).toHaveAttribute('title', 'T1059.001 — 1 rule');
    expect(screen.getByText('T1110').closest('a')).toHaveAttribute('title', 'T1110 — 12 rules');
  });

  it('heatmap shade follows the count', async () => {
    mockFetch(index);
    renderView();
    await screen.findByText('Techniques covered');
    expect(screen.getByText('T1110').closest('a')?.className).toContain('bg-emerald-500/80');
    expect(screen.getByText('T1003').closest('a')?.className).toContain('bg-emerald-500/55');
    expect(screen.getByText('T1059').closest('a')?.className).toContain('bg-emerald-500/35');
    expect(screen.getByText('T1059.001').closest('a')?.className).toContain('bg-emerald-500/15');
  });

  it('a tier filter shows only that tier and says how many techniques are shown', async () => {
    mockFetch(index);
    renderView();
    await screen.findByText('Techniques covered');
    await userEvent.click(screen.getByRole('button', { name: 'Imported' }));
    expect(screen.getByText('T1059')).toBeInTheDocument();
    expect(screen.queryByText('T1110')).toBeNull();
    expect(screen.queryByText('T1059.001')).toBeNull();
    expect(screen.getByText('in Imported tier (1 shown)')).toBeInTheDocument();
    await userEvent.click(screen.getByRole('button', { name: 'All tiers' }));
    expect(screen.getByText('T1110')).toBeInTheDocument();
  });

  it('a tier with nothing in it says so instead of drawing an empty matrix', async () => {
    mockFetch({ ...index, mitre_coverage: { ...index.mitre_coverage, by_tier: { stable: { T1110: 12 } } } });
    renderView();
    await screen.findByText('Techniques covered');
    await userEvent.click(screen.getByRole('button', { name: 'Community' }));
    expect(screen.getByText('No techniques covered for this tier yet.')).toBeInTheDocument();
  });

  it('a technique the tactic table does not know goes under Other rather than disappearing', async () => {
    mockFetch({ ...index, mitre_coverage: { ...index.mitre_coverage, techniques: { T9999: 2 }, by_tier: { stable: { T9999: 2 } } } });
    renderView();
    await screen.findByText('Techniques covered');
    expect(screen.getByText('T9999')).toBeInTheDocument();
  });
});
