import { beforeEach, describe, expect, it, vi } from 'vitest';
import { render, screen, waitFor } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { SWRConfig } from 'swr';

const api = vi.hoisted(() => ({ queue: vi.fn(), stats: vi.fn() }));
vi.mock('@/lib/api', () => ({ entityRiskApi: api }));

import { EntityRiskQueue } from './EntityRiskQueue';

const stamp = '2026-10-08T01:00:00Z';
const record = (value: string, score: number, promoted: boolean) => ({
  tenant_id: 't1', entity_type: 'user', entity_value: value, score, display_score: score, threshold: 80, promoted, promoted_incident_id: null,
  last_seen: stamp, first_seen: stamp, contributions: [], severity_histogram: { critical: 0, high: 1, medium: 0, low: 0, info: 0 }, alert_count: 3,
});
const stats = { tenant_id: 't1', threshold: 80, total: 2, promoted: 1, bands: { critical: 1, high: 0, medium: 1, low: 0 }, alert_count: 40 };

function renderQueue() {
  return render(
    <SWRConfig value={{ provider: () => new Map(), dedupingInterval: 0, shouldRetryOnError: false }}>
      <EntityRiskQueue />
    </SWRConfig>,
  );
}
/** The text of the stat tile with this label, e.g. "2Active entities". */
const tile = (label: string) => screen.getByText(label).parentElement!.textContent ?? '';

beforeEach(() => {
  Object.values(api).forEach((m) => m.mockReset());
  api.queue.mockResolvedValue({ tenant_id: 't1', threshold: 80, entities: [record('alice', 91, true), record('bob', 40, false)] });
  api.stats.mockResolvedValue(stats);
});

// When the queue could not be loaded this screen said "Fusion service unreachable, showing demo entity queue so you can explore Risk-Based Alerting" (no demo queue exists), and then fell through
// to "No entities are currently being tracked." (a failure presented as an empty queue), with every tile computed from nothing: 0 entities, 0 promoted, 0 alerts, and an alert:incident ratio of 0:0 below the bar.
describe('when the queue loads', () => {
  it('shows the real entities and the real figures, with no demo wording', async () => {
    const { container } = renderQueue();
    expect(await screen.findByText('alice')).toBeInTheDocument();
    expect(screen.getByText('bob')).toBeInTheDocument();
    await waitFor(() => expect(tile('Active entities')).toContain('2'));
    expect(tile('Contributing alerts')).toContain('40');
    expect(container.textContent).not.toMatch(/demo/i);
  });

  it('still says so when there genuinely are no entities, and for the promoted-only filter', async () => {
    api.queue.mockResolvedValue({ tenant_id: 't1', threshold: 80, entities: [] });
    api.stats.mockResolvedValue({ ...stats, total: 0, promoted: 0, alert_count: 0 });
    renderQueue();
    expect(await screen.findByText('No entities are currently being tracked.')).toBeInTheDocument();
    await userEvent.setup().click(screen.getByRole('button', { name: 'Promoted only' }));
    expect(await screen.findByText('No entities have crossed the promotion threshold yet.')).toBeInTheDocument();
    expect(screen.queryByText("Couldn't load the entity queue")).not.toBeInTheDocument();
  });
});

describe('when the queue cannot be loaded', () => {
  beforeEach(() => {
    api.queue.mockRejectedValue(new Error('HTTP 503'));
    api.stats.mockRejectedValue(new Error('HTTP 503'));
  });

  it('says so with the reason and a working Retry, and does not claim nothing is being tracked', async () => {
    const { container } = renderQueue();
    expect(await screen.findByText("Couldn't load the entity queue")).toBeInTheDocument();
    expect(screen.getByText(/HTTP 503/)).toBeInTheDocument();
    expect(screen.queryByText('No entities are currently being tracked.')).not.toBeInTheDocument();
    expect(container.textContent).not.toMatch(/demo/i);

    api.queue.mockResolvedValue({ tenant_id: 't1', threshold: 80, entities: [record('alice', 91, true)] });
    api.stats.mockResolvedValue(stats);
    await userEvent.setup().click(screen.getByRole('button', { name: 'Retry' }));
    expect(await screen.findByText('alice')).toBeInTheDocument();
    expect(screen.queryByText("Couldn't load the entity queue")).not.toBeInTheDocument();
  });

  it('shows dashes, never invented zeros or a 0:0 ratio, for the figures it does not know', async () => {
    renderQueue();
    await screen.findByText("Couldn't load the entity queue");
    for (const label of ['Active entities', 'Promoted', 'Contributing alerts', 'Alert \u2192 Incident']) {
      expect(tile(label)).toContain('\u2014');
      expect(tile(label)).not.toMatch(/(^|\D)0(\D|$)/);
    }
    expect(screen.queryByText('0:0')).not.toBeInTheDocument();
    expect(screen.getByText(/\u2014 shown/)).toBeInTheDocument();
  });

  it('still shows the stats figures when only the queue failed (they come from a separate call and are real)', async () => {
    api.stats.mockResolvedValue(stats);
    renderQueue();
    await screen.findByText("Couldn't load the entity queue");
    await waitFor(() => expect(tile('Active entities')).toContain('2'));
    expect(tile('Contributing alerts')).toContain('40');
  });
});
