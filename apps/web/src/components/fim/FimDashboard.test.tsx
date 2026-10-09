import { beforeEach, describe, expect, it, vi } from 'vitest';
import { render, screen, waitFor } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { SWRConfig } from 'swr';

const osq = vi.hoisted(() => ({ getFimEvents: vi.fn(), getFimSummary: vi.fn() }));
vi.mock('@/lib/osquery-api', () => osq);

import { FimDashboard } from './FimDashboard';

const stamp = '2026-10-09T10:00:00Z';
const event = (id: number, path: string) => ({
  id, tenant_id: 't1', node_key: 'node-1', hostname: 'host-1', target_path: path, action: 'UPDATED', md5: null, sha256: null, pid: 1, ppid: 0, process_name: 'vim', username: 'root', event_time: stamp, ingested_at: stamp,
});
const page = (path: string, p = 1) => ({ events: [event(p, path)], total: 60, page: p, page_size: 25 });
const summary = { total_events: 60, by_action: [{ action: 'UPDATED', count: 60 }], top_paths: [{ target_path: '/etc/passwd', count: 5 }], active_nodes: 3 };
const lastEvents = () => osq.getFimEvents.mock.calls.at(-1)![0] as { tenant_id?: string; page: number };

function renderDashboard() {
  return render(
    <SWRConfig value={{ provider: () => new Map(), dedupingInterval: 0, shouldRetryOnError: false }}>
      <FimDashboard />
    </SWRConfig>,
  );
}

beforeEach(() => {
  Object.values(osq).forEach((m) => m.mockReset());
  osq.getFimEvents.mockImplementation(async (p: { page: number }) => page('/etc/hosts', p.page));
  osq.getFimSummary.mockResolvedValue(summary);
});

// THE REQUEST STORM. The time window was computed at render time (`new Date()`) and used in the SWR key, so every finished fetch caused a re-render with a NEW key and therefore another fetch: against a server that answers in 20 ms the idle page made about 80 requests a second.
// With instant mocks it never yielded at all (the test run simply hung). The keys now carry the chosen option and the timestamp is computed when the request is made.
const later = <T,>(value: T, ms = 20) => new Promise<T>((resolve) => setTimeout(() => resolve(value), ms));

describe('the request storm', () => {
  it('makes a bounded number of requests while idle, not one per render', async () => {
    osq.getFimEvents.mockImplementation(() => later(page('/etc/hosts')));
    osq.getFimSummary.mockImplementation(() => later(summary));
    renderDashboard();
    await screen.findByText('/etc/hosts');
    await new Promise((r) => setTimeout(r, 400)); // twenty server round trips' worth of time
    expect(osq.getFimEvents.mock.calls.length).toBeLessThanOrEqual(2);
    expect(osq.getFimSummary.mock.calls.length).toBeLessThanOrEqual(2);
  });
});

describe('the time window', () => {
  const sinceOf = (call: unknown[]) => (call[0] as { since?: string }).since;
  const minutesAgo = (iso: string | undefined) => (Date.now() - new Date(iso as string).getTime()) / 60_000;

  it('is computed from the chosen option when the request is made (24 hours by default)', async () => {
    renderDashboard();
    await screen.findByText('/etc/hosts');
    expect(minutesAgo(sinceOf(osq.getFimEvents.mock.calls[0]))).toBeCloseTo(24 * 60, -1);
    expect(minutesAgo(sinceOf(osq.getFimSummary.mock.calls[0]))).toBeCloseTo(24 * 60, -1);
  });

  it('follows the option the user picks, for the events and the summary', async () => {
    renderDashboard();
    await screen.findByText('/etc/hosts');
    await userEvent.setup().selectOptions(screen.getByDisplayValue('Last 24 hours'), 'Last 1 hour');
    await waitFor(() => expect(minutesAgo(sinceOf(osq.getFimEvents.mock.calls.at(-1)!))).toBeCloseTo(60, -1));
    await waitFor(() => expect(minutesAgo(sinceOf(osq.getFimSummary.mock.calls.at(-1)!))).toBeCloseTo(60, -1));
  });

  it('"All time" sends no lower bound at all', async () => {
    renderDashboard();
    await screen.findByText('/etc/hosts');
    await userEvent.setup().selectOptions(screen.getByDisplayValue('Last 24 hours'), 'All time');
    await waitFor(() => expect(sinceOf(osq.getFimEvents.mock.calls.at(-1)!)).toBeUndefined());
    await waitFor(() => expect(sinceOf(osq.getFimSummary.mock.calls.at(-1)!)).toBeUndefined());
  });

  it('changing the window goes back to page 1', async () => {
    renderDashboard();
    const user = userEvent.setup();
    await screen.findByText('/etc/hosts');
    await user.click(screen.getByRole('button', { name: /Next/ }));
    await waitFor(() => expect(lastEvents().page).toBe(2));
    await user.selectOptions(screen.getByDisplayValue('Last 24 hours'), 'Last 6 hours');
    await waitFor(() => expect(lastEvents().page).toBe(1));
  });
});
