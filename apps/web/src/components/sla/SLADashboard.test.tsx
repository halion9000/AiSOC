import { beforeEach, describe, expect, it, vi } from 'vitest';
import { act, render, screen, waitFor } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { SWRConfig, mutate } from 'swr';

const authFetch = vi.hoisted(() => vi.fn());
vi.mock('@/lib/auth-session', () => ({ authFetch }));

import { SLADashboard } from './SLADashboard';

const json = (status: number, body: unknown) => new Response(JSON.stringify(body), { status, headers: { 'content-type': 'application/json' } });
const METRICS_URL = '/api/v1/sla/metrics?days=30';
const metrics = {
  period_days: 30,
  computed_at: '2026-10-08T01:00:00Z',
  overall: { total_alerts: 120, total_breaches: 6, breach_rate: 5, mttd_avg: 4, mttr_avg: 35, mttc_avg: 20 },
  per_severity: { critical: { total: 10, breaches: 2, breach_rate: 20, mttd_avg: 3, mttr_avg: 30, mttc_avg: 15, mttd_target: 5, mttr_target: 60, mttc_target: 30 } },
  kpi_bar: null,
};

let metricsResponse: () => Response | Promise<Response>;

// This default cache is used on purpose: the view's own refreshes go through SWR's global mutate. No de-duplication window, or SWR hands a test the response of an identical request made <2s earlier.
const view = () => (
  <SWRConfig value={{ dedupingInterval: 0, shouldRetryOnError: false, refreshInterval: 0 }}>
    <SLADashboard />
  </SWRConfig>
);
/** The text of the summary card with this label, e.g. "Total Alerts120" (the label comes first in this layout). */
const card = (label: string) => screen.getByText(label).parentElement!.textContent ?? '';

beforeEach(async () => {
  await mutate(() => true, undefined, { revalidate: false });
  authFetch.mockReset();
  metricsResponse = () => json(200, metrics);
  authFetch.mockImplementation(async (url: string) => {
    if (url === METRICS_URL) return metricsResponse();
    if (url === '/api/v1/sla/config') return json(200, []);
    return json(404, {});
  });
});

// When the SLA metrics request failed this page said "SLA API unreachable, showing demo metrics so you can explore the dashboard" (no demo metrics exist) over a blank page; and a response of the wrong
// SHAPE (no error at all) also left a silent blank, because the page only renders metrics it has validated.
describe('when the metrics load', () => {
  it('shows the real figures, with no demo wording', async () => {
    const { container } = render(view());
    await waitFor(() => expect(card('Total Alerts')).toBe('Total Alerts120'));
    expect(card('SLA Breaches')).toBe('SLA Breaches6');
    expect(card('Breach Rate')).toBe('Breach Rate5%');
    expect(container.textContent).not.toMatch(/demo/i);
    expect(screen.queryByRole('alert')).not.toBeInTheDocument();
  });
});

describe('when the metrics cannot be loaded', () => {
  it('says so with the reason and a working Retry, shows no figures, and never mentions demo data', async () => {
    metricsResponse = () => json(503, {});
    const { container } = render(view());
    expect(await screen.findByText("Couldn't load SLA metrics")).toBeInTheDocument();
    expect(screen.getByText(/HTTP 503/)).toBeInTheDocument();
    expect(screen.queryByText('Total Alerts')).not.toBeInTheDocument();
    expect(container.textContent).not.toMatch(/demo/i);
    expect(screen.queryByText(/showing what was last loaded/)).not.toBeInTheDocument(); // nothing was ever loaded, so it must not claim a "last loaded" view

    metricsResponse = () => json(200, metrics);
    await userEvent.setup().click(screen.getByRole('button', { name: 'Retry' }));
    await waitFor(() => expect(card('Total Alerts')).toBe('Total Alerts120'));
    expect(screen.queryByText("Couldn't load SLA metrics")).not.toBeInTheDocument();
  });

  it('says so when the response is not valid JSON, instead of a blank page', async () => {
    metricsResponse = () => new Response('<html>gateway</html>', { status: 200 });
    render(view());
    expect(await screen.findByText("Couldn't load SLA metrics")).toBeInTheDocument();
    expect(screen.getByText(/Invalid JSON/)).toBeInTheDocument();
  });
});

describe('when the server answers with something this page cannot read', () => {
  it('says so, instead of a silent blank page, and shows no figures', async () => {
    metricsResponse = () => json(200, { unexpected: 'shape' });
    render(view());
    expect(await screen.findByText("The SLA service returned data this page can't read")).toBeInTheDocument();
    expect(screen.queryByText('Total Alerts')).not.toBeInTheDocument();
    expect(screen.queryByText("Couldn't load SLA metrics")).not.toBeInTheDocument(); // it is not a failed request
  });

  it('offers a Retry that works', async () => {
    metricsResponse = () => json(200, { unexpected: 'shape' });
    render(view());
    await screen.findByText("The SLA service returned data this page can't read");
    metricsResponse = () => json(200, metrics);
    await userEvent.setup().click(screen.getByRole('button', { name: 'Retry' }));
    await waitFor(() => expect(card('Total Alerts')).toBe('Total Alerts120'));
  });
});

describe('when a later refresh fails', () => {
  it('keeps the last loaded figures and says the refresh failed', async () => {
    render(view());
    await waitFor(() => expect(card('Total Alerts')).toBe('Total Alerts120'));
    metricsResponse = () => json(500, {});
    await act(async () => { await mutate(METRICS_URL); });
    expect(await screen.findByText(/Couldn.t refresh SLA metrics; showing what was last loaded/)).toBeInTheDocument();
    expect(card('Total Alerts')).toBe('Total Alerts120');
    expect(screen.queryByText("Couldn't load SLA metrics")).not.toBeInTheDocument();
  });
});
