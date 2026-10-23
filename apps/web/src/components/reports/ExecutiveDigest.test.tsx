import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { render, screen, waitFor, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { SWRConfig } from 'swr';

const api = vi.hoisted(() => ({ weeklyDigest: vi.fn(), weeklyDigestHtml: vi.fn() }));
vi.mock('@/lib/api', () => ({ reportsApi: api }));

import { ExecutiveDigest } from './ExecutiveDigest';

const digest = (over: Record<string, unknown> = {}) => ({
  period: { label: 'Oct 1 to Oct 7', start: '2026-10-01T00:00:00Z', end: '2026-10-07T00:00:00Z' },
  headline: 'Alert volume fell 12% and every critical alert was handled.',
  alerts: { total: 200, new: 150, open_at_period_end: 9, resolved: 141, severity: { critical: 10, high: 50, medium: 100, low: 30, info: 10 } },
  cases: { opened: 6, closed: 5, sla_breached: 1 },
  mtt: { mttr_hours: 0.5, mttd_hours: 3.25, mttc_hours: 48 },
  automation: { total_decisions: 40, auto_executed: 30, escalated: 6, review_pending: 4 },
  top_tactics: [{ tactic: 'Credential Access', count: 20, delta_from_prior: 5 }, { tactic: 'Execution', count: 8, delta_from_prior: -3 }, { tactic: 'Discovery', count: 2, delta_from_prior: 0 }],
  top_sources: [{ connector_type: 'crowdstrike', count: 90 }],
  high_risk_alerts: [{ alert_id: 'a1', title: 'Mass mailbox forwarding rule', severity: 'critical', ai_score: 0.9234, mitre_tactics: ['Collection', 'Exfiltration'], event_time: '2026-10-03T10:00:00Z' }, { alert_id: 'a2', title: '', severity: 'high', ai_score: null, mitre_tactics: [], event_time: '2026-10-04T10:00:00Z' }],
  recommendations: [{ severity: 'critical', title: 'Tune the noisy rule', body: 'One rule made 40% of alerts.' }, { severity: 'warning', title: 'Review SLA', body: 'One breach.' }],
  ...over,
});

function renderIt() {
  return render(
    <SWRConfig value={{ provider: () => new Map(), dedupingInterval: 0, shouldRetryOnError: false }}>
      <ExecutiveDigest />
    </SWRConfig>,
  );
}

const days = (p: { period_start: string; period_end: string }) => Math.round((Date.parse(p.period_end) - Date.parse(p.period_start)) / 86400_000);

beforeEach(() => { api.weeklyDigest.mockReset(); api.weeklyDigestHtml.mockReset(); });
afterEach(() => vi.unstubAllGlobals());

describe('ExecutiveDigest', () => {
  it('shows a computing message first, with Print disabled', () => {
    api.weeklyDigest.mockReturnValue(new Promise(() => {}));
    renderIt();
    expect(screen.getByText('Computing digest…')).toBeInTheDocument();
    expect(screen.getByRole('button', { name: 'Print / Save as PDF' })).toBeDisabled();
  });

  it('asks for a seven-day window by default, and a longer one when chosen', async () => {
    api.weeklyDigest.mockResolvedValue(digest());
    renderIt();
    await screen.findByText('Oct 1 to Oct 7');
    expect(days(api.weeklyDigest.mock.calls[0][0])).toBe(7);
    await userEvent.selectOptions(screen.getByRole('combobox'), '30');
    await waitFor(() => expect(api.weeklyDigest).toHaveBeenCalledTimes(2));
    expect(days(api.weeklyDigest.mock.calls[1][0])).toBe(30);
  });

  it('shows the headline and the four headline numbers', async () => {
    api.weeklyDigest.mockResolvedValue(digest());
    renderIt();
    expect(await screen.findByText('Alert volume fell 12% and every critical alert was handled.')).toBeInTheDocument();
    const card = (label: string) => screen.getByText(label).parentElement as HTMLElement;
    expect(within(card('New alerts')).getByText('150')).toBeInTheDocument();
    expect(within(card('New alerts')).getByText('200 total in window')).toBeInTheDocument();
    expect(within(card('Open alerts')).getByText('9')).toBeInTheDocument();
    expect(within(card('Open alerts')).getByText('141 resolved this period')).toBeInTheDocument();
    expect(within(card('Cases opened')).getByText('5 closed · 1 SLA breaches')).toBeInTheDocument();
    expect(within(card('Mean MTTR')).getByText('30m')).toBeInTheDocument();
    expect(within(card('Mean MTTR')).getByText('MTTD 3.3h · MTTC 2.0d')).toBeInTheDocument();
  });

  it('shows a dash for a time it does not have', async () => {
    api.weeklyDigest.mockResolvedValue(digest({ mtt: { mttr_hours: null, mttd_hours: null, mttc_hours: null } }));
    renderIt();
    await screen.findByText('Mean MTTR');
    expect(within(screen.getByText('Mean MTTR').parentElement as HTMLElement).getByText('—')).toBeInTheDocument();
    expect(screen.getByText('MTTD — · MTTC —')).toBeInTheDocument();
  });

  it('shows the severity split in order, and what share of decisions needed no analyst', async () => {
    api.weeklyDigest.mockResolvedValue(digest());
    renderIt();
    await screen.findByText('Alerts by severity');
    const names = ['critical', 'high', 'medium', 'low', 'info'].map((s) => screen.getAllByText(s)[0]);
    names.slice(1).forEach((n, i) => expect(names[i].compareDocumentPosition(n) & Node.DOCUMENT_POSITION_FOLLOWING).toBeTruthy());
    expect(within(screen.getByText('medium').parentElement as HTMLElement).getByText('100')).toBeInTheDocument();
    expect(screen.getByText('75% of decisions executed without analyst intervention.')).toBeInTheDocument();
  });

  it('says so when there were no decisions, and does not divide by zero in the severity bars', async () => {
    api.weeklyDigest.mockResolvedValue(digest({ automation: { total_decisions: 0, auto_executed: 0, escalated: 0, review_pending: 0 }, alerts: { total: 0, new: 0, open_at_period_end: 0, resolved: 0, severity: {} } }));
    renderIt();
    expect(await screen.findByText('No remediation decisions logged this period.')).toBeInTheDocument();
    expect(screen.queryByText(/NaN/)).toBeNull();
  });

  it('shows tactic changes with their sign: up, down and unchanged', async () => {
    api.weeklyDigest.mockResolvedValue(digest());
    renderIt();
    await screen.findByText('Top MITRE tactics');
    expect(screen.getByText('+5')).toHaveClass('text-amber-300');
    expect(screen.getByText('-3')).toHaveClass('text-emerald-300');
    expect(screen.getByText('±0')).toHaveClass('text-gray-500');
  });

  it('shows the high-risk alerts, falling back to the id for a missing title and a dash for a missing score or tactics', async () => {
    api.weeklyDigest.mockResolvedValue(digest());
    renderIt();
    expect(await screen.findByText('Mass mailbox forwarding rule')).toBeInTheDocument();
    expect(screen.getByText('0.92')).toBeInTheDocument();
    expect(screen.getByText('Collection, Exfiltration')).toBeInTheDocument();
    const row = screen.getByText('a2').closest('tr') as HTMLElement;
    expect(within(row).getAllByText('—')).toHaveLength(2);
  });

  it('shows each recommendation', async () => {
    api.weeklyDigest.mockResolvedValue(digest());
    renderIt();
    expect(await screen.findByText('Tune the noisy rule')).toBeInTheDocument();
    expect(screen.getByText('Review SLA')).toBeInTheDocument();
  });

  it('empty lists say what is missing', async () => {
    api.weeklyDigest.mockResolvedValue(digest({ top_tactics: [], top_sources: [], high_risk_alerts: [], recommendations: [] }));
    renderIt();
    expect(await screen.findByText('No tactic-tagged alerts in this window.')).toBeInTheDocument();
    expect(screen.getByText('No connector-tagged alerts in this window.')).toBeInTheDocument();
    expect(screen.getByText('No high-risk alerts surfaced this period.')).toBeInTheDocument();
    expect(screen.getByText('No recommendations triggered for this period.')).toBeInTheDocument();
  });

  it('shows the error, and Refresh asks again', async () => {
    api.weeklyDigest.mockRejectedValueOnce(new Error('reports unavailable')).mockResolvedValueOnce(digest());
    renderIt();
    expect(await screen.findByText('Failed to load digest: reports unavailable')).toBeInTheDocument();
    await userEvent.click(screen.getByRole('button', { name: 'Refresh' }));
    expect(await screen.findByText('Oct 1 to Oct 7')).toBeInTheDocument();
  });

  it('Print opens the printable digest in a new tab', async () => {
    api.weeklyDigest.mockResolvedValue(digest());
    api.weeklyDigestHtml.mockResolvedValue('<html>digest</html>');
    const open = vi.fn().mockReturnValue({});
    vi.stubGlobal('open', open);
    Object.assign(URL, { createObjectURL: vi.fn().mockReturnValue('blob:digest'), revokeObjectURL: vi.fn() });
    renderIt();
    await screen.findByText('Oct 1 to Oct 7');
    await userEvent.click(screen.getByRole('button', { name: 'Print / Save as PDF' }));
    await waitFor(() => expect(open).toHaveBeenCalledWith('blob:digest', '_blank', 'noopener,noreferrer'));
    expect(api.weeklyDigestHtml).toHaveBeenCalledTimes(1);
    expect(screen.queryByText(/Pop-up blocked/)).toBeNull();
  });

  it('says so when the browser blocks the pop-up, and shows a failure to fetch the printable page', async () => {
    api.weeklyDigest.mockResolvedValue(digest());
    api.weeklyDigestHtml.mockResolvedValueOnce('<html/>').mockRejectedValueOnce(new Error('render failed'));
    vi.stubGlobal('open', vi.fn().mockReturnValue(null));
    Object.assign(URL, { createObjectURL: vi.fn().mockReturnValue('blob:x'), revokeObjectURL: vi.fn() });
    renderIt();
    await screen.findByText('Oct 1 to Oct 7');
    await userEvent.click(screen.getByRole('button', { name: 'Print / Save as PDF' }));
    expect(await screen.findByText(/Pop-up blocked/)).toBeInTheDocument();
    await userEvent.click(screen.getByRole('button', { name: 'Print / Save as PDF' }));
    expect(await screen.findByText('render failed')).toBeInTheDocument();
    expect(screen.queryByText(/Pop-up blocked/)).toBeNull();
  });
});
