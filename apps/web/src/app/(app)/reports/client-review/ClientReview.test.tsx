import { beforeEach, describe, expect, it, vi } from 'vitest';
import { render, screen, waitFor } from '@testing-library/react';
import userEvent from '@testing-library/user-event';

const authFetch = vi.hoisted(() => vi.fn());
vi.mock('@/lib/auth-session', () => ({ authFetch }));
const routerParams = vi.hoisted(() => ({ current: new URLSearchParams('') }));
vi.mock('next/navigation', () => ({ useSearchParams: () => routerParams.current }));

import { ClientReview, dueText, readinessHeadline, visibleCoverage, type Review, type TechAnswer } from './ClientReview';

const reply = (body: unknown, ok = true, status = 200) => ({ ok, status: ok ? 200 : status, json: () => Promise.resolve(body) });

const review = (over: Partial<Review> = {}): Review => ({
  client_id: 'c1',
  client_name: 'Acme Dental',
  generated_at: '2026-10-21T12:00:00Z',
  window_days: 30,
  devices: {
    endpoints: 20,
    coverage: [
      { tool: 'huntress', have: 17, of: 20, percent: 85 },
      { tool: 'autoelevate', have: 0, of: 0, percent: null },
      { tool: 'dnsfilter', have: 0, of: 20, percent: 0, enrolled: false },
    ],
    stale_agents: 2,
    offline: 1,
    with_known_exploited: 3,
    with_ransomware_exploit: 1,
  },
  mfa: { people: 20, with_mfa: 15, not_required: 2, without_mfa: 3, admins_without_mfa: 1 },
  secure_score: { percent: 43.1, current: 115, max: 267, average: 54, taken_at: '2026-10-21T00:00:00Z' },
  alerts: { open: 5, critical_open: 1, high_open: 2, opened_30d: 9, closed_30d: 7 },
  cases: { open: 2, opened_30d: 3, resolved_30d: 1 },
  readiness: {
    met: 2,
    partly: 1,
    not_met: 1,
    unknown: 4,
    items: [
      { key: 'edr', question: 'Is endpoint detection and response on every computer?', status: 'partly', evidence: '17 of 20 Windows, Mac and Linux machines (85%) report Huntress.' },
      { key: 'backups', question: 'Are backups tested and kept offline?', status: 'unknown', evidence: 'A.C.O.R.N does not collect this yet; answer it from the client\'s own records.' },
    ],
  },
  ...over,
});

beforeEach(() => {
  authFetch.mockReset();
  routerParams.current = new URLSearchParams('');
});

describe('the helpers', () => {
  it('says how many answers are met, need work and are not known, in plain words', () => {
    expect(readinessHeadline({ met: 2, partly: 1, not_met: 1, unknown: 4, items: new Array(8).fill(null) })).toBe('2 of 8 answers are met, 2 need work, 4 are not known to A.C.O.R.N.');
    expect(readinessHeadline({ met: 9, partly: 0, not_met: 0, unknown: 0, items: new Array(9).fill(null) })).toBe('9 of 9 answers are met.');
    expect(readinessHeadline({ met: 0, partly: 0, not_met: 1, unknown: 1, items: new Array(2).fill(null) })).toBe('0 of 2 answers are met, 1 needs work, 1 is not known to A.C.O.R.N.');
  });
  it('shows only the tools some of the client\'s machines should run', () => {
    expect(visibleCoverage(review().devices.coverage).map((c) => c.tool)).toEqual(['huntress', 'dnsfilter']);
  });
});

describe('ClientReview', () => {
  it('asks to choose a client, then loads that client\'s review and lays it out', async () => {
    authFetch.mockImplementation((url?: string) =>
      Promise.resolve(String(url).startsWith('/api/v1/client-review/') ? reply(review()) : reply([{ id: 'c1', name: 'Acme Dental' }, { id: 'c0', name: 'Birch Law' }])),
    );
    const user = userEvent.setup();
    render(<ClientReview />);
    expect(screen.getByText('Choose a client to see its review.')).toBeInTheDocument();
    await waitFor(() => expect(screen.getByRole('option', { name: 'Acme Dental' })).toBeInTheDocument());
    await user.selectOptions(screen.getByLabelText('Client'), 'c1');
    expect(await screen.findByTestId('review-title')).toHaveTextContent('Acme Dental');
    expect(screen.getByTestId('review-headline')).toHaveTextContent('2 of 2 answers are met, 2 need work, 4 are not known to A.C.O.R.N.');
    expect(screen.getByTestId('readiness')).toHaveTextContent('Partly');
    expect(screen.getByTestId('readiness')).toHaveTextContent('Not known');
    expect(screen.getByTestId('coverage')).toHaveTextContent('Huntress (endpoint detection)');
    expect(screen.getByTestId('coverage')).toHaveTextContent('17 of 20 (85%)');
    expect(screen.getByTestId('not-enrolled')).toHaveTextContent('DNSFilter');
    expect(screen.getByTestId('not-enrolled')).toHaveTextContent('Not currently enrolled');
    expect(screen.getByTestId('not-enrolled')).not.toHaveTextContent('0 of 20');
    expect(screen.getByTestId('mfa-line')).toHaveTextContent('15 of 20 people have a required second factor; 3 have none, 1 of them administrators.');
    expect(screen.getByTestId('score-line')).toHaveTextContent('Microsoft Secure Score 43.1% (115 of 267), Microsoft\'s average is 54.');
    expect(screen.getByTestId('alerts-line')).toHaveTextContent('5 open (1 critical, 2 high). 9 raised and 7 closed in the last 30 days.');
    expect(screen.getByTestId('cases-line')).toHaveTextContent('2 open. 3 opened and 1 resolved in the last 30 days.');
    expect(authFetch).toHaveBeenCalledWith('/api/v1/client-review/c1');
  });

  it('opens straight on the client named in the address and says so plainly when data is missing', async () => {
    routerParams.current = new URLSearchParams('client=c1');
    authFetch.mockImplementation((url?: string) =>
      Promise.resolve(String(url).startsWith('/api/v1/client-review/') ? reply(review({ mfa: null, secure_score: null })) : reply([{ id: 'c1', name: 'Acme Dental' }])),
    );
    render(<ClientReview />);
    expect(await screen.findByText('No multi-factor data for this client yet.')).toBeInTheDocument();
    expect(screen.getByText('No Microsoft Secure Score read for this client yet.')).toBeInTheDocument();
  });

  it('shows an error when the client is not found', async () => {
    routerParams.current = new URLSearchParams('client=gone');
    authFetch.mockImplementation((url?: string) => Promise.resolve(String(url).startsWith('/api/v1/client-review/') ? reply({}, false, 404) : reply([])));
    render(<ClientReview />);
    expect(await screen.findByRole('alert')).toHaveTextContent('That client was not found.');
  });
});

describe('the vCIO Toolbox part', () => {
  const vcio = {
    recommendations: { total: 50, pending: 40, adopted: 8, declined: 2, top: [{ name: 'Restrict Group Creation', priority: 'High', adoption: 'Pending', due: '2026-06-12', on_roadmap: false }] },
    risks: [{ name: 'Cyber Liability', category: 'Financial Risk', priority: 'Medium', impact: 4, likelihood: 2, score: 8, inherent: 'Medium' }],
    refreshed_at: '2026-10-21T08:00:00Z',
  };

  it('writes a due date plainly, and nothing for a missing or odd one', () => {
    expect(dueText('2026-06-12')).toBe('due 12 Jun 2026');
    expect(dueText(null)).toBe('');
    expect(dueText('06/12/26')).toBe('');
    expect(dueText('2026-13-01')).toBe('');
  });

  it('shows the recommendations by adoption, the first pending ones and the risks, and says the review answers are not available', async () => {
    routerParams.current = new URLSearchParams('client=c1');
    authFetch.mockImplementation((url?: string) => Promise.resolve(String(url).startsWith('/api/v1/client-review/') ? reply(review({ vcio })) : reply([{ id: 'c1', name: 'Acme Dental' }])));
    render(<ClientReview />);
    expect(await screen.findByTestId('vcio-line')).toHaveTextContent('50 recommendations: 40 pending, 8 adopted, 2 declined.');
    expect(screen.getByTestId('vcio-top')).toHaveTextContent('Restrict Group Creation · High · due 12 Jun 2026');
    expect(screen.getByTestId('vcio-risks')).toHaveTextContent('Cyber Liability · score 8 (impact 4, likelihood 2) · Financial Risk');
    expect(screen.getByText(/IT review answers themselves are not available/)).toBeInTheDocument();
  });

  it('leaves the section out when CORE has not sent anything for the client', async () => {
    routerParams.current = new URLSearchParams('client=c1');
    authFetch.mockImplementation((url?: string) => Promise.resolve(String(url).startsWith('/api/v1/client-review/') ? reply(review({ vcio: null })) : reply([{ id: 'c1', name: 'Acme Dental' }])));
    render(<ClientReview />);
    await screen.findByTestId('review-title');
    expect(screen.queryByText('From vCIO Toolbox')).not.toBeInTheDocument();
  });

  it('lays out the technology questions with the suggestion and what it was based on, and says Ask the client where A.C.O.R.N cannot see', async () => {
    routerParams.current = new URLSearchParams('client=c1');
    const tech_stack: TechAnswer[] = [
      { key: 'edr_pc', group: 'Security tools', question: 'What endpoint security is in use for PCs', status: 'seen', suggested: 'Huntress', evidence: '17 of 20 Windows computers report Huntress.' },
      { key: 'edr_mac', group: 'Security tools', question: 'What endpoint security is in use for Macs', status: 'not_seen', suggested: 'None seen', evidence: "None of the client's 3 Macs report Huntress." },
      { key: 'firewall', group: 'Network equipment', question: 'What is the client Firewall', status: 'unknown', suggested: null, evidence: 'A.C.O.R.N does not collect this; ask the client.' },
    ];
    authFetch.mockImplementation((url?: string) => Promise.resolve(String(url).startsWith('/api/v1/client-review/') ? reply(review({ tech_stack })) : reply([{ id: 'c1', name: 'Acme Dental' }])));
    render(<ClientReview />);
    const table = await screen.findByTestId('tech-stack');
    expect(table).toHaveTextContent('Huntress');
    expect(table).toHaveTextContent('17 of 20 Windows computers report Huntress.');
    expect(table).toHaveTextContent('None seen');
    expect(table).toHaveTextContent('Ask the client');
    expect(table).toHaveTextContent('Network equipment');
  });
});
