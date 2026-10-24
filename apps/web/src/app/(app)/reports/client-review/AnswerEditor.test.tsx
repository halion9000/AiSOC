import { beforeEach, describe, expect, it, vi } from 'vitest';
import { render, screen, waitFor, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';

const authFetch = vi.hoisted(() => vi.fn());
vi.mock('@/lib/auth-session', () => ({ authFetch }));
const routerParams = vi.hoisted(() => ({ current: new URLSearchParams('client=c1') }));
vi.mock('next/navigation', () => ({ useSearchParams: () => routerParams.current }));

import { ClientReview, type Review } from './ClientReview';

const reply = (body: unknown, ok = true, status = 200) => ({ ok, status: ok ? 200 : status, json: () => Promise.resolve(body) });
const base = (): Review =>
  ({
    client_id: 'c1',
    client_name: 'Acme Dental',
    generated_at: '2026-10-21T12:00:00Z',
    window_days: 30,
    devices: { endpoints: 0, coverage: [], stale_agents: 0, offline: 0, with_known_exploited: null, with_ransomware_exploit: null },
    mfa: null,
    secure_score: null,
    alerts: { open: 0, critical_open: 0, high_open: 0, opened_30d: 0, closed_30d: 0 },
    cases: { open: 0, opened_30d: 0, resolved_30d: 0 },
    readiness: { met: 0, partly: 0, not_met: 0, unknown: 1, items: [{ key: 'backups', question: 'Are backups tested and kept offline?', status: 'unknown', evidence: 'A.C.O.R.N does not collect this yet.' }] },
    tech_stack: [{ key: 'firewall', group: 'Network equipment', question: 'What is the client Firewall', status: 'unknown', suggested: null, evidence: 'ask the client' }],
    m365: [{ group: 'M365 Admin Center', question: 'Ensure the customer lockbox feature is enabled', status: 'needs_person', evidence: '' }],
  }) as Review;

let current: Review;
let puts: { url: string; body: Record<string, unknown> }[];

beforeEach(() => {
  authFetch.mockReset();
  current = base();
  puts = [];
  authFetch.mockImplementation(async (url: string, init?: { method?: string; body?: string }) => {
    if (init?.method === 'PUT') {
      puts.push({ url, body: JSON.parse(String(init.body)) });
      return reply({});
    }
    if (url.includes('/mssp/children')) return reply([{ id: 'c1', name: 'Acme Dental' }]);
    if (url.includes('/client-review/')) return reply(current);
    return reply({});
  });
});

async function open(label: RegExp | string) {
  render(<ClientReview />);
  await screen.findByTestId('readiness');
  await userEvent.click(screen.getByRole('button', { name: label }));
  return screen.getByRole('group', { name: 'Edit this answer' });
}

describe('typing answers and notes into the review', () => {
  it('a checklist question takes a status and a note and saves them for that client', async () => {
    const form = await open(/Edit the answer to: backups/);
    await userEvent.selectOptions(within(form).getByRole('combobox'), 'met');
    await userEvent.type(within(form).getByRole('textbox'), 'Veeam to Wasabi, restore tested in September');
    await userEvent.click(within(form).getByRole('button', { name: 'Save' }));
    await waitFor(() => expect(puts).toHaveLength(1));
    expect(puts[0].url).toBe('/api/v1/client-review/c1/answers');
    expect(puts[0].body).toEqual({ section: 'readiness', key: 'backups', status: 'met', answer: null, note: 'Veeam to Wasabi, restore tested in September' });
  });

  it('after saving, the review is read again and shows the typed answer, what A.C.O.R.N suggested, and the note', async () => {
    const form = await open(/Edit the answer to: backups/);
    current.readiness.items[0] = { ...current.readiness.items[0], status: 'met', manual: true, auto_status: 'unknown', note: 'tested in September' };
    await userEvent.selectOptions(within(form).getByRole('combobox'), 'met');
    await userEvent.click(within(form).getByRole('button', { name: 'Save' }));
    expect(await screen.findByTestId('typed-mark')).toHaveTextContent('Typed (A.C.O.R.N suggested: Not known)');
    expect(screen.getByTestId('answer-note')).toHaveTextContent('Note: tested in September');
    expect(within(screen.getByTestId('readiness')).getByText('Met')).toBeInTheDocument();
  });

  it('a note alone sends no status', async () => {
    const form = await open(/Edit the answer to: backups/);
    await userEvent.type(within(form).getByRole('textbox'), 'ask Dana');
    await userEvent.click(within(form).getByRole('button', { name: 'Save' }));
    await waitFor(() => expect(puts[0]?.body).toEqual({ section: 'readiness', key: 'backups', status: null, answer: null, note: 'ask Dana' }));
  });

  it('a technology question also takes the answer typed in', async () => {
    render(<ClientReview />);
    await screen.findByTestId('tech-stack');
    await userEvent.click(screen.getByRole('button', { name: /Edit the answer to: firewall/ }));
    const form = screen.getByRole('group', { name: 'Edit this answer' });
    await userEvent.selectOptions(within(form).getByRole('combobox'), 'seen');
    await userEvent.type(within(form).getByPlaceholderText('e.g. Fortinet 60F'), 'Fortinet 60F');
    await userEvent.click(within(form).getByRole('button', { name: 'Save' }));
    await waitFor(() => expect(puts[0]?.body).toEqual({ section: 'tech', key: 'firewall', status: 'seen', answer: 'Fortinet 60F', note: null }));
  });

  it('a Microsoft 365 question is keyed by its own words', async () => {
    render(<ClientReview />);
    await screen.findByTestId('m365');
    await userEvent.click(screen.getByRole('button', { name: /Edit the answer to: Ensure the customer lockbox/ }));
    const form = screen.getByRole('group', { name: 'Edit this answer' });
    await userEvent.selectOptions(within(form).getByRole('combobox'), 'met');
    await userEvent.click(within(form).getByRole('button', { name: 'Save' }));
    await waitFor(() => expect(puts[0]?.body).toMatchObject({ section: 'm365', key: 'Ensure the customer lockbox feature is enabled', status: 'met' }));
  });

  it('Back to automatic sends nothing in every field, which clears it', async () => {
    const form = await open(/Edit the answer to: backups/);
    await userEvent.click(within(form).getByRole('button', { name: /Back to automatic/ }));
    await waitFor(() => expect(puts[0]?.body).toEqual({ section: 'readiness', key: 'backups', status: null, answer: null, note: null }));
  });

  it('says why when the server refuses and keeps the form open', async () => {
    authFetch.mockImplementation(async (url: string, init?: { method?: string }) => {
      if (init?.method === 'PUT') return reply({ detail: 'status for readiness must be one of: met' }, false, 422);
      if (url.includes('/mssp/children')) return reply([{ id: 'c1', name: 'Acme Dental' }]);
      return reply(current);
    });
    const form = await open(/Edit the answer to: backups/);
    await userEvent.click(within(form).getByRole('button', { name: 'Save' }));
    expect(await within(form).findByRole('alert')).toHaveTextContent('status for readiness must be one of: met');
    expect(screen.getByRole('group', { name: 'Edit this answer' })).toBeInTheDocument();
  });

  it('Cancel closes the form without saving', async () => {
    const form = await open(/Edit the answer to: backups/);
    await userEvent.click(within(form).getByRole('button', { name: 'Cancel' }));
    expect(screen.queryByRole('group', { name: 'Edit this answer' })).not.toBeInTheDocument();
    expect(puts).toHaveLength(0);
  });

  it('shows a note on a question whose answer was not typed, with no Typed mark', async () => {
    current.readiness.items[0] = { ...current.readiness.items[0], note: 'two machines are being replaced' };
    render(<ClientReview />);
    expect(await screen.findByTestId('answer-note')).toHaveTextContent('two machines are being replaced');
    expect(screen.queryByTestId('typed-mark')).not.toBeInTheDocument();
  });
});
