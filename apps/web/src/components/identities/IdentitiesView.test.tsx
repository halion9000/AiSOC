import { beforeEach, describe, expect, it, vi } from 'vitest';
import { render, screen, waitFor, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { SWRConfig } from 'swr';

const api = vi.hoisted(() => ({ list: vi.fn(), detail: vi.fn(), listChildren: vi.fn() }));
vi.mock('@/lib/api', () => ({ identitiesApi: { list: api.list, detail: api.detail }, msspApi: { listChildren: api.listChildren } }));
vi.mock('next/link', () => ({ default: ({ children, href }: { children: React.ReactNode; href: string }) => <a href={href}>{children}</a> }));

import { IdentitiesView } from './IdentitiesView';

const person = (over: Record<string, unknown> = {}) => ({
  key: 'c1:amy@acme.com',
  client_id: 'c1',
  client_name: 'Acme',
  email: 'amy@acme.com',
  display_name: 'Amy Adams',
  kind: 'user',
  enabled: true,
  admin: false,
  licensed: true,
  mfa: 'covered',
  mfa_methods: null,
  tools: ['cipp', 'dropsuite'],
  sources: [],
  open_alerts: 0,
  top_severity: null,
  ...over,
});
const list = (items: unknown[], over: Record<string, unknown> = {}) => ({
  summary: { total: items.length, with_alerts: 1, without_mfa: 2, admins: 1, disabled: 0, in_one_tool: 3, tools: { cipp: 5, dropsuite: 2, 'datto-saas': 1 } },
  items,
  total: items.length,
  page: 1,
  page_size: 50,
  pages: 1,
  ...over,
});
const lastQuery = () => api.list.mock.calls.at(-1)![0] as Record<string, unknown>;

function show() {
  return render(
    <SWRConfig value={{ provider: () => new Map(), dedupingInterval: 0, shouldRetryOnError: false }}>
      <IdentitiesView />
    </SWRConfig>,
  );
}

beforeEach(() => {
  Object.values(api).forEach((m) => m.mockReset());
  api.listChildren.mockResolvedValue([{ id: 'c1', name: 'Acme' }, { id: 'c2', name: 'Beta' }]);
  api.list.mockResolvedValue(list([person(), person({ key: 'c1:bob@acme.com', email: 'bob@acme.com', display_name: null, mfa: 'none', tools: ['dropsuite'], open_alerts: 3, top_severity: 'high', admin: true, enabled: false })]));
});

describe('the Identities page', () => {
  it('lists each person once with their tools as logos, multi-factor state and alerts', async () => {
    show();
    const rows = await screen.findAllByTestId('identity-row');
    expect(rows).toHaveLength(2);
    expect(rows[0]).toHaveTextContent('Amy Adams');
    expect(rows[0]).toHaveTextContent('amy@acme.com');
    expect(within(rows[0]).getAllByRole('img').map((i) => i.getAttribute('title'))).toEqual(['CIPP', 'Dropsuite']);
    expect(rows[0]).toHaveTextContent('Covered');
    expect(rows[1]).toHaveTextContent('bob@acme.com');
    expect(rows[1]).toHaveTextContent('None');
    expect(rows[1]).toHaveTextContent('3');
    expect(rows[1]).toHaveTextContent('high');
    expect(rows[1]).toHaveTextContent('admin');
    expect(rows[1]).toHaveTextContent('disabled');
    expect(screen.getByTestId('identities-total')).toHaveTextContent('2');
  });

  it('filters by search, client, tool and multi-factor, asking the server and starting again at page 1', async () => {
    show();
    await screen.findAllByTestId('identity-row');
    await userEvent.type(screen.getByLabelText('Search people'), 'amy');
    await waitFor(() => expect(lastQuery().search).toBe('amy'));
    await userEvent.selectOptions(screen.getByLabelText('Client'), 'c2');
    await waitFor(() => expect(lastQuery().clientId).toBe('c2'));
    await userEvent.selectOptions(screen.getByLabelText('Known to'), 'dropsuite');
    await waitFor(() => expect(lastQuery().source).toBe('dropsuite'));
    await userEvent.selectOptions(screen.getByLabelText('Multi-Factor'), 'none');
    await waitFor(() => expect(lastQuery().mfa).toBe('none'));
    expect(lastQuery().page).toBe(1);
  });

  it('the tiles filter too, and show the counts for everyone', async () => {
    show();
    await screen.findAllByTestId('identity-row');
    expect(screen.getByRole('button', { name: /With open alerts/ })).toHaveTextContent('1');
    await userEvent.click(screen.getByRole('button', { name: /With open alerts/ }));
    await waitFor(() => expect(lastQuery().hasAlerts).toBe(true));
    await userEvent.click(screen.getByRole('button', { name: /Administrators/ }));
    await waitFor(() => expect(lastQuery().admin).toBe(true));
    await userEvent.click(screen.getByRole('button', { name: /No Multi-Factor/ }));
    await waitFor(() => expect(lastQuery().mfa).toBe('none'));
    await userEvent.click(screen.getByRole('button', { name: /No Multi-Factor/ }));
    await waitFor(() => expect(lastQuery().mfa).toBeUndefined());
  });

  it('"in only one tool" needs a tool picked, and then asks for the people only that tool knows', async () => {
    show();
    await screen.findAllByTestId('identity-row');
    await userEvent.click(screen.getByRole('button', { name: /In only one tool/ }));
    expect(screen.getByText(/Pick a tool below/)).toBeInTheDocument();
    expect(lastQuery().onlyIn).toBeUndefined();
    await userEvent.selectOptions(screen.getByLabelText('Known to'), 'dropsuite');
    await waitFor(() => expect(lastQuery().onlyIn).toBe('dropsuite'));
  });

  it('sorts by the column clicked', async () => {
    show();
    await screen.findAllByTestId('identity-row');
    expect(lastQuery().sort).toBe('alerts');
    await userEvent.click(within(screen.getByRole('columnheader', { name: /Client/ })).getByRole('button'));
    await waitFor(() => expect(lastQuery().sort).toBe('client'));
    await userEvent.click(within(screen.getByRole('columnheader', { name: /Known to/ })).getByRole('button'));
    await waitFor(() => expect(lastQuery().sort).toBe('tools'));
    await userEvent.click(within(screen.getByRole('columnheader', { name: /Person/ })).getByRole('button'));
    await waitFor(() => expect(lastQuery().sort).toBe('email'));
  });

  it('a row opens to each tool\'s record, the alerts that name the person and their sign-ins', async () => {
    api.detail.mockResolvedValue({
      person: person({ sources: [{ vendor: 'cipp', external_id: '1', enabled: true, details: {} }, { vendor: 'dropsuite', external_id: '2', enabled: false, details: {} }], mfa_methods: 'authenticator' }),
      alerts: [{ id: 'a9', title: 'Impossible travel', severity: 'high', status: 'new', source: 'petra', created_at: '2026-10-22T00:00:00Z' }],
      signins: { last_30_days: 40, failed: 3, unusual: 2, countries: ['US', 'GB'], last_at: '2026-10-22T10:00:00Z' },
    });
    show();
    await userEvent.click((await screen.findAllByTestId('identity-row'))[0]);
    const detail = await screen.findByTestId('identity-detail');
    expect(api.detail).toHaveBeenCalledWith('c1', 'amy@acme.com');
    expect(detail).toHaveTextContent('CIPP');
    expect(detail).toHaveTextContent('Dropsuite');
    expect(detail).toHaveTextContent('disabled');
    expect(within(detail).getByRole('link', { name: 'Impossible travel' })).toHaveAttribute('href', '/alerts/a9');
    expect(detail).toHaveTextContent('40 sign-ins, 3 failed');
    expect(detail).toHaveTextContent('From: US, GB');
    expect(detail).toHaveTextContent('authenticator');
  });

  it('says plainly when nobody matches, and shows an error with a retry', async () => {
    api.list.mockResolvedValueOnce(list([], { total: 0 }));
    const first = show();
    expect(await screen.findByText('No people match.')).toBeInTheDocument();
    first.unmount();
    api.list.mockRejectedValue(new Error('API 500'));
    show();
    expect(await screen.findByRole('alert')).toHaveTextContent('Could not load the identities: API 500');
  });

  it('pages through a long list', async () => {
    api.list.mockResolvedValue(list([person()], { page: 1, pages: 3, total: 120 }));
    show();
    await screen.findAllByTestId('identity-row');
    expect(screen.getByText(/Page 1 of 3 \(120 people\)/)).toBeInTheDocument();
    await userEvent.click(screen.getByRole('button', { name: 'Next' }));
    await waitFor(() => expect(lastQuery().page).toBe(2));
  });
});

describe('alerts broken up by the tool that raised them', () => {
  it('shows each person\'s open alerts as one chip per tool, with the count', async () => {
    api.list.mockResolvedValue(list([person({ open_alerts: 5, top_severity: 'high', alerts_by_source: { huntress: 3, petra: 2 } })]));
    show();
    const row = await screen.findByTestId('identity-row');
    const chips = within(within(row).getByTestId('alerts-by-source')).getAllByTitle(/open alert/);
    expect(chips.map((c) => c.getAttribute('title'))).toEqual(['3 open alerts from Huntress', '2 open alerts from Petra']);
    expect(chips[0]).toHaveTextContent('3');
    expect(row).toHaveTextContent('5');
  });

  it('an alert naming no tool shows as other', async () => {
    api.list.mockResolvedValue(list([person({ open_alerts: 1, alerts_by_source: { other: 1 } })]));
    show();
    expect(await screen.findByTitle('1 open alert from an unnamed tool')).toBeInTheDocument();
  });

  it('can be filtered to people with an alert from one tool, offering the tools that have alerts', async () => {
    api.list.mockResolvedValue(list([person()], { summary: { total: 1, with_alerts: 1, without_mfa: 0, admins: 0, disabled: 0, in_one_tool: 0, tools: { cipp: 1 }, alert_sources: { huntress: 2, petra: 1 } } }));
    show();
    await screen.findAllByTestId('identity-row');
    const menu = screen.getByLabelText('Alerts from');
    expect(within(menu).getAllByRole('option').map((o) => o.textContent)).toEqual(['Alerts from any tool', 'Huntress (2)', 'Petra (1)']);
    await userEvent.selectOptions(menu, 'petra');
    await waitFor(() => expect(lastQuery().alertSource).toBe('petra'));
    expect(lastQuery().page).toBe(1);
  });

  it('opens to the person\'s alerts grouped by tool, the tool with the most first', async () => {
    api.detail.mockResolvedValue({
      person: person({ sources: [] }),
      alerts: [
        { id: 'a1', title: 'Impossible travel', severity: 'high', status: 'new', source: 'petra', created_at: null },
        { id: 'a2', title: 'Risky sign-in', severity: 'medium', status: 'new', source: 'huntress', created_at: null },
        { id: 'a3', title: 'Another risky sign-in', severity: 'low', status: 'new', source: 'huntress', created_at: null },
        { id: 'a4', title: 'No tool', severity: 'info', status: 'new', source: null, created_at: null },
      ],
      signins: { last_30_days: 0, failed: 0, unusual: 0, countries: [], last_at: null },
    });
    show();
    await userEvent.click((await screen.findAllByTestId('identity-row'))[0]);
    const groups = await screen.findAllByTestId('alert-group');
    expect(groups.map((g) => g.textContent?.match(/Huntress|Petra|Other/)?.[0])).toEqual(['Huntress', 'Other', 'Petra']);
    expect(groups[0]).toHaveTextContent('(2)');
    expect(within(groups[0]).getAllByRole('link')).toHaveLength(2);
  });
});

describe('groupBySource', () => {
  it('groups, puts the biggest group first and files an alert with no tool under other', async () => {
    const { groupBySource } = await import('./IdentitiesView');
    const out = groupBySource([{ source: 'b' }, { source: 'a' }, { source: 'a' }, { source: null }]);
    expect(Object.keys(out)).toEqual(['a', 'b', 'other']);
    expect(out.a).toHaveLength(2);
  });
});
