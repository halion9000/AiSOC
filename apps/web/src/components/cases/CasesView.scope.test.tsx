import { beforeEach, describe, expect, it, vi } from 'vitest';
import { render, screen, waitFor } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { SWRConfig } from 'swr';

const api = vi.hoisted(() => ({ list: vi.fn(), counts: vi.fn(), children: vi.fn() }));
vi.mock('@/lib/api', () => ({
  casesApi: { list: api.list, counts: api.counts, create: vi.fn() },
  msspApi: { listChildren: api.children },
}));
const routerParams = vi.hoisted(() => ({ current: new URLSearchParams('') }));
vi.mock('next/navigation', () => ({ useSearchParams: () => routerParams.current }));
vi.mock('react-hot-toast', () => ({ default: { success: vi.fn(), error: vi.fn() } }));
vi.mock('@/components/saved-views/SavedViewsBar', () => ({ SavedViewsBar: () => null }));

import { CasesView } from './CasesView';

const caseRow = (i: number, clientName?: string) => ({ id: `c${i}`, title: `Case ${i}`, severity: 'medium', status: 'open', alertCount: 1, createdAt: '2026-10-19T10:00:00Z', updatedAt: '2026-10-19T10:00:00Z', clientName });

function show() {
  return render(
    <SWRConfig value={{ provider: () => new Map(), dedupingInterval: 0 }}>
      <CasesView />
    </SWRConfig>,
  );
}

beforeEach(() => {
  window.localStorage.clear();
  routerParams.current = new URLSearchParams('');
  api.list.mockReset().mockResolvedValue({ cases: [], total: 0 });
  api.counts.mockReset().mockResolvedValue({ all: 64, open: 64, in_progress: 0, resolved: 0, closed: 0 });
  api.children.mockReset().mockResolvedValue([{ id: 'c1', name: 'Acme Dental' }, { id: 'c0', name: 'Aardvark Vet' }]);
});

describe('the cases page: all clients', () => {
  it('has no switch for an organization without clients, and asks for its own cases only', async () => {
    api.children.mockResolvedValue([]);
    show();
    await waitFor(() => expect(api.list).toHaveBeenCalled());
    expect(screen.queryByTestId('cases-scope')).not.toBeInTheDocument();
    expect(api.list).toHaveBeenLastCalledWith({ status: 'open', limit: 500 });
    expect(api.counts).toHaveBeenLastCalledWith('own', undefined);
  });

  it('starts on My organization, and All clients asks for every client\'s cases and counts, then shows each case\'s client', async () => {
    api.list.mockImplementation(async (f: { scope?: string }) => ({ cases: f.scope === 'all' ? [caseRow(1, 'Acme Dental'), caseRow(2)] : [caseRow(2)], total: 2 }));
    api.counts.mockImplementation(async (scope: string) => (scope === 'all' ? { all: 3878, open: 3878, in_progress: 0, resolved: 0, closed: 0 } : { all: 64, open: 64, in_progress: 0, resolved: 0, closed: 0 }));
    show();
    expect(await screen.findByTestId('cases-count-open')).toHaveTextContent('64');
    expect(screen.queryByTestId('case-client')).not.toBeInTheDocument();
    await userEvent.click(await screen.findByRole('button', { name: 'All clients' }));
    await waitFor(() => expect(api.list).toHaveBeenLastCalledWith({ status: 'open', limit: 500, scope: 'all', clientId: undefined }));
    expect(api.counts).toHaveBeenLastCalledWith('all', undefined);
    expect(await screen.findByTestId('cases-count-open')).toHaveTextContent('3878');
    expect(await screen.findByTestId('case-client')).toHaveTextContent('Acme Dental');
  });

  it('can narrow to one client, listed alphabetically, and remembers the choice', async () => {
    const first = show();
    await userEvent.click(await screen.findByRole('button', { name: 'All clients' }));
    const select = await screen.findByLabelText('Client');
    expect([...select.querySelectorAll('option')].map((o) => o.textContent)).toEqual(['Every client', 'Aardvark Vet', 'Acme Dental']);
    await userEvent.selectOptions(select, 'c1');
    await waitFor(() => expect(api.list).toHaveBeenLastCalledWith(expect.objectContaining({ scope: 'all', clientId: 'c1' })));
    expect(api.counts).toHaveBeenLastCalledWith('all', 'c1');
    first.unmount();
    show();
    await waitFor(() => expect(api.list).toHaveBeenLastCalledWith(expect.objectContaining({ scope: 'all', clientId: 'c1' })));
    expect(screen.getByRole('button', { name: 'All clients' })).toHaveAttribute('aria-pressed', 'true');
  });

  it('a link naming a client opens the all-clients list for that client, and does not change what was remembered', async () => {
    window.localStorage.setItem('aisoc.filters.cases', JSON.stringify({ scope: 'own', clientId: '' }));
    routerParams.current = new URLSearchParams('scope=all&client=c1');
    show();
    await waitFor(() => expect(api.list).toHaveBeenLastCalledWith(expect.objectContaining({ scope: 'all', clientId: 'c1' })));
    expect(api.counts).toHaveBeenLastCalledWith('all', 'c1');
    expect(await screen.findByRole('button', { name: 'All clients' })).toHaveAttribute('aria-pressed', 'true');
    expect(JSON.parse(window.localStorage.getItem('aisoc.filters.cases') ?? '{}')).toEqual({ scope: 'own', clientId: '' });
  });
});
