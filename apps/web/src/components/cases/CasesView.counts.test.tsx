import { beforeEach, describe, expect, it, vi } from 'vitest';
import { render, screen, waitFor } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { SWRConfig } from 'swr';

const api = vi.hoisted(() => ({ list: vi.fn(), counts: vi.fn() }));
vi.mock('@/lib/api', () => ({ casesApi: { list: api.list, counts: api.counts, create: vi.fn() } }));
vi.mock('react-hot-toast', () => ({ default: { success: vi.fn(), error: vi.fn() } }));
vi.mock('@/components/saved-views/SavedViewsBar', () => ({ SavedViewsBar: () => null }));

import { CasesView } from './CasesView';

const caseRow = (i: number) => ({ id: `c${i}`, title: `Case ${i}`, severity: 'medium', status: 'open', alertCount: 1, createdAt: '2026-10-19T10:00:00Z', updatedAt: '2026-10-19T10:00:00Z' });

function show() {
  return render(
    <SWRConfig value={{ provider: () => new Map(), dedupingInterval: 0 }}>
      <CasesView />
    </SWRConfig>,
  );
}

beforeEach(() => {
  api.list.mockReset().mockResolvedValue({ cases: [], total: 0 });
  api.counts.mockReset().mockResolvedValue({ all: 612, open: 580, in_progress: 12, resolved: 15, closed: 5 });
});

describe('the cases page', () => {
  it('starts on Open, asks for 500 cases not the API default of 50, and shows the real counts of the whole caseload', async () => {
    show();
    await waitFor(() => expect(api.list).toHaveBeenCalledWith({ status: 'open', limit: 500 }));
    expect(await screen.findByTestId('cases-count-open')).toHaveTextContent('580');
    expect(screen.getByTestId('cases-count-all')).toHaveTextContent('612');
    expect(screen.getByTestId('cases-count-in_progress')).toHaveTextContent('12');
    expect(screen.getByTestId('cases-count-closed')).toHaveTextContent('5');
  });

  it('lists Open first and All Cases after Closed', async () => {
    show();
    await screen.findByTestId('cases-count-open');
    const labels = screen.getAllByTestId(/^cases-count-/).map((el) => el.getAttribute('data-testid'));
    expect(labels).toEqual(['cases-count-open', 'cases-count-in_progress', 'cases-count-resolved', 'cases-count-closed', 'cases-count-all']);
  });

  it('says when the list is cut short, and not otherwise', async () => {
    api.list.mockResolvedValue({ cases: Array.from({ length: 500 }, (_, i) => caseRow(i)), total: 500 });
    show();
    expect(await screen.findByTestId('cases-truncated')).toHaveTextContent('Showing the newest 500 of 580 cases');
  });

  it('shows no notice when everything fits', async () => {
    api.counts.mockResolvedValue({ all: 3, open: 3, in_progress: 0, resolved: 0, closed: 0 });
    api.list.mockResolvedValue({ cases: [caseRow(1), caseRow(2), caseRow(3)], total: 3 });
    show();
    await screen.findAllByText('Case 1'); // the title is also on the Act now card
    expect(screen.queryByTestId('cases-truncated')).not.toBeInTheDocument();
  });

  it('asks for the other tiles when they are chosen, All Cases with no status', async () => {
    const user = userEvent.setup();
    show();
    await screen.findByTestId('cases-count-all');
    await user.click(screen.getByTestId('cases-count-closed'));
    await waitFor(() => expect(api.list).toHaveBeenLastCalledWith({ status: 'closed', limit: 500 }));
    await user.click(screen.getByTestId('cases-count-all'));
    await waitFor(() => expect(api.list).toHaveBeenLastCalledWith({ status: undefined, limit: 500 }));
  });
});

describe('the Act now board on the cases page', () => {
  it('says what is open and starts with the most severe case, only on the Open and All tiles', async () => {
    const user = userEvent.setup();
    api.counts.mockResolvedValue({ all: 2, open: 2, in_progress: 0, resolved: 0, closed: 0 });
    api.list.mockResolvedValue({ cases: [{ ...caseRow(1), severity: 'low' }, { ...caseRow(2), severity: 'critical' }], total: 2 });
    show();
    expect(await screen.findByTestId('act-now-headline')).toHaveTextContent('2 open cases, 2 with no owner. Start with Case 2.');
    expect(screen.getAllByTestId('act-now-card')[0]).toHaveTextContent('Act now');
    await user.click(screen.getByTestId('cases-count-closed'));
    expect(screen.queryByTestId('act-now')).not.toBeInTheDocument();
  });
});
