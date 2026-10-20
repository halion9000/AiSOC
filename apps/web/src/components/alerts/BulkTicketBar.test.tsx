import { beforeEach, describe, expect, it, vi } from 'vitest';
import { render, screen, waitFor } from '@testing-library/react';
import userEvent from '@testing-library/user-event';

const addTicket = vi.hoisted(() => vi.fn());
vi.mock('@/lib/api', () => ({ alertsApi: { addTicket: (...a: unknown[]) => addTicket(...a) } }));
vi.mock('react-hot-toast', () => ({ default: { success: vi.fn(), error: vi.fn() } }));

import BulkTicketBar, { bulkSummary, linkTicketToAlerts } from './BulkTicketBar';

beforeEach(() => addTicket.mockReset().mockResolvedValue({ tickets: [] }));

describe('linkTicketToAlerts', () => {
  it('links the ticket to every alert and counts them', async () => {
    const r = await linkTicketToAlerts(['a', 'b', 'c'], '4521', addTicket);
    expect(r).toEqual({ linked: 3, failed: [] });
    expect(addTicket).toHaveBeenCalledTimes(3);
    expect(addTicket).toHaveBeenCalledWith('b', { id: '4521' });
  });

  it('keeps going after one fails and reports which', async () => {
    addTicket.mockImplementation((id: string) => (id === 'b' ? Promise.reject(new Error('Alert not found')) : Promise.resolve({})));
    const r = await linkTicketToAlerts(['a', 'b', 'c'], '4521', addTicket);
    expect(r.linked).toBe(2);
    expect(r.failed).toEqual([{ alertId: 'b', message: 'Alert not found' }]);
  });
});

describe('bulkSummary', () => {
  it('says what happened in plain words', () => {
    expect(bulkSummary('4521', { linked: 1, failed: [] })).toBe('Linked ticket 4521 to 1 alert.');
    expect(bulkSummary('4521', { linked: 2, failed: [{ alertId: 'x', message: 'nope' }] })).toBe('Linked ticket 4521 to 2 alerts; 1 failed: nope');
  });
});

describe('BulkTicketBar', () => {
  it('shows nothing when no alert is ticked', () => {
    const { container } = render(<BulkTicketBar alertIds={[]} onDone={() => {}} onClear={() => {}} />);
    expect(container).toBeEmptyDOMElement();
  });

  it('links the typed number (a leading # is dropped) to the ticked alerts, then refreshes and clears', async () => {
    const onDone = vi.fn();
    const onClear = vi.fn();
    render(<BulkTicketBar alertIds={['a', 'b']} onDone={onDone} onClear={onClear} />);
    expect(screen.getByTestId('bulk-ticket-bar')).toHaveTextContent('2 selected');
    const button = screen.getByRole('button', { name: 'Link ticket' });
    expect(button).toBeDisabled();
    await userEvent.type(screen.getByLabelText('Ticket number'), '#4521');
    await userEvent.click(button);
    await waitFor(() => expect(onDone).toHaveBeenCalled());
    expect(addTicket).toHaveBeenCalledWith('a', { id: '4521' });
    expect(addTicket).toHaveBeenCalledWith('b', { id: '4521' });
    expect(onClear).toHaveBeenCalled();
  });

  it('keeps the selection when some alerts failed, so they can be tried again', async () => {
    addTicket.mockImplementation((id: string) => (id === 'b' ? Promise.reject(new Error('boom')) : Promise.resolve({})));
    const onClear = vi.fn();
    const onDone = vi.fn();
    render(<BulkTicketBar alertIds={['a', 'b']} onDone={onDone} onClear={onClear} />);
    await userEvent.type(screen.getByLabelText('Ticket number'), '9');
    await userEvent.click(screen.getByRole('button', { name: 'Link ticket' }));
    await waitFor(() => expect(onDone).toHaveBeenCalled());
    expect(onClear).not.toHaveBeenCalled();
  });
});
