import { beforeEach, describe, expect, it, vi } from 'vitest';
import { render, screen, waitFor } from '@testing-library/react';
import userEvent from '@testing-library/user-event';

const addTicket = vi.hoisted(() => vi.fn());
vi.mock('@/lib/api', async (importOriginal) => ({
  ...(await importOriginal<typeof import('@/lib/api')>()),
  alertsApi: { addTicket: (...a: unknown[]) => addTicket(...a) },
}));
vi.mock('react-hot-toast', () => ({ default: { success: vi.fn(), error: vi.fn() } }));

import { AlertsTableGrid } from './AlertsView';
import type { Alert } from '@/lib/api';

const alert = (id: string, title: string) => ({ id, title, description: '', severity: 'high', status: 'new', source: 'huntress', tenantId: 't', riskScore: 5, createdAt: '2026-10-19T10:00:00Z' }) as unknown as Alert;

function show(alerts: Alert[], onChanged = vi.fn()) {
  render(<AlertsTableGrid alerts={alerts} isLoading={false} error={null} filters={{ page: 1, pageSize: 25 }} selectedAlertId={null} onSelect={() => {}} onFilterChange={() => {}} onChanged={onChanged} />);
  return onChanged;
}

beforeEach(() => addTicket.mockReset().mockResolvedValue({ tickets: [] }));

describe('ticking alerts to link one ticket to several', () => {
  it('shows the bar only while rows are ticked, with how many', async () => {
    show([alert('a', 'Alert A'), alert('b', 'Alert B')]);
    expect(screen.queryByTestId('bulk-ticket-bar')).not.toBeInTheDocument();
    await userEvent.click(screen.getByLabelText('Select alert Alert A'));
    expect(screen.getByTestId('bulk-ticket-bar')).toHaveTextContent('1 selected');
    await userEvent.click(screen.getByLabelText('Select alert Alert B'));
    expect(screen.getByTestId('bulk-ticket-bar')).toHaveTextContent('2 selected');
    await userEvent.click(screen.getByLabelText('Select alert Alert A'));
    expect(screen.getByTestId('bulk-ticket-bar')).toHaveTextContent('1 selected');
  });

  it('links the ticket to only the ticked alerts, refreshes the list and clears the ticks', async () => {
    const onChanged = show([alert('a', 'Alert A'), alert('b', 'Alert B'), alert('c', 'Alert C')]);
    await userEvent.click(screen.getByLabelText('Select alert Alert A'));
    await userEvent.click(screen.getByLabelText('Select alert Alert C'));
    await userEvent.type(screen.getByLabelText('Ticket number'), '4521');
    await userEvent.click(screen.getByRole('button', { name: 'Link ticket' }));
    await waitFor(() => expect(onChanged).toHaveBeenCalled());
    expect(addTicket).toHaveBeenCalledTimes(2);
    expect(addTicket).toHaveBeenCalledWith('a', { id: '4521' });
    expect(addTicket).toHaveBeenCalledWith('c', { id: '4521' });
    expect(addTicket).not.toHaveBeenCalledWith('b', expect.anything());
    await waitFor(() => expect(screen.queryByTestId('bulk-ticket-bar')).not.toBeInTheDocument());
  });
});
