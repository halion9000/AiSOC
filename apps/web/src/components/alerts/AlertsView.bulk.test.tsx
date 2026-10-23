import { beforeEach, describe, expect, it, vi } from 'vitest';
import { render, screen, waitFor } from '@testing-library/react';
import userEvent from '@testing-library/user-event';

const addTicket = vi.hoisted(() => vi.fn());
const scriptOptions = vi.hoisted(() => vi.fn());
const runScriptBulk = vi.hoisted(() => vi.fn());
vi.mock('@/lib/api', async (importOriginal) => ({
  ...(await importOriginal<typeof import('@/lib/api')>()),
  alertsApi: { addTicket: (...a: unknown[]) => addTicket(...a), scriptOptions: (...a: unknown[]) => scriptOptions(...a), runScriptBulk: (...a: unknown[]) => runScriptBulk(...a) },
}));
vi.mock('react-hot-toast', () => ({ default: { success: vi.fn(), error: vi.fn() } }));

import { AlertsTableGrid } from './AlertsView';
import type { Alert } from '@/lib/api';

const alert = (id: string, title: string) => ({ id, title, description: '', severity: 'high', status: 'new', source: 'huntress', tenantId: 't', riskScore: 5, createdAt: '2026-10-19T10:00:00Z' }) as unknown as Alert;

function show(alerts: Alert[], onChanged = vi.fn()) {
  render(<AlertsTableGrid alerts={alerts} isLoading={false} error={null} filters={{ page: 1, pageSize: 25 }} selectedAlertId={null} onSelect={() => {}} onFilterChange={() => {}} onChanged={onChanged} />);
  return onChanged;
}

beforeEach(() => {
  addTicket.mockReset().mockResolvedValue({ tickets: [] });
  scriptOptions.mockReset().mockResolvedValue({ scripts: [{ id: 7, name: 'Disk Space Scan', one_click: false }], device: null, tickets: [], case_id: null, case_number: null, blocked: null, suggested_script_id: null });
  runScriptBulk.mockReset();
});

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

describe('ticking alerts to run a script on their machines', () => {
  const plan = (preview: boolean) => ({ batch_id: preview ? null : 'b'.repeat(32), preview, script_name: 'Disk Space Scan', runs_at_once: false, queued: 2, skipped: 0, items: [
    { alert_id: 'a', device: 'PC-01', outcome: 'queued', reason: null, request_id: null },
    { alert_id: 'c', device: 'PC-03', outcome: 'queued', reason: null, request_id: null },
  ] });

  it('shows the script bar only while rows are ticked, with how many', async () => {
    show([alert('a', 'Alert A'), alert('b', 'Alert B')]);
    expect(screen.queryByTestId('bulk-script-bar')).not.toBeInTheDocument();
    await userEvent.click(screen.getByLabelText('Select alert Alert A'));
    expect(screen.getByTestId('bulk-script-bar')).toHaveTextContent('1 selected');
  });

  it('asks about only the ticked alerts, previews first, and after the one confirm refreshes the list and clears the ticks', async () => {
    runScriptBulk.mockImplementation(async (body: { preview?: boolean }) => plan(Boolean(body.preview)));
    const onChanged = show([alert('a', 'Alert A'), alert('b', 'Alert B'), alert('c', 'Alert C')]);
    await userEvent.click(screen.getByLabelText('Select alert Alert A'));
    await userEvent.click(screen.getByLabelText('Select alert Alert C'));
    await userEvent.click(screen.getByText('Run script on these machines'));
    await userEvent.click(await screen.findByText('See which machines'));
    await screen.findByTestId('bulk-script-plan');
    expect(runScriptBulk).toHaveBeenCalledTimes(1);
    expect(runScriptBulk.mock.calls[0][0]).toEqual({ script_id: 7, alert_ids: ['a', 'c'], preview: true });
    await userEvent.click(screen.getByText('Confirm: run on 2 machines'));
    await waitFor(() => expect(onChanged).toHaveBeenCalled());
    expect(runScriptBulk.mock.calls[1][0]).toEqual({ script_id: 7, alert_ids: ['a', 'c'], preview: false });
    await waitFor(() => expect(screen.queryByTestId('bulk-script-bar')).not.toBeInTheDocument());
  });
});
