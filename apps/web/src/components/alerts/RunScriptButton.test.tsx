import { beforeEach, describe, expect, it, vi } from 'vitest';
import { render, screen, waitFor } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import type { AlertScriptOptions } from '@/lib/api';

const api = vi.hoisted(() => ({ scriptOptions: vi.fn(), runScript: vi.fn(), addTicket: vi.fn(), createCase: vi.fn() }));
vi.mock('@/lib/api', () => ({ alertsApi: { scriptOptions: api.scriptOptions, runScript: api.runScript, addTicket: api.addTicket }, casesApi: { create: api.createCase } }));
const toast = vi.hoisted(() => ({ success: vi.fn(), error: vi.fn() }));
vi.mock('react-hot-toast', () => ({ default: toast }));

import { RunScriptButton, planRun } from './RunScriptButton';

const OPTIONS: AlertScriptOptions = {
  scripts: [
    { id: 7, name: 'Disk Space Scan', one_click: true },
    { id: 9, name: 'Restart Spooler', one_click: false },
  ],
  device: 'PC-01',
  tickets: [],
  case_id: null,
  case_number: null,
  blocked: null,
};

describe('planRun', () => {
  it('links a ticket number the alert does not have yet, and opens a case when there is none', () => {
    const r = planRun(OPTIONS, { scriptId: 7, ticketMode: 'number', linked: '', number: '#0553688' });
    expect(r).toEqual({ ok: true, plan: { scriptId: 7, ticket: { mode: 'link', number: '553688' }, linkTicket: '553688', needCase: true } });
  });
  it('does not link again a ticket the alert already has, and reuses its case', () => {
    const r = planRun({ ...OPTIONS, tickets: ['553688'], case_id: 'c1', case_number: 'C-1' }, { scriptId: 9, ticketMode: 'linked', linked: '553688', number: '' });
    expect(r).toEqual({ ok: true, plan: { scriptId: 9, ticket: { mode: 'link', number: '553688' }, needCase: false } });
  });
  it('opening a new ticket carries no number, and bad input is refused with a reason', () => {
    expect(planRun(OPTIONS, { scriptId: 7, ticketMode: 'create', linked: '', number: '' })).toMatchObject({ ok: true, plan: { ticket: { mode: 'create' } } });
    expect(planRun(OPTIONS, { scriptId: 7, ticketMode: 'number', linked: '', number: 'abc' })).toMatchObject({ ok: false });
    expect(planRun(OPTIONS, { scriptId: 99, ticketMode: 'create', linked: '', number: '' })).toMatchObject({ ok: false, error: 'Choose a script.' });
    expect(planRun(OPTIONS, { scriptId: null, ticketMode: 'create', linked: '', number: '' })).toMatchObject({ ok: false });
  });
});

describe('RunScriptButton', () => {
  beforeEach(() => {
    Object.values(api).forEach((m) => m.mockReset());
    toast.success.mockReset();
    toast.error.mockReset();
    api.scriptOptions.mockResolvedValue(OPTIONS);
    api.runScript.mockResolvedValue({ id: 'r1', status: 'pending', runs_at_once: true });
    api.addTicket.mockResolvedValue({ tickets: [] });
    api.createCase.mockResolvedValue({ id: 'case-new' });
  });

  it('opens a case, links the ticket, then queues the script for CORE, in that order', async () => {
    const order: string[] = [];
    api.createCase.mockImplementation(async () => (order.push('case'), { id: 'case-new' }));
    api.addTicket.mockImplementation(async () => (order.push('ticket'), { tickets: [] }));
    api.runScript.mockImplementation(async () => (order.push('run'), { id: 'r1', status: 'pending', runs_at_once: true }));
    render(<RunScriptButton alertId="a1" title="Disk space low" severity="high" />);
    await userEvent.click(screen.getByRole('button', { name: 'Run script' }));
    expect(await screen.findByTestId('run-script-case')).toHaveTextContent('no case yet');
    expect(screen.getByText('CORE runs this at once.')).toBeInTheDocument();
    await userEvent.type(screen.getByLabelText('Ticket number'), '553688');
    await userEvent.click(screen.getByRole('button', { name: 'Run' }));
    await waitFor(() => expect(api.runScript).toHaveBeenCalled());
    expect(order).toEqual(['case', 'ticket', 'run']);
    expect(api.createCase).toHaveBeenCalledWith({ title: 'Disk space low', severity: 'high', alertIds: ['a1'] });
    expect(api.addTicket).toHaveBeenCalledWith('a1', { id: '553688' });
    expect(api.runScript).toHaveBeenCalledWith('a1', { script_id: 7, ticket: { mode: 'link', number: '553688' }, case_id: 'case-new' });
    expect(toast.success).toHaveBeenCalled();
  });

  it('asking for a new ticket sends mode create, and a script CORE must approve says so', async () => {
    api.runScript.mockResolvedValue({ id: 'r1', status: 'pending', runs_at_once: false });
    api.scriptOptions.mockResolvedValue({ ...OPTIONS, case_id: 'c9', case_number: 'C-9' });
    render(<RunScriptButton alertId="a1" title="t" />);
    await userEvent.click(screen.getByRole('button', { name: 'Run script' }));
    await userEvent.selectOptions(await screen.findByLabelText('Script'), '9');
    expect(screen.getByText('CORE will ask you to approve it first.')).toBeInTheDocument();
    expect(screen.getByTestId('run-script-case')).toHaveTextContent('case C-9');
    await userEvent.click(screen.getByLabelText('Open a new ticket for this alert'));
    await userEvent.click(screen.getByRole('button', { name: 'Run' }));
    await waitFor(() => expect(api.runScript).toHaveBeenCalledWith('a1', { script_id: 9, ticket: { mode: 'create' }, case_id: 'c9' }));
    expect(api.createCase).not.toHaveBeenCalled();
    expect(api.addTicket).not.toHaveBeenCalled();
    expect(toast.success.mock.calls[0][0]).toMatch(/approve the script in CORE/);
  });

  it('says why nothing can be run, and offers no Run button', async () => {
    api.scriptOptions.mockResolvedValue({ ...OPTIONS, scripts: [], blocked: 'CORE has not shared any scripts.' });
    render(<RunScriptButton alertId="a1" title="t" />);
    await userEvent.click(screen.getByRole('button', { name: 'Run script' }));
    expect(await screen.findByTestId('run-script-blocked')).toHaveTextContent('CORE has not shared any scripts.');
    expect(screen.queryByRole('button', { name: 'Run' })).not.toBeInTheDocument();
  });

  it('a refused request is shown, and no case or ticket step is repeated by it', async () => {
    api.runScript.mockRejectedValue(new Error('A script request for this alert is already waiting for CORE'));
    api.scriptOptions.mockResolvedValue({ ...OPTIONS, case_id: 'c9', case_number: 'C-9', tickets: ['5'] });
    render(<RunScriptButton alertId="a1" title="t" />);
    await userEvent.click(screen.getByRole('button', { name: 'Run script' }));
    await userEvent.click(await screen.findByRole('button', { name: 'Run' }));
    await waitFor(() => expect(toast.error).toHaveBeenCalledWith('A script request for this alert is already waiting for CORE'));
    expect(screen.getByRole('button', { name: 'Run' })).toBeEnabled();
  });
});
