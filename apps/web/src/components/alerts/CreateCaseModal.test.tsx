import { beforeEach, describe, expect, it, vi } from 'vitest';
import { render, screen, waitFor } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { SWRConfig } from 'swr';
import type { Alert } from '@/lib/api';

const api = vi.hoisted(() => ({ list: vi.fn(), create: vi.fn(), linkAlerts: vi.fn() }));
const push = vi.hoisted(() => vi.fn());
vi.mock('@/lib/api', () => ({ casesApi: api }));
vi.mock('next/navigation', () => ({ useRouter: () => ({ push }) }));
vi.mock('react-hot-toast', () => ({ __esModule: true, default: Object.assign(vi.fn(), { error: vi.fn(), success: vi.fn() }) }));

import toast from 'react-hot-toast';
import { CreateCaseModal } from './CreateCaseModal';

const alert = (over: Partial<Alert> = {}) => ({ id: 'a1', title: 'Persistent foothold', severity: 'high', mitreAttack: [{ techniqueId: 'T1059' }, { techniqueId: 'T1547' }], ...over }) as unknown as Alert;

function show(a: Alert = alert(), onClose = vi.fn()) {
  render(
    <SWRConfig value={{ provider: () => new Map(), dedupingInterval: 0 }}>
      <CreateCaseModal open onClose={onClose} alert={a} />
    </SWRConfig>,
  );
  return onClose;
}

beforeEach(() => {
  Object.values(api).forEach((m) => m.mockReset());
  push.mockReset();
  vi.mocked(toast.error).mockReset();
  vi.mocked(toast.success).mockReset();
});

describe('CreateCaseModal', () => {
  it('renders nothing when closed', () => {
    render(<CreateCaseModal open={false} onClose={vi.fn()} alert={alert()} />);
    expect(screen.queryByRole('dialog')).not.toBeInTheDocument();
  });

  it('starts from the alert: its title and severity, and the alert id and techniques go with the new case', async () => {
    api.create.mockResolvedValue({ id: 'case-9', caseNumber: 'CASE-9' });
    const onClose = show();
    expect(screen.getByLabelText('Title')).toHaveValue('Persistent foothold');
    expect(screen.getByLabelText('Severity')).toHaveValue('high');
    await userEvent.click(screen.getByRole('button', { name: 'Create case' }));
    await waitFor(() => expect(api.create).toHaveBeenCalled());
    expect(api.create).toHaveBeenCalledWith({ title: 'Persistent foothold', description: undefined, severity: 'high', alertIds: ['a1'], mitre: ['T1059', 'T1547'] });
    await waitFor(() => expect(push).toHaveBeenCalledWith('/cases/case-9'));
    expect(onClose).toHaveBeenCalled();
    expect(toast.success).toHaveBeenCalledWith('Created CASE-9 from alert');
  });

  it('an info alert becomes a low case, because cases have no info level', () => {
    show(alert({ severity: 'info' }));
    expect(screen.getByLabelText('Severity')).toHaveValue('low');
  });

  it('refuses a title under three characters and creates nothing', async () => {
    show(alert({ title: 'ab' }));
    await userEvent.click(screen.getByRole('button', { name: 'Create case' }));
    expect(toast.error).toHaveBeenCalledWith('Case title must be at least 3 characters.');
    expect(api.create).not.toHaveBeenCalled();
  });

  it('says so when the case could not be created, and stays open', async () => {
    api.create.mockRejectedValue(new Error('500'));
    const onClose = show();
    await userEvent.click(screen.getByRole('button', { name: 'Create case' }));
    await waitFor(() => expect(toast.error).toHaveBeenCalledWith('Could not create the case. Please try again.'));
    expect(push).not.toHaveBeenCalled();
    expect(onClose).not.toHaveBeenCalled();
  });

  it('adds the alert to an existing open case, only after one is picked', async () => {
    api.list.mockResolvedValue({ cases: [{ id: 'c1', title: 'Phish wave', caseNumber: 'CASE-1' }], total: 1 });
    api.linkAlerts.mockResolvedValue({ id: 'c1', caseNumber: 'CASE-1' });
    show();
    await userEvent.click(screen.getByRole('button', { name: 'Add to existing case' }));
    await userEvent.click(screen.getByRole('button', { name: 'Add to case' }));
    expect(toast.error).toHaveBeenCalledWith('Pick a case to add this alert to.');
    expect(api.linkAlerts).not.toHaveBeenCalled();
    await screen.findByRole('option', { name: 'CASE-1 · Phish wave' });
    await userEvent.selectOptions(screen.getByLabelText('Open case'), 'c1');
    await userEvent.click(screen.getByRole('button', { name: 'Add to case' }));
    await waitFor(() => expect(api.linkAlerts).toHaveBeenCalledWith('c1', ['a1']));
    await waitFor(() => expect(push).toHaveBeenCalledWith('/cases/c1'));
    expect(api.list).toHaveBeenCalledWith({ status: 'open' });
  });

  it('says there are no open cases when there are none', async () => {
    api.list.mockResolvedValue({ cases: [], total: 0 });
    show();
    await userEvent.click(screen.getByRole('button', { name: 'Add to existing case' }));
    expect(await screen.findByText(/No open cases yet/)).toBeInTheDocument();
  });

  it('does not load the case list until that tab is opened', () => {
    show();
    expect(api.list).not.toHaveBeenCalled();
  });
});
