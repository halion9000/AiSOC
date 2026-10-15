import { beforeEach, describe, expect, it, vi } from 'vitest';
import { render, screen } from '@testing-library/react';
import userEvent from '@testing-library/user-event';

const createMock = vi.fn();
vi.mock('react-hot-toast', () => ({ default: { success: vi.fn(), error: vi.fn() } }));
vi.mock('@/lib/api', () => ({ alertsApi: { create: (...a: unknown[]) => createMock(...a) } }));

import { CreateAlertModal, buildManualAlert } from './CreateAlertModal';

beforeEach(() => createMock.mockReset());

describe('buildManualAlert', () => {
  it('builds one event with the entered details and leaves blank optional fields out', () => {
    const body = buildManualAlert({ title: ' Odd login ', severity: 'high', description: '', host: 'PC-1', user: '  ', ip: '10.0.0.5' }, new Date('2026-10-14T00:00:00Z'));
    expect(body).toEqual({
      events: [{ displayMessage: 'Odd login', severity: 'high', published: '2026-10-14T00:00:00.000Z', client: { ipAddress: '10.0.0.5', device: 'PC-1' } }],
      connector_type: 'manual',
      title: 'Odd login',
      severity: 'high',
      tags: ['manual'],
    });
  });
});

describe('CreateAlertModal', () => {
  it('will not submit without a title, then submits and reports success', async () => {
    createMock.mockResolvedValue({ id: 'a1' });
    const onCreated = vi.fn();
    const onClose = vi.fn();
    const user = userEvent.setup();
    render(<CreateAlertModal open onClose={onClose} onCreated={onCreated} />);

    await user.click(screen.getByRole('button', { name: 'Create alert' }));
    expect(createMock).not.toHaveBeenCalled();

    await user.type(screen.getByLabelText('Title'), 'Phishing report');
    await user.selectOptions(screen.getByLabelText('Severity'), 'critical');
    await user.click(screen.getByRole('button', { name: 'Create alert' }));

    expect(createMock).toHaveBeenCalledTimes(1);
    expect(createMock.mock.calls[0][0]).toMatchObject({ title: 'Phishing report', severity: 'critical', connector_type: 'manual' });
    expect(onCreated).toHaveBeenCalled();
    expect(onClose).toHaveBeenCalled();
  });

  it('renders nothing when closed', () => {
    render(<CreateAlertModal open={false} onClose={() => {}} onCreated={() => {}} />);
    expect(screen.queryByRole('dialog')).toBeNull();
  });
});
