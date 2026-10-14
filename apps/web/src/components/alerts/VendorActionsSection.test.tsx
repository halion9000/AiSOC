import { beforeEach, describe, expect, it, vi } from 'vitest';
import { render, screen, waitFor } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { SWRConfig } from 'swr';

const api = vi.hoisted(() => ({ vendorActions: vi.fn(), requestVendorAction: vi.fn() }));
vi.mock('@/lib/api', async (importOriginal) => ({ ...(await importOriginal<typeof import('@/lib/api')>()), alertsApi: api }));

import { availableActions, VendorActionsSection } from './VendorActionsSection';
import type { VendorActions, VendorState } from '@/lib/api';

const rem = (id: number, status: string) => ({ id, type: 'assisted', action: `Step ${id}`, parameters: [{ name: 'path', description: 'c:\\evil.exe' }], status });
const stateOf = (status: string, rems: string[]): VendorState => ({
  vendor: 'huntress',
  at: '2026-10-14T12:00:00Z',
  status,
  remediations: rems.map((s, i) => rem(i + 1, s)),
  psa_ticket_eids: ['T-1696'],
});
const payload = (over: Partial<VendorActions> = {}): VendorActions => ({
  supported: true,
  vendor: 'huntress',
  incident_uid: 'huntress:7',
  vendor_state: stateOf('sent', ['unapproved']),
  actions: [],
  tickets: [],
  ...over,
});

function show() {
  return render(
    <SWRConfig value={{ provider: () => new Map(), dedupingInterval: 0 }}>
      <VendorActionsSection alertId="alert-1" />
    </SWRConfig>
  );
}

beforeEach(() => {
  api.vendorActions.mockReset();
  api.requestVendorAction.mockReset();
});

describe('availableActions', () => {
  it('offers approve and reject while something is unapproved, and resolve only when nothing is', () => {
    const open = availableActions(stateOf('sent', ['unapproved', 'approved']), false);
    expect([open.approve.enabled, open.reject.enabled, open.resolve.enabled]).toEqual([true, true, false]);
    const done = availableActions(stateOf('sent', ['approved']), false);
    expect([done.approve.enabled, done.reject.enabled, done.resolve.enabled]).toEqual([false, false, true]);
  });
  it('offers nothing for a closed incident, with no reported state, or while an action is already waiting', () => {
    for (const a of [availableActions(stateOf('closed', ['approved']), false), availableActions(null, false), availableActions(stateOf('sent', ['unapproved']), true)]) {
      expect(a.approve.enabled || a.reject.enabled || a.resolve.enabled).toBe(false);
      expect(a.approve.why).not.toBe('');
    }
  });
});

describe('VendorActionsSection', () => {
  it('renders nothing for an alert that is not a Huntress incident', async () => {
    api.vendorActions.mockResolvedValue(payload({ supported: false, vendor: null, incident_uid: null, vendor_state: null }));
    const { container } = show();
    await waitFor(() => expect(api.vendorActions).toHaveBeenCalled());
    expect(container).toBeEmptyDOMElement();
  });

  it('shows the plan, its parameters and the PSA ticket Huntress opened', async () => {
    api.vendorActions.mockResolvedValue(payload());
    show();
    expect(await screen.findByText('Step 1')).toBeInTheDocument();
    expect(screen.getByText('c:\\evil.exe')).toBeInTheDocument();
    expect(screen.getByText('T-1696')).toBeInTheDocument();
  });

  it('asks for confirmation before anything is sent, then queues exactly the confirmed action', async () => {
    api.vendorActions.mockResolvedValue(payload());
    api.requestVendorAction.mockResolvedValue({ id: 'x', action: 'approve', status: 'pending', result_message: null, created_at: '2026-10-14T12:00:00Z', finished_at: null });
    show();
    await userEvent.click(await screen.findByRole('button', { name: 'Approve plan' }));
    expect(api.requestVendorAction).not.toHaveBeenCalled();
    expect(screen.getByRole('group', { name: /Confirm Approve plan/ })).toBeInTheDocument();
    await userEvent.click(screen.getByRole('button', { name: /Confirm: Approve plan/ }));
    await waitFor(() => expect(api.requestVendorAction).toHaveBeenCalledWith('alert-1', { action: 'approve' }));
  });

  it('will not send a rejection without a comment, and sends the reason, comment and usefulness with one', async () => {
    api.vendorActions.mockResolvedValue(payload());
    api.requestVendorAction.mockResolvedValue({ id: 'x', action: 'reject', status: 'pending', result_message: null, created_at: '2026-10-14T12:00:00Z', finished_at: null });
    show();
    await userEvent.click(await screen.findByRole('button', { name: 'Reject plan' }));
    const confirm = screen.getByRole('button', { name: /Confirm: Reject plan/ });
    expect(confirm).toBeDisabled();
    await userEvent.selectOptions(screen.getByLabelText('Reason'), 'approved_application');
    await userEvent.type(screen.getByLabelText(/Comment for the Huntress SOC/), 'our own admin tool');
    await userEvent.click(screen.getByLabelText('The plan was useful'));
    expect(confirm).toBeEnabled();
    await userEvent.click(confirm);
    await waitFor(() =>
      expect(api.requestVendorAction).toHaveBeenCalledWith('alert-1', { action: 'reject', comment: 'our own admin tool', reason: 'approved_application', useful: false })
    );
  });

  it('disables every button while an action is waiting, and shows its progress and the result of earlier ones', async () => {
    api.vendorActions.mockResolvedValue(
      payload({
        actions: [
          { id: '1', action: 'approve', status: 'pending', result_message: null, created_at: new Date().toISOString(), finished_at: null },
          { id: '0', action: 'resolve', status: 'failed', result_message: 'Huntress refused: read-only key.', created_at: new Date().toISOString(), finished_at: null },
        ],
      })
    );
    show();
    expect(await screen.findByText('Waiting for CORE')).toBeInTheDocument();
    expect(screen.getByText('Huntress refused: read-only key.')).toBeInTheDocument();
    for (const name of ['Approve plan', 'Reject plan', 'Resolve incident']) expect(screen.getByRole('button', { name })).toBeDisabled();
  });

  it("says so when CORE hasn't reported the incident yet, and offers no action", async () => {
    api.vendorActions.mockResolvedValue(payload({ vendor_state: null }));
    show();
    expect(await screen.findByText(/Waiting for CORE to report/)).toBeInTheDocument();
    expect(screen.getByRole('button', { name: 'Approve plan' })).toBeDisabled();
  });

  it("shows the server's reason when a request is refused, and leaves the confirmation open", async () => {
    const { ApiError } = await import('@/lib/api');
    api.vendorActions.mockResolvedValue(payload());
    api.requestVendorAction.mockRejectedValue(new ApiError('409', 409, JSON.stringify({ detail: 'There are no unapproved remediations to approve or reject.' })));
    show();
    await userEvent.click(await screen.findByRole('button', { name: 'Approve plan' }));
    await userEvent.click(screen.getByRole('button', { name: /Confirm: Approve plan/ }));
    expect(await screen.findByRole('alert')).toHaveTextContent('There are no unapproved remediations to approve or reject.');
  });
});
