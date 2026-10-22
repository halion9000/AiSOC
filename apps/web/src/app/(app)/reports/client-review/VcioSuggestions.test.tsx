import { beforeEach, describe, expect, it, vi } from 'vitest';
import { render, screen, waitFor } from '@testing-library/react';
import userEvent from '@testing-library/user-event';

const authFetch = vi.hoisted(() => vi.fn());
vi.mock('@/lib/auth-session', () => ({ authFetch }));

import { orderProposals, VcioSuggestions, type Proposal } from './VcioSuggestions';

const reply = (body: unknown, ok = true, status = 200) => ({ ok, status: ok ? 200 : status, json: () => Promise.resolve(body) });
const proposal = (over: Partial<Proposal> = {}): Proposal => ({
  id: 'p1',
  key: 'mfa_admins',
  name: 'Require Multi-Factor Authentication for every administrator',
  description: 'd',
  priority: 'High',
  evidence: '2 administrator(s) have no Multi-Factor.',
  status: 'suggested',
  result_message: null,
  ...over,
});

beforeEach(() => authFetch.mockReset());

describe('ordering', () => {
  it('puts what needs a person first, then what is waiting on CORE, then what is done', () => {
    const list = [proposal({ id: 'a', status: 'cleared', name: 'A' }), proposal({ id: 'b', status: 'sent', name: 'B' }), proposal({ id: 'c', status: 'suggested', name: 'C' }), proposal({ id: 'd', status: 'failed', name: 'D' }), proposal({ id: 'e', status: 'approved', name: 'E' })];
    expect(orderProposals(list).map((p) => p.id)).toEqual(['c', 'd', 'e', 'b', 'a']);
  });
});

describe('the suggestions card', () => {
  it('lists each suggestion with its evidence and the words for its state, and asks for the client\'s own list', async () => {
    authFetch.mockResolvedValue(reply({ mapped: true, proposals: [proposal(), proposal({ id: 'p2', key: 'edr', name: 'Put EDR everywhere', status: 'sent', evidence: '17 of 20 machines report Huntress.' })] }));
    render(<VcioSuggestions clientId="c 1" />);
    expect(await screen.findAllByTestId('vcio-suggestion')).toHaveLength(2);
    expect(authFetch).toHaveBeenCalledWith('/api/v1/client-review/c%201/vcio-proposals');
    expect(screen.getByText('2 administrator(s) have no Multi-Factor.')).toBeInTheDocument();
    expect(screen.getAllByTestId('vcio-suggestion-status').map((e) => e.textContent)).toEqual(['Waiting for you', 'Added to vCIO Toolbox']);
    expect(screen.getAllByRole('button', { name: 'Approve' })).toHaveLength(1);
  });

  it('approving posts to that suggestion and then shows the new list', async () => {
    authFetch.mockResolvedValueOnce(reply({ mapped: true, proposals: [proposal()] }));
    authFetch.mockResolvedValueOnce(reply({ id: 'p1' }));
    authFetch.mockResolvedValueOnce(reply({ mapped: true, proposals: [proposal({ status: 'approved' })] }));
    render(<VcioSuggestions clientId="c1" />);
    await userEvent.click(await screen.findByRole('button', { name: 'Approve' }));
    await waitFor(() => expect(screen.getByTestId('vcio-suggestion-status')).toHaveTextContent('Approved: CORE will add it to vCIO Toolbox'));
    expect(authFetch).toHaveBeenCalledWith('/api/v1/client-review/c1/vcio-proposals/p1/approve', { method: 'POST' });
    expect(screen.queryByRole('button', { name: 'Approve' })).not.toBeInTheDocument();
  });

  it('a client that is not mapped to a vCIO customer says so and cannot approve', async () => {
    authFetch.mockResolvedValue(reply({ mapped: false, proposals: [proposal()] }));
    render(<VcioSuggestions clientId="c1" />);
    expect(await screen.findByTestId('vcio-unmapped')).toHaveTextContent('not mapped to a vCIO Toolbox customer');
    expect(screen.getByRole('button', { name: 'Approve' })).toBeDisabled();
    expect(screen.getByRole('button', { name: 'Reject' })).toBeEnabled();
  });

  it('shows the API\'s own reason when a decision is refused', async () => {
    authFetch.mockResolvedValueOnce(reply({ mapped: true, proposals: [proposal()] }));
    authFetch.mockResolvedValueOnce(reply({ detail: 'A suggestion that is approved cannot be rejected.' }, false, 409));
    render(<VcioSuggestions clientId="c1" />);
    await userEvent.click(await screen.findByRole('button', { name: 'Reject' }));
    expect(await screen.findByRole('alert')).toHaveTextContent('cannot be rejected');
  });

  it('Check again works the list out afresh and shows what came back; a failed send offers to try again', async () => {
    authFetch.mockResolvedValueOnce(reply({ mapped: true, proposals: [] }));
    authFetch.mockResolvedValueOnce(reply({ mapped: true, proposals: [proposal({ status: 'failed', result_message: 'vCIO Toolbox returned 422' })] }));
    render(<VcioSuggestions clientId="c1" />);
    expect(await screen.findByText(/No suggestions yet/)).toBeInTheDocument();
    await userEvent.click(screen.getByRole('button', { name: 'Check again' }));
    expect(await screen.findByText('vCIO Toolbox returned 422')).toBeInTheDocument();
    expect(authFetch).toHaveBeenLastCalledWith('/api/v1/client-review/c1/vcio-proposals/refresh', { method: 'POST' });
    expect(screen.getByRole('button', { name: 'Approve and try again' })).toBeInTheDocument();
  });
});
