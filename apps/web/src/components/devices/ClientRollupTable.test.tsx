import { beforeEach, describe, expect, it, vi } from 'vitest';
import { render, screen, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';

const rollup = vi.hoisted(() => vi.fn());
vi.mock('@/lib/api', () => ({ devicesApi: { rollup } }));

import { ClientRollupTable } from './ClientRollupTable';

const row = (over: Record<string, unknown>) => ({ client_id: 'c1', client_name: 'Acme', devices: 10, needs_attention: 0, stale_agents: 0, not_in_huntress: 0, offline: 0, ...over });

beforeEach(() => {
  rollup.mockReset();
});

describe('ClientRollupTable', () => {
  it('reads nothing until it is opened, then lists the clients in the order the API gave', async () => {
    rollup.mockResolvedValue([row({ client_id: 'c2', client_name: 'Zed', needs_attention: 4, stale_agents: 2 }), row({})]);
    render(<ClientRollupTable onPick={vi.fn()} />);
    expect(rollup).not.toHaveBeenCalled();
    await userEvent.setup().click(screen.getByRole('button', { name: /By client/ }));
    const rows = await screen.findAllByRole('row');
    expect(within(rows[1]).getByText('Zed')).toBeInTheDocument();
    expect(rows[1]).toHaveTextContent('4');
    expect(within(rows[2]).getByText('Acme')).toBeInTheDocument();
    expect(rollup).toHaveBeenCalledTimes(1);
  });

  it('picking a client hands its id to the page', async () => {
    rollup.mockResolvedValue([row({ client_id: 'c9', client_name: 'Nine' })]);
    const onPick = vi.fn();
    render(<ClientRollupTable onPick={onPick} />);
    const user = userEvent.setup();
    await user.click(screen.getByRole('button', { name: /By client/ }));
    await user.click(await screen.findByText('Nine'));
    expect(onPick).toHaveBeenCalledWith('c9');
  });

  it('says so when there are no devices, and does not break when the call fails', async () => {
    rollup.mockResolvedValueOnce([]);
    render(<ClientRollupTable onPick={vi.fn()} />);
    await userEvent.setup().click(screen.getByRole('button', { name: /By client/ }));
    expect(await screen.findByText('No devices yet.')).toBeInTheDocument();
  });

  it('shows no table when the call fails', async () => {
    rollup.mockImplementation(async () => {
      throw new Error('boom');
    });
    render(<ClientRollupTable onPick={vi.fn()} />);
    await userEvent.setup().click(screen.getByRole('button', { name: /By client/ }));
    expect(await screen.findByText('No devices yet.')).toBeInTheDocument();
  });
});
