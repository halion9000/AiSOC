import { beforeEach, describe, expect, it, vi } from 'vitest';
import { render, screen } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import type { ManagedTenantRow, VendorClient } from '@/lib/api';

const clientsMock = vi.fn();
const mapMock = vi.fn();
const unmapMock = vi.fn();
const ignoreMock = vi.fn();
vi.mock('@/lib/api', () => ({
  msspApi: {
    clients: () => clientsMock(),
    mapClient: (...a: unknown[]) => mapMock(...a),
    unmapClient: (...a: unknown[]) => unmapMock(...a),
    ignoreClient: (...a: unknown[]) => ignoreMock(...a),
  },
}));
vi.mock('react-hot-toast', () => ({ default: { success: vi.fn(), error: vi.fn() } }));

import ClientMapping, { groupClients, vendorLabel } from './ClientMapping';

function client(over: Partial<VendorClient> & { vendor_client_name: string }): VendorClient {
  return { id: `a-${over.vendor_client_name}`, vendor: 'petra', vendor_client_id: '1', child_tenant_id: null, child_tenant_name: null, ignored: false, match_source: 'suggested', suggestions: [], ...over };
}
const tenant = (name: string): ManagedTenantRow => ({
  tenant_id: `t-${name}`, name, has_metrics: false, snapshot_at: null, health_score: null, open_alerts: null, critical_alerts: null, open_cases: null, mttr_minutes: null, sla_breaches: null, connector_count: null,
});
const tenants = [tenant('Acme Dental'), tenant('Birch Law')];

beforeEach(() => {
  for (const m of [clientsMock, mapMock, unmapMock, ignoreMock]) m.mockReset();
  mapMock.mockResolvedValue({});
  unmapMock.mockResolvedValue(undefined);
  ignoreMock.mockResolvedValue(undefined);
});

describe('grouping', () => {
  it('splits clients into unmapped, mapped and ignored, and an ignored client is never "unmapped"', () => {
    const g = groupClients([
      client({ vendor_client_name: 'A' }),
      client({ vendor_client_name: 'B', child_tenant_id: 't' }),
      client({ vendor_client_name: 'C', ignored: true }),
    ]);
    expect([g.unmapped, g.mapped, g.ignored].map((x) => x.map((c) => c.vendor_client_name))).toEqual([['A'], ['B'], ['C']]);
    expect(vendorLabel('petra')).toBe('Petra');
  });
});

describe('the Client mapping section', () => {
  it('explains where clients come from when there are none yet', async () => {
    clientsMock.mockResolvedValue({ clients: [], unmapped: 0 });
    render(<ClientMapping tenants={tenants} onChanged={() => {}} />);
    expect(await screen.findByText(/after CORE syncs them/)).toBeInTheDocument();
  });

  it('preselects the best suggestion and maps to it', async () => {
    clientsMock.mockResolvedValue({
      clients: [client({ vendor_client_name: 'ACME Dental Group', suggestions: [{ tenant_id: 't-Acme Dental', name: 'Acme Dental', score: 0.85 }] })],
      unmapped: 1,
    });
    const onChanged = vi.fn();
    const user = userEvent.setup();
    render(<ClientMapping tenants={tenants} onChanged={onChanged} />);

    const select = await screen.findByLabelText('Client for ACME Dental Group');
    expect(select).toHaveValue('t-Acme Dental');
    await user.click(screen.getByRole('button', { name: 'Map' }));
    expect(mapMock).toHaveBeenCalledWith('a-ACME Dental Group', { childTenantId: 't-Acme Dental' });
    await vi.waitFor(() => expect(onChanged).toHaveBeenCalled());
  });

  it('cannot map until a client is chosen, and can add the vendor client as a new client', async () => {
    clientsMock.mockResolvedValue({ clients: [client({ vendor_client_name: 'Zed Corp' })], unmapped: 1 });
    const user = userEvent.setup();
    render(<ClientMapping tenants={tenants} onChanged={() => {}} />);

    const select = await screen.findByLabelText('Client for Zed Corp');
    expect(screen.getByRole('button', { name: 'Map' })).toBeDisabled();
    await user.selectOptions(select, screen.getByRole('option', { name: /Add “Zed Corp” as a new client/ }));
    await user.click(screen.getByRole('button', { name: 'Map' }));
    expect(mapMock).toHaveBeenCalledWith('a-Zed Corp', { newTenantName: 'Zed Corp' });
  });

  it('ignores, unmaps and restores', async () => {
    clientsMock.mockResolvedValue({
      clients: [
        client({ vendor_client_name: 'Open One' }),
        client({ vendor_client_name: 'Linked', child_tenant_id: 't-Birch Law', child_tenant_name: 'Birch Law' }),
        client({ vendor_client_name: 'Skipped', ignored: true }),
      ],
      unmapped: 1,
    });
    const user = userEvent.setup();
    render(<ClientMapping tenants={tenants} onChanged={() => {}} />);

    await screen.findByText('Open One');
    expect(screen.getByText('→ Birch Law')).toBeInTheDocument();
    await user.click(screen.getByRole('button', { name: 'Ignore' }));
    expect(ignoreMock).toHaveBeenCalledWith('a-Open One', true);
    await user.click(screen.getByRole('button', { name: 'Unmap' }));
    expect(unmapMock).toHaveBeenCalledWith('a-Linked');
    await user.click(screen.getByRole('button', { name: 'Restore' }));
    expect(ignoreMock).toHaveBeenCalledWith('a-Skipped', false);
  });

  it('shows an error rather than an empty list when the clients cannot be loaded', async () => {
    clientsMock.mockRejectedValue(new Error('boom'));
    render(<ClientMapping tenants={tenants} onChanged={() => {}} />);
    expect(await screen.findByRole('alert')).toHaveTextContent('boom');
  });
});

