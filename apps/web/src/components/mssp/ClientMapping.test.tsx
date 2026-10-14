import { beforeEach, describe, expect, it, vi } from 'vitest';
import { render, screen } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import type { ManagedTenantRow, VendorClient } from '@/lib/api';

const clientsMock = vi.fn();
const mapMock = vi.fn();
const unmapMock = vi.fn();
const ignoreMock = vi.fn();
const importMock = vi.fn();
const sourcesMock = vi.fn();
const hiddenMock = vi.fn();
const removeMock = vi.fn();
const tenantsMock = vi.fn();
vi.mock('@/lib/api', () => ({
  msspApi: {
    clients: () => clientsMock(),
    mapClient: (...a: unknown[]) => mapMock(...a),
    unmapClient: (...a: unknown[]) => unmapMock(...a),
    ignoreClient: (...a: unknown[]) => ignoreMock(...a),
    importClients: (...a: unknown[]) => importMock(...a),
    setClientSources: (...a: unknown[]) => sourcesMock(...a),
    setClientHidden: (...a: unknown[]) => hiddenMock(...a),
    removeClient: (...a: unknown[]) => removeMock(...a),
    tenants: (...a: unknown[]) => tenantsMock(...a),
  },
}));
vi.mock('react-hot-toast', () => ({ default: { success: vi.fn(), error: vi.fn() } }));

import ClientMapping, { removeClients, keptSummary, filterClients, toolTabs, groupClients, sortClients, sourceChoices, unmappedByVendor, vendorLabel } from './ClientMapping';

function client(over: Partial<VendorClient> & { vendor_client_name: string }): VendorClient {
  return { id: `a-${over.vendor_client_name}`, vendor: 'petra', vendor_client_id: '1', child_tenant_id: null, child_tenant_name: null, ignored: false, match_source: 'suggested', suggestions: [], ...over };
}
const tenant = (name: string): ManagedTenantRow => ({
  tenant_id: `t-${name}`, name, has_metrics: false, snapshot_at: null, health_score: null, open_alerts: null, critical_alerts: null, open_cases: null, mttr_minutes: null, sla_breaches: null, connector_count: null,
});
const tenants = [tenant('Acme Dental'), tenant('Birch Law')];

beforeEach(() => {
  for (const m of [clientsMock, mapMock, unmapMock, ignoreMock, importMock, sourcesMock, hiddenMock, removeMock, tenantsMock]) m.mockReset();
  tenantsMock.mockResolvedValue([tenant('Acme Dental'), tenant('Birch Law')]);
  removeMock.mockImplementation(async (id: string) => ({ removed: true, name: id, reason: null }));
  hiddenMock.mockResolvedValue(undefined);
  importMock.mockResolvedValue({ created: 2, linked: 1 });
  sourcesMock.mockResolvedValue({ sync_vendors: [], created: 0, linked: 0 });
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
    expect(vendorLabel('halopsa')).toBe('HaloPSA');
    expect(vendorLabel('ninjaone')).toBe('NinjaOne');
    expect(vendorLabel('acme')).toBe('Acme');
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


describe('importing every unmapped client from a tool', () => {
  const two = [client({ vendor_client_name: 'A', vendor: 'petra' }), client({ vendor_client_name: 'B', vendor: 'petra' }), client({ vendor_client_name: 'C', vendor: 'huntress' })];

  it('counts unmapped clients per tool, biggest first', () => {
    expect(unmappedByVendor(two)).toEqual([{ vendor: 'petra', count: 2 }, { vendor: 'huntress', count: 1 }]);
  });

  it('offers one button per tool and imports only after confirmation', async () => {
    clientsMock.mockResolvedValue({ clients: two, unmapped: 3 });
    const confirm = vi.spyOn(window, 'confirm');
    const user = userEvent.setup();
    render(<ClientMapping tenants={tenants} onChanged={() => {}} />);

    const petra = await screen.findByRole('button', { name: 'Import all 2 from Petra' });
    expect(screen.getByRole('button', { name: 'Import all 1 from Huntress' })).toBeInTheDocument();

    confirm.mockReturnValueOnce(false);
    await user.click(petra);
    expect(importMock).not.toHaveBeenCalled();

    confirm.mockReturnValueOnce(true);
    await user.click(petra);
    expect(importMock).toHaveBeenCalledWith('petra');
    confirm.mockRestore();
  });

  it('offers no import when nothing is unmapped', async () => {
    clientsMock.mockResolvedValue({ clients: [client({ vendor_client_name: 'Linked', child_tenant_id: 't-Birch Law', child_tenant_name: 'Birch Law' })], unmapped: 0 });
    render(<ClientMapping tenants={tenants} onChanged={() => {}} />);
    await screen.findByText('Everything is mapped.');
    expect(screen.queryByRole('button', { name: /Import all/ })).toBeNull();
  });
});

describe('choosing which tools add clients automatically', () => {
  const list = [client({ vendor_client_name: 'A', vendor: 'petra' }), client({ vendor_client_name: 'B', vendor: 'halopsa' })];

  it('lists every tool that sent clients, with the chosen ones on', () => {
    expect(sourceChoices(list, ['halopsa'])).toEqual([{ vendor: 'halopsa', on: true }, { vendor: 'petra', on: false }]);
  });

  it('turning a tool on asks first, then saves the whole chosen list', async () => {
    clientsMock.mockResolvedValue({ clients: list, unmapped: 2, sync_vendors: ['halopsa'] });
    const confirm = vi.spyOn(window, 'confirm');
    const user = userEvent.setup();
    render(<ClientMapping tenants={tenants} onChanged={() => {}} />);

    const petra = await screen.findByRole('checkbox', { name: 'Petra' });
    expect(screen.getByRole('checkbox', { name: 'HaloPSA' })).toBeChecked();
    confirm.mockReturnValueOnce(false);
    await user.click(petra);
    expect(sourcesMock).not.toHaveBeenCalled();
    confirm.mockReturnValueOnce(true);
    await user.click(petra);
    expect(sourcesMock).toHaveBeenCalledWith(['halopsa', 'petra']);
    confirm.mockRestore();
  });

  it('turning a tool off needs no confirmation and keeps the others', async () => {
    clientsMock.mockResolvedValue({ clients: list, unmapped: 2, sync_vendors: ['halopsa', 'petra'] });
    const user = userEvent.setup();
    render(<ClientMapping tenants={tenants} onChanged={() => {}} />);
    await user.click(await screen.findByRole('checkbox', { name: 'HaloPSA' }));
    expect(sourcesMock).toHaveBeenCalledWith(['petra']);
  });
});

describe('sorting and hiding', () => {
  const mapped = (name: string, vendor: string, tenantName: string, hidden = false) =>
    client({ vendor_client_name: name, vendor, id: `${vendor}-${name}`, child_tenant_id: `t-${tenantName}`, child_tenant_name: tenantName, child_tenant_hidden: hidden });

  it('sorts by name ignoring case, so the same customer from two tools sits side by side', () => {
    const sorted = sortClients([mapped('birch law', 'petra', 'Birch'), mapped('Acme', 'petra', 'A'), mapped('ACME', 'huntress', 'A'), mapped('Zed', 'halopsa', 'Z')], 'name');
    expect(sorted.map((c) => `${c.vendor_client_name}/${c.vendor}`)).toEqual(['ACME/huntress', 'Acme/petra', 'birch law/petra', 'Zed/halopsa']);
  });

  it('can sort by tool or by the tenant it is mapped to, and does not change the input', () => {
    const input = [mapped('B', 'petra', 'Z'), mapped('A', 'huntress', 'Y')];
    expect(sortClients(input, 'tool').map((c) => c.vendor)).toEqual(['huntress', 'petra']);
    expect(sortClients(input, 'tenant').map((c) => c.child_tenant_name)).toEqual(['Y', 'Z']);
    expect(input[0].vendor_client_name).toBe('B');
  });

  it('moves clients mapped to a hidden tenant out of Mapped', () => {
    const g = groupClients([mapped('Hal Test', 'huntress', 'Hal Test', true), mapped('Acme', 'petra', 'Acme')]);
    expect(g.mapped.map((c) => c.vendor_client_name)).toEqual(['Acme']);
    expect(g.hidden.map((c) => c.vendor_client_name)).toEqual(['Hal Test']);
  });

  it('Hide hides the mapped tenant, and a hidden one only appears under "Show hidden"', async () => {
    clientsMock.mockResolvedValue({ clients: [mapped('Hal Test', 'huntress', 'Hal Test'), mapped('Gone', 'petra', 'Gone', true)], unmapped: 0, sync_vendors: [] });
    const user = userEvent.setup();
    render(<ClientMapping tenants={tenants} onChanged={() => {}} />);
    await screen.findByText('Hal Test');
    expect(screen.queryByText('Gone')).toBeNull();
    await user.click(screen.getByRole('button', { name: 'Hide' }));
    expect(hiddenMock).toHaveBeenCalledWith('t-Hal Test', true);
    await user.click(screen.getByLabelText(/Show hidden/));
    expect(await screen.findByText('Gone')).toBeInTheDocument();
    await user.click(screen.getByRole('button', { name: 'Show' }));
    expect(hiddenMock).toHaveBeenCalledWith('t-Gone', false);
  });
});

describe('possible duplicates', () => {
  it('lists tenants with near-identical names and which tool clients feed each', async () => {
    clientsMock.mockResolvedValue({
      clients: [client({ vendor_client_name: 'Acme' })],
      unmapped: 1,
      sync_vendors: [],
      duplicates: [{ tenants: [{ tenant_id: 'a', name: 'Acme Dental', mapped_from: ['petra: Acme Dental'] }, { tenant_id: 'b', name: 'Acme Dental LLC', mapped_from: [] }] }],
    });
    render(<ClientMapping tenants={tenants} onChanged={() => {}} />);
    const panel = await screen.findByRole('region', { name: 'Possible duplicates' });
    expect(panel).toHaveTextContent('Acme Dental');
    expect(panel).toHaveTextContent('Acme Dental LLC');
    expect(panel).toHaveTextContent('petra: Acme Dental');
    expect(panel).toHaveTextContent('nothing mapped to it');
  });

  it('shows no panel when nothing looks duplicated', async () => {
    clientsMock.mockResolvedValue({ clients: [client({ vendor_client_name: 'Acme' })], unmapped: 1, sync_vendors: [], duplicates: [] });
    render(<ClientMapping tenants={tenants} onChanged={() => {}} />);
    await screen.findByText('Acme');
    expect(screen.queryByRole('region', { name: 'Possible duplicates' })).toBeNull();
  });
});

describe('one tool at a time', () => {
  const rows = [
    client({ vendor_client_name: 'Acme', vendor: 'petra' }),
    client({ vendor_client_name: 'Cedar Farms', vendor: 'huntress' }),
    client({ vendor_client_name: 'Acme Dental', vendor: 'huntress', child_tenant_id: 't1', child_tenant_name: 'Acme Dental' }),
    client({ vendor_client_name: 'Skip', vendor: 'huntress', ignored: true }),
  ];

  it('counts each tool\'s clients and the ones still unmapped (ignored ones are not "unmapped")', () => {
    expect(toolTabs(rows)).toEqual([
      { vendor: 'huntress', total: 3, unmapped: 1 },
      { vendor: 'petra', total: 1, unmapped: 1 },
    ]);
  });

  it('filters by tool and by name text', () => {
    expect(filterClients(rows, 'huntress', '').map((c) => c.vendor_client_name)).toEqual(['Cedar Farms', 'Acme Dental', 'Skip']);
    expect(filterClients(rows, null, ' acme ').map((c) => c.vendor_client_name)).toEqual(['Acme', 'Acme Dental']);
    expect(filterClients(rows, 'petra', 'cedar')).toEqual([]);
  });

  it('a tool tab shows only that tool\'s clients, and All tools shows everything again', async () => {
    clientsMock.mockResolvedValue({ clients: rows, unmapped: 2, sync_vendors: [] });
    const user = userEvent.setup();
    render(<ClientMapping tenants={tenants} onChanged={() => {}} />);
    await screen.findAllByText('Cedar Farms');
    await user.click(screen.getByRole('tab', { name: /Petra/ }));
    expect(screen.queryAllByText('Cedar Farms')).toHaveLength(0);
    expect(screen.getAllByText('Acme').length).toBeGreaterThan(0);
    await user.click(screen.getByRole('tab', { name: /All tools/ }));
    expect(screen.getAllByText('Cedar Farms').length).toBeGreaterThan(0);
  });

  it('searching narrows the list', async () => {
    clientsMock.mockResolvedValue({ clients: rows, unmapped: 2, sync_vendors: [] });
    const user = userEvent.setup();
    render(<ClientMapping tenants={tenants} onChanged={() => {}} />);
    await screen.findAllByText('Cedar Farms');
    await user.type(screen.getByLabelText('Search'), 'cedar');
    expect(screen.getAllByText('Cedar Farms').length).toBeGreaterThan(0);
    expect(screen.queryAllByText('Acme')).toHaveLength(0);
  });
});

describe('start over', () => {
  const open = async () => {
    clientsMock.mockResolvedValue({ clients: [client({ vendor_client_name: 'Acme' })], unmapped: 1, sync_vendors: [] });
    const user = userEvent.setup();
    render(<ClientMapping tenants={tenants} onChanged={() => {}} />);
    await screen.findAllByText('Acme');
    await user.click(screen.getByRole('button', { name: 'Remove all client tenants' }));
    return user;
  };

  it('shows an in-page confirmation (no browser prompt, which Electron does not support) and removes only after REMOVE is typed', async () => {
    const prompt = vi.spyOn(window, 'prompt');
    const user = await open();
    const go = screen.getByRole('button', { name: 'Remove everything' });
    expect(go).toBeDisabled();
    await user.type(screen.getByLabelText('Type REMOVE to confirm'), 'remove it');
    expect(go).toBeDisabled();
    await user.clear(screen.getByLabelText('Type REMOVE to confirm'));
    await user.type(screen.getByLabelText('Type REMOVE to confirm'), 'REMOVE');
    await user.click(go);
    await screen.findByRole('button', { name: 'Remove everything' }).catch(() => null);
    expect(sourcesMock).toHaveBeenCalledWith([]);
    expect(removeMock.mock.calls.map((c) => c[0])).toEqual(['t-Acme Dental', 't-Birch Law']);
    expect(prompt).not.toHaveBeenCalled();
    prompt.mockRestore();
  });

  it('Cancel closes the confirmation and removes nothing', async () => {
    const user = await open();
    await user.click(screen.getByRole('button', { name: 'Cancel' }));
    expect(screen.queryByRole('alertdialog')).toBeNull();
    expect(removeMock).not.toHaveBeenCalled();
    expect(sourcesMock).not.toHaveBeenCalled();
  });
});

describe('keptSummary', () => {
  it('is empty when nothing was kept, and names the first few with the reason otherwise', () => {
    expect(keptSummary([])).toBe('');
    const k = (n: string) => ({ name: n, reason: 'it has audit records' });
    expect(keptSummary([k('A')])).toBe('; kept 1: A (it has audit records)');
    expect(keptSummary([k('A'), k('B'), k('C'), k('D'), k('E')])).toBe('; kept 5: A (it has audit records), B (it has audit records), C (it has audit records), and 2 more');
  });
});

describe('removeClients', () => {
  const list = [{ tenant_id: 'a', name: 'A' }, { tenant_id: 'b', name: 'B' }, { tenant_id: 'c', name: 'C' }];

  it('removes one at a time, reports progress, and carries on when one is kept or fails', async () => {
    const calls: string[] = [];
    const progress: number[] = [];
    const out = await removeClients(
      list,
      async (id) => {
        calls.push(id);
        if (id === 'b') return { removed: false, name: 'B', reason: 'it has audit records' };
        if (id === 'c') throw new Error('API 500');
        return { removed: true, name: 'A', reason: null };
      },
      (done) => progress.push(done),
    );
    expect(calls).toEqual(['a', 'b', 'c']);
    expect(progress).toEqual([1, 2, 3]);
    expect(out).toEqual({ removed: 1, kept: [{ name: 'B', reason: 'it has audit records' }, { name: 'C', reason: 'API 500' }] });
  });
});
