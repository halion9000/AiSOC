import { beforeEach, describe, expect, it, vi } from 'vitest';
import { render, screen, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import type { ManagedTenantRow, MsspOverview } from '@/lib/api';

const overviewMock = vi.fn();
const tenantsMock = vi.fn();
vi.mock('@/lib/api', () => ({ msspApi: { overview: () => overviewMock(), tenants: () => tenantsMock() } }));
vi.mock('react-hot-toast', () => ({ default: { success: vi.fn(), error: vi.fn() } }));

import MSSPDashboardView, { figure, matchesFilter, tenantsToCsv } from './MSSPDashboardView';

// The page used to render six invented tenants ("Acme Financial", "GlobalRetail Corp", ...) with invented alert counts, ARR and analyst
// allocation to every workspace, and an "Export Report" button that only showed a toast. These tests pin that it shows real data or an honest
// empty state, never a made-up number, and that Export really exports.
const INVENTED = ['Acme Financial', 'GlobalRetail Corp', 'MedSecure Health', 'NovaTech Industries', 'Pinnacle Energy', 'Stratos Logistics'];

const none: MsspOverview = {
  total_tenants: 0, tenants_reporting: 0, total_open_alerts: null, total_critical_alerts: null, total_open_cases: null, avg_health_score: null, avg_mttr_minutes: null, sla_breach_count: null,
};

function row(over: Partial<ManagedTenantRow> & { name: string }): ManagedTenantRow {
  return {
    tenant_id: `id-${over.name}`, has_metrics: false, snapshot_at: null, health_score: null, open_alerts: null, critical_alerts: null, open_cases: null, mttr_minutes: null, sla_breaches: null, connector_count: null, ...over,
  };
}

const reporting = row({ name: 'Reporting Co', has_metrics: true, snapshot_at: '2026-10-07T12:00:00Z', open_alerts: 12, critical_alerts: 2, open_cases: 4, mttr_minutes: 30, sla_breaches: 1, connector_count: 3, health_score: 80 });
const quiet = row({ name: 'Quiet Co' });
const healthy = row({ name: 'Healthy Co', has_metrics: true, snapshot_at: '2026-10-07T12:00:00Z', open_alerts: 0, critical_alerts: 0, open_cases: 0, mttr_minutes: 10, sla_breaches: 0, connector_count: 1, health_score: 99 });

beforeEach(() => {
  overviewMock.mockReset();
  tenantsMock.mockReset();
});

describe('a workspace with no child tenants (the reported case)', () => {
  it('shows an honest empty state, none of the invented tenants, and no made-up figures', async () => {
    overviewMock.mockResolvedValue(none);
    tenantsMock.mockResolvedValue([]);
    const { container } = render(<MSSPDashboardView />);

    expect(await screen.findByText('No managed tenants yet')).toBeInTheDocument();
    for (const name of INVENTED) expect(container.textContent).not.toContain(name);
    expect(screen.getByText('0 reporting metrics')).toBeInTheDocument();
    // the totals nobody has reported are dashes, not zeros
    expect(screen.getAllByText('—').length).toBe(5);
    expect(container.textContent).not.toMatch(/ARR|\$\d/);
  });
});

describe('real tenants', () => {
  it('lists each tenant, with dashes and "No data yet" where nothing has been reported', async () => {
    overviewMock.mockResolvedValue({ ...none, total_tenants: 2, tenants_reporting: 1, total_open_alerts: 12, total_critical_alerts: 2, total_open_cases: 4, sla_breach_count: 1, avg_mttr_minutes: 30 });
    tenantsMock.mockResolvedValue([reporting, quiet]);
    render(<MSSPDashboardView />);

    const table = await screen.findByRole('table');
    const reportingRow = within(table).getByText('Reporting Co').closest('tr') as HTMLElement;
    expect(within(reportingRow).getAllByRole('cell').map((c) => c.textContent).slice(1, 8)).toEqual(['12', '2', '4', '30', '1', '3', '80']);
    const quietRow = within(table).getByText('Quiet Co').closest('tr') as HTMLElement;
    expect(within(quietRow).getAllByRole('cell').map((c) => c.textContent).slice(1)).toEqual(['—', '—', '—', '—', '—', '—', '—', 'No data yet']);
  });

  it('shows a real zero as 0 and an unreported figure as a dash: they are not the same thing', async () => {
    overviewMock.mockResolvedValue({ ...none, total_tenants: 2, tenants_reporting: 1, total_open_alerts: 0, total_critical_alerts: 0, total_open_cases: 0, sla_breach_count: 0, avg_mttr_minutes: 10 });
    tenantsMock.mockResolvedValue([healthy, quiet]);
    render(<MSSPDashboardView />);
    const table = await screen.findByRole('table');
    expect(within(within(table).getByText('Healthy Co').closest('tr') as HTMLElement).getAllByRole('cell')[1].textContent).toBe('0');
    expect(within(within(table).getByText('Quiet Co').closest('tr') as HTMLElement).getAllByRole('cell')[1].textContent).toBe('—');
  });

  it('has no ARR or analyst-allocation columns (there is no source for either)', async () => {
    overviewMock.mockResolvedValue({ ...none, total_tenants: 1 });
    tenantsMock.mockResolvedValue([quiet]);
    render(<MSSPDashboardView />);
    const headers = (await within(await screen.findByRole('table')).findAllByRole('columnheader')).map((h) => h.textContent);
    expect(headers).not.toContain('ARR');
    expect(headers).not.toContain('Analysts');
    expect(headers).not.toContain('MTTD (min)');
  });
});

describe('filters', () => {
  it('shows only tenants breaching their SLA, or only those with no data yet', async () => {
    overviewMock.mockResolvedValue({ ...none, total_tenants: 3 });
    tenantsMock.mockResolvedValue([reporting, quiet, healthy]);
    render(<MSSPDashboardView />);
    const user = userEvent.setup();
    await screen.findByRole('table');

    await user.click(screen.getByRole('button', { name: 'Breaching SLA' }));
    expect(screen.getByText('Reporting Co')).toBeInTheDocument();
    expect(screen.queryByText('Healthy Co')).not.toBeInTheDocument();
    expect(screen.queryByText('Quiet Co')).not.toBeInTheDocument();

    await user.click(screen.getByRole('button', { name: 'No data yet' }));
    expect(screen.getByText('Quiet Co')).toBeInTheDocument();
    expect(screen.queryByText('Reporting Co')).not.toBeInTheDocument();
  });

  it('offers a way back when a filter matches nothing', async () => {
    overviewMock.mockResolvedValue({ ...none, total_tenants: 1 });
    tenantsMock.mockResolvedValue([healthy]);
    render(<MSSPDashboardView />);
    const user = userEvent.setup();
    await screen.findByRole('table');
    await user.click(screen.getByRole('button', { name: 'Breaching SLA' }));
    expect(screen.getByText('No tenants match this filter')).toBeInTheDocument();
    await user.click(screen.getByRole('button', { name: 'Show all tenants' }));
    expect(screen.getByText('Healthy Co')).toBeInTheDocument();
  });

  it('matchesFilter treats a tenant with no metrics as not breaching', () => {
    expect(matchesFilter(quiet, 'breaching')).toBe(false);
    expect(matchesFilter(quiet, 'no-data')).toBe(true);
    expect(matchesFilter(reporting, 'breaching')).toBe(true);
    expect(matchesFilter(healthy, 'breaching')).toBe(false);
  });
});

describe('loading and errors', () => {
  it('says it is loading, then shows the data', async () => {
    let finish: (rows: ManagedTenantRow[]) => void = () => undefined;
    overviewMock.mockResolvedValue({ ...none, total_tenants: 1 });
    tenantsMock.mockReturnValue(new Promise<ManagedTenantRow[]>((resolve) => (finish = resolve)));
    render(<MSSPDashboardView />);
    expect(screen.getByRole('status')).toHaveTextContent('Loading managed tenants');
    finish([quiet]);
    expect(await screen.findByText('Quiet Co')).toBeInTheDocument();
  });

  it('shows the failure instead of falling back to sample data, and retries', async () => {
    overviewMock.mockRejectedValueOnce(new Error('403 forbidden: missing mssp:read')).mockResolvedValue({ ...none, total_tenants: 1 });
    tenantsMock.mockResolvedValue([quiet]);
    const { container } = render(<MSSPDashboardView />);
    expect(await screen.findByText('Could not load managed tenants')).toBeInTheDocument();
    expect(screen.getByText('403 forbidden: missing mssp:read')).toBeInTheDocument();
    for (const name of INVENTED) expect(container.textContent).not.toContain(name);
    await userEvent.setup().click(screen.getByRole('button', { name: 'Try again' }));
    expect(await screen.findByText('Quiet Co')).toBeInTheDocument();
  });
});

describe('Export CSV really exports', () => {
  it('builds a CSV with a header, blank cells for unreported figures, and safe quoting', () => {
    const csv = tenantsToCsv([reporting, quiet, row({ name: 'Smith, "Jones" & Co' })]);
    const lines = csv.trimEnd().split('\n');
    expect(lines[0]).toBe('tenant,tenant_id,has_metrics,snapshot_at,open_alerts,critical_alerts,open_cases,mttr_minutes,sla_breaches,connector_count,health_score');
    expect(lines[1]).toBe('Reporting Co,id-Reporting Co,yes,2026-10-07T12:00:00Z,12,2,4,30,1,3,80');
    expect(lines[2]).toBe('Quiet Co,id-Quiet Co,no,,,,,,,,');
    // a comma or a double quote forces quoting, and a quote inside a quoted cell is doubled
    expect(lines[3]).toBe('"Smith, ""Jones"" & Co","id-Smith, ""Jones"" & Co",no,,,,,,,,');
  });

  it('downloads the rows on screen when clicked, and is disabled when there are none', async () => {
    const created: Blob[] = [];
    const createObjectURL = vi.fn((blob: Blob) => (created.push(blob), 'blob:test'));
    Object.assign(URL, { createObjectURL, revokeObjectURL: vi.fn() });
    const click = vi.spyOn(HTMLAnchorElement.prototype, 'click').mockImplementation(() => undefined);

    overviewMock.mockResolvedValue({ ...none, total_tenants: 2 });
    tenantsMock.mockResolvedValue([reporting, quiet]);
    const view = render(<MSSPDashboardView />);
    const user = userEvent.setup();
    await screen.findByRole('table');
    await user.click(screen.getByRole('button', { name: 'No data yet' }));
    await user.click(screen.getByRole('button', { name: 'Export CSV' }));

    expect(click).toHaveBeenCalledTimes(1);
    const text = await created[0].text();
    expect(text).toContain('Quiet Co');
    expect(text).not.toContain('Reporting Co'); // exports what is filtered on screen
    view.unmount();

    tenantsMock.mockResolvedValue([]);
    overviewMock.mockResolvedValue(none);
    render(<MSSPDashboardView />);
    await screen.findByText('No managed tenants yet');
    expect(screen.getByRole('button', { name: 'Export CSV' })).toBeDisabled();
    click.mockRestore();
  });
});

describe('figure()', () => {
  it('is a dash for anything unreported, and formats real numbers', () => {
    expect(figure(null)).toBe('—');
    expect(figure(undefined)).toBe('—');
    expect(figure(Number.NaN)).toBe('—');
    expect(figure(0)).toBe('0');
    expect(figure(30.4, { decimals: 0, suffix: ' min' })).toBe('30 min');
  });
});
