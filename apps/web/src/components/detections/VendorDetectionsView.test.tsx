import { describe, expect, it, vi, beforeEach } from 'vitest';
import { render, screen, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { SWRConfig } from 'swr';

const api = vi.hoisted(() => ({ vendorDetections: vi.fn() }));
vi.mock('@/lib/api', () => ({ detectionApi: { vendorDetections: api.vendorDetections } }));

import { VendorDetectionsView } from './VendorDetectionsView';

const DATA = {
  window_days: 30,
  detections: [
    { source: 'huntress', name: 'Malicious Process', count: 5, open: 2, severity: 'critical', clients: 3, last_seen: '2026-10-14T10:00:00+00:00' },
    { source: 'petra', name: 'Impossible travel', count: 1, open: 0, severity: 'medium', clients: 1, last_seen: null },
  ],
};

function show() {
  return render(
    <SWRConfig value={{ provider: () => new Map(), dedupingInterval: 0, shouldRetryOnError: false }}>
      <VendorDetectionsView />
    </SWRConfig>,
  );
}

beforeEach(() => {
  api.vendorDetections.mockReset();
});

describe('VendorDetectionsView', () => {
  it('lists what each tool detected and filters by tool', async () => {
    api.vendorDetections.mockResolvedValue(DATA);
    const user = userEvent.setup();
    show();
    const table = await screen.findByRole('table');
    expect(within(table).getByText('Malicious Process')).toBeInTheDocument();
    expect(within(table).getByText('Impossible travel')).toBeInTheDocument();

    await user.click(screen.getByRole('button', { name: /Petra \(1\)/ }));
    expect(within(screen.getByRole('table')).queryByText('Malicious Process')).not.toBeInTheDocument();
    expect(within(screen.getByRole('table')).getByText('Impossible travel')).toBeInTheDocument();
  });

  it('filters by severity and sorts the most serious first', async () => {
    api.vendorDetections.mockResolvedValue({
      window_days: 30,
      detections: [
        { source: 'huntress', name: 'Low one', count: 9, open: 1, severity: 'low', clients: 1, last_seen: '2026-10-14T10:00:00+00:00' },
        { source: 'huntress', name: 'Critical one', count: 2, open: 1, severity: 'critical', clients: 1, last_seen: '2026-10-13T10:00:00+00:00' },
        { source: 'petra', name: 'High one', count: 4, open: 0, severity: 'high', clients: 2, last_seen: null },
      ],
    });
    const user = userEvent.setup();
    show();
    await screen.findByRole('table');
    const names = () => screen.getAllByRole('row').map((r) => r.textContent ?? '').filter((t) => /one/.test(t));
    expect(names().map((t) => t.match(/(Critical|High|Low) one/)?.[0])).toEqual(['Critical one', 'High one', 'Low one']);

    await user.click(screen.getByRole('button', { name: /^high \(1\)/ }));
    expect(screen.getByText('High one')).toBeInTheDocument();
    expect(screen.queryByText('Low one')).not.toBeInTheDocument();
    expect(screen.queryByText('Critical one')).not.toBeInTheDocument();
    await user.click(screen.getByRole('button', { name: /^All$/ }));
    expect(screen.getByText('Low one')).toBeInTheDocument();
  });

  it('sorts a column when its header is clicked and filters by detection text and a minimum', async () => {
    api.vendorDetections.mockResolvedValue({
      window_days: 30,
      detections: [
        { source: 'huntress', name: 'Few', count: 2, open: 0, severity: 'low', clients: 1, last_seen: null },
        { source: 'huntress', name: 'Many', count: 50, open: 0, severity: 'low', clients: 1, last_seen: null },
        { source: 'huntress', name: 'Some', count: 10, open: 0, severity: 'low', clients: 1, last_seen: null },
      ],
    });
    const user = userEvent.setup();
    show();
    await screen.findByRole('table');
    const order = () => screen.getAllByRole('row').map((r) => r.textContent ?? '').filter((t) => /Few|Many|Some/.test(t)).map((t) => t.match(/Few|Many|Some/)?.[0]);
    await user.click(within(screen.getByRole('columnheader', { name: /Alerts/ })).getByRole('button'));
    expect(order()).toEqual(['Few', 'Some', 'Many']);
    await user.click(within(screen.getByRole('columnheader', { name: /Alerts/ })).getByRole('button'));
    expect(order()).toEqual(['Many', 'Some', 'Few']);

    await user.type(screen.getByLabelText('Minimum Alerts'), '10');
    expect(order()).toEqual(['Many', 'Some']);
    await user.type(screen.getByLabelText('Filter Detection'), 'man');
    expect(order()).toEqual(['Many']);
    await user.type(screen.getByLabelText('Minimum Alerts'), '00');
    expect(screen.getByText('Nothing matches these filters.')).toBeInTheDocument();
  });

  it('says plainly when nothing has fired', async () => {
    api.vendorDetections.mockResolvedValue({ window_days: 30, detections: [] });
    show();
    expect(await screen.findByText(/No vendor detections yet/i)).toBeInTheDocument();
    expect(screen.getByRole('link', { name: /Open Connectors/i })).toHaveAttribute('href', '/connectors');
  });

  it('shows an error with a retry instead of an empty table', async () => {
    api.vendorDetections.mockRejectedValueOnce(new Error('boom'));
    show();
    expect(await screen.findByText(/Could not load vendor detections/i)).toBeInTheDocument();
    expect(screen.getByText(/boom/)).toBeInTheDocument();
  });
});
