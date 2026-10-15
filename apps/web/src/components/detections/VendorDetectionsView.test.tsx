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
