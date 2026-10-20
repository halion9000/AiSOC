import { beforeEach, describe, expect, it, vi } from 'vitest';
import { render, screen } from '@testing-library/react';
import { SWRConfig } from 'swr';

const devices = vi.hoisted(() => vi.fn());
vi.mock('@/lib/api', () => ({ casesApi: { devices } }));
vi.mock('next/link', () => ({ default: ({ children, href }: { children: React.ReactNode; href: string }) => <a href={href}>{children}</a> }));

import { CaseDevices } from './CaseDevices';

const show = () =>
  render(
    <SWRConfig value={{ provider: () => new Map(), dedupingInterval: 0 }}>
      <CaseDevices caseId="c1" />
    </SWRConfig>,
  );

beforeEach(() => devices.mockReset());

describe('CaseDevices', () => {
  it('lists each machine with an Open in <tool> link for every tool that has one', async () => {
    devices.mockResolvedValue([
      { hostname: 'PC-01', device_id: 'd1', os: 'Windows 11', alerts: 1, links: [{ vendor: 'ninjaone', label: 'NinjaOne', url: 'https://app.ninjarmm.com/#/deviceDashboard/18/overview' }, { vendor: 'huntress', label: 'Huntress', url: 'https://x.huntress.io/org/1/agents/9' }] },
    ]);
    show();
    const ninja = await screen.findByRole('link', { name: /Open in NinjaOne/ });
    expect(ninja).toHaveAttribute('href', 'https://app.ninjarmm.com/#/deviceDashboard/18/overview');
    expect(screen.getByRole('link', { name: /Open in Huntress/ })).toHaveAttribute('href', 'https://x.huntress.io/org/1/agents/9');
    expect(screen.getByRole('link', { name: 'In Devices' })).toHaveAttribute('href', '/devices?search=PC-01');
  });

  it('says when no tool has a link, and shows nothing for a case that names no machine', async () => {
    devices.mockResolvedValue([{ hostname: 'PC-02', device_id: null, os: null, alerts: 1, links: [] }]);
    const first = show();
    expect(await screen.findByText(/No tool has given a link/)).toBeInTheDocument();
    first.unmount();
    devices.mockResolvedValue([]);
    show();
    await Promise.resolve();
    expect(screen.queryByTestId('case-devices')).not.toBeInTheDocument();
  });
});
