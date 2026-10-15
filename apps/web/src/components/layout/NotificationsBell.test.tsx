import { beforeEach, describe, expect, it, vi } from 'vitest';
import { render, screen } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { SWRConfig } from 'swr';
import type { Alert } from '@/lib/api';

const listMock = vi.fn();
vi.mock('@/lib/api', () => ({ alertsApi: { list: (...a: unknown[]) => listMock(...a) } }));
vi.mock('next/link', () => ({ default: ({ children, href, onClick }: { children: React.ReactNode; href: string; onClick?: () => void }) => <a href={href} onClick={onClick}>{children}</a> }));

import { NotificationsBell, needsAttention } from './NotificationsBell';

const alert = (id: string, severity: string, createdAt: string, clientName?: string) => ({ id, title: `Alert ${id}`, severity, createdAt, clientName }) as unknown as Alert;
const wrap = () => render(<SWRConfig value={{ provider: () => new Map(), dedupingInterval: 0 }}><NotificationsBell /></SWRConfig>);

beforeEach(() => {
  listMock.mockReset();
});

describe('needsAttention', () => {
  it('merges critical and high newest first and caps the list', () => {
    const out = needsAttention([alert('c1', 'critical', '2026-10-15T01:00:00Z')], [alert('h1', 'high', '2026-10-15T02:00:00Z'), alert('h2', 'high', '2026-10-14T01:00:00Z')], 2);
    expect(out.map((a) => a.id)).toEqual(['h1', 'c1']);
  });
});

describe('the notifications bell', () => {
  it('opens a panel with the newest critical/high alerts, each a link, and closes again', async () => {
    listMock.mockImplementation(async (f: { severity: string }) =>
      f.severity === 'critical'
        ? { alerts: [alert('c1', 'critical', '2026-10-15T01:00:00Z', 'Acme')], total: 3 }
        : { alerts: [alert('h1', 'high', '2026-10-15T02:00:00Z')], total: 5 },
    );
    const user = userEvent.setup();
    wrap();
    await user.click(screen.getByRole('button', { name: 'Open notifications' }));
    expect(await screen.findByText('Alert c1')).toBeTruthy();
    expect(screen.getByText('3 critical, 5 high, not yet picked up')).toBeTruthy();
    expect(screen.getByRole('link', { name: /Alert c1/ }).getAttribute('href')).toBe('/alerts/c1');
    expect(screen.getByRole('link', { name: 'View all alerts' }).getAttribute('href')).toBe('/alerts');
    expect(screen.getByTestId('bell-dot')).toBeTruthy();
    await user.keyboard('{Escape}');
    expect(screen.queryByRole('dialog')).toBeNull();
  });

  it('says so, and shows no red dot, when nothing needs attention', async () => {
    listMock.mockResolvedValue({ alerts: [], total: 0 });
    const user = userEvent.setup();
    wrap();
    await user.click(screen.getByRole('button', { name: 'Open notifications' }));
    expect(await screen.findByText('No new critical or high alerts.')).toBeTruthy();
    expect(screen.queryByTestId('bell-dot')).toBeNull();
  });
});
