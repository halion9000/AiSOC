import { describe, expect, it, vi } from 'vitest';
import { render, screen, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';

import { FimEventsTable } from './FimEventsTable';

const event = (over: Record<string, unknown> = {}) => ({
  id: 'e1',
  event_time: new Date(Date.now() - 5 * 60_000).toISOString(),
  action: 'CREATED',
  target_path: 'C:\\Windows\\System32\\drivers\\etc\\hosts',
  hostname: 'WS-014',
  node_key: 'abcdef1234567890',
  process_name: 'notepad.exe',
  pid: 4242,
  username: 'jsmith',
  sha256: 'a'.repeat(64),
  ...over,
});
const props = (over: Record<string, unknown> = {}) => ({ events: [event()] as never, total: 1, page: 1, pageSize: 50, onPageChange: vi.fn(), ...over });

describe('FimEventsTable', () => {
  it('says so when there are no events', () => {
    render(<FimEventsTable {...props({ events: [], total: 0 })} />);
    expect(screen.getByText('No FIM events found for the selected filters.')).toBeInTheDocument();
    expect(screen.queryByRole('table')).toBeNull();
  });

  it('shows each event with time ago, action, path, host, process with pid, user and a shortened hash', () => {
    render(<FimEventsTable {...props()} />);
    const row = screen.getByText('CREATED').closest('tr') as HTMLElement;
    expect(within(row).getByText(/5 minutes ago/)).toBeInTheDocument();
    expect(within(row).getByText(/hosts$/)).toBeInTheDocument();
    expect(within(row).getByText('WS-014')).toBeInTheDocument();
    expect(within(row).getByText(/notepad\.exe/)).toHaveTextContent('notepad.exe(4242)');
    expect(within(row).getByText('jsmith')).toBeInTheDocument();
    expect(within(row).getByText(`${'a'.repeat(12)}…`)).toHaveAttribute('title', 'a'.repeat(64));
  });

  it('the exact time is available on the time cell', () => {
    const e = event();
    render(<FimEventsTable {...props({ events: [e] })} />);
    expect(screen.getByText(/ago/)).toHaveAttribute('title', e.event_time);
  });

  it('shows a dash for a missing process, user or hash, and the start of the node key when there is no host name', () => {
    render(<FimEventsTable {...props({ events: [event({ hostname: null, process_name: null, username: null, sha256: null })] })} />);
    const row = screen.getByText('CREATED').closest('tr') as HTMLElement;
    expect(within(row).getAllByText('—')).toHaveLength(3);
    expect(within(row).getByText('abcdef12')).toBeInTheDocument();
  });

  it('leaves the pid out when there is none, but keeps pid 0', () => {
    const { unmount } = render(<FimEventsTable {...props({ events: [event({ pid: null })] })} />);
    expect(screen.getByText(/notepad\.exe/)).not.toHaveTextContent('(');
    unmount();
    render(<FimEventsTable {...props({ events: [event({ pid: 0 })] })} />);
    expect(screen.getByText(/notepad\.exe/)).toHaveTextContent('(0)');
  });

  it('colours the known actions and shows an unknown one in grey rather than hiding it', () => {
    render(<FimEventsTable {...props({ events: [event({ id: '1', action: 'DELETED' }), event({ id: '2', action: 'MOVED' })], total: 2 })} />);
    expect(screen.getByText('DELETED').className).toContain('bg-red-500/20');
    expect(screen.getByText('MOVED').className).toContain('bg-gray-800');
  });

  it('says which events are shown out of how many, and which page of how many', () => {
    render(<FimEventsTable {...props({ total: 1234, page: 3, pageSize: 50 })} />);
    expect(screen.getByText(/Showing 101–150 of 1,234 events/)).toBeInTheDocument();
    expect(screen.getByText('Page 3 / 25')).toBeInTheDocument();
  });

  it('the last page ends at the total, not past it', () => {
    render(<FimEventsTable {...props({ total: 120, page: 3, pageSize: 50 })} />);
    expect(screen.getByText(/Showing 101–120 of 120/)).toBeInTheDocument();
  });

  it('Prev and Next ask for the neighbouring page, and are off at the ends', async () => {
    const onPageChange = vi.fn();
    const { unmount } = render(<FimEventsTable {...props({ total: 150, page: 1, onPageChange })} />);
    expect(screen.getByRole('button', { name: '← Prev' })).toBeDisabled();
    await userEvent.click(screen.getByRole('button', { name: 'Next →' }));
    expect(onPageChange).toHaveBeenCalledWith(2);
    unmount();
    render(<FimEventsTable {...props({ total: 150, page: 3, onPageChange })} />);
    expect(screen.getByRole('button', { name: 'Next →' })).toBeDisabled();
    await userEvent.click(screen.getByRole('button', { name: '← Prev' }));
    expect(onPageChange).toHaveBeenLastCalledWith(2);
  });
});
